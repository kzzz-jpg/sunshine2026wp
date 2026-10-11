# 待修清單（轉交 `wp/00_基礎知識_從零開始.md` 的負責 agent）

來源：review round 2（`wp/review_round2_fmtstr.md`）的 **[W1]** 與 §3 術語一致性段落。
說明：這些修正**必須改 `wp/00_基礎知識_從零開始.md`**，而該檔不在「fmtstr 修正」任務的可動檔案清單內
（本任務只能改 `pwn2/notes.md`、`pwn2/exploit.py`、`pwn3/notes.md`、`pwn3/exploit.py`
＋新增 `wp/fixes_round2_fmtstr.md`、本檔）。
**請由 `wp/00` 的負責 agent 套用；以下每一條都已附上可直接替換的原文/新文字與驗證方式。**

---

## P1〔高〕`wp/00_基礎知識_從零開始.md:883` 對 pwn3 的描述與 `pwn3/notes.md` §11-7 直接矛盾

### 現況（原文，第 883 行）

```
| revolution | `pwn3/revolution` | 26002 | 自製 printf 的長度整數問題 → `.bss` 溢寫 | `../pwn3/notes.md` |
```

### 為什麼是錯的（已驗證）

* `pwn3/notes.md` §11-7（「常見坑」第 7 條）**花了一整段在駁斥**這個說法：
  > 7. **不要相信題目提示裡的「`.bss 0x4060` 的 16-bit 長度整數溢位 + `memcpy`」說法。**
  >    * `0x4060` 根本不在 `.bss`（`.bss` 是 `0x404040`–`0x404070`），`0x404060` 是 **stderr 的 COPY relocation 欄位**。
  >    * 這支程式**沒有匯入 `memcpy`**（`readelf -s` 只有 write/strlen/strcspn/read/setvbuf）。
  >    * `0x401540` 的 16 進位轉換只是把 18 bytes 寫進 printf 自己堆疊框的暫存區，安全。
  >    真正的原因在 §4.1 / §6：`overflow_arg_area` 初始化成 `buf`。
* 我的獨立複驗（本輪）：
  ```bash
  $ readelf -sW pwn3/revolution | grep -E "memcpy|write|strlen|strcspn|read|setvbuf"
  # → 只有 write / strlen / strcspn / read / setvbuf，沒有 memcpy ✅
  $ objdump -d -M intel --start-address=0x401190 --stop-address=0x4011c6 pwn3/revolution
  # → 0x401190 是 .init_array[1]：對 stdout/stderr 呼叫 setvbuf(...,2,0)（不是什麼長度整數）
  $ printf '%6$p\n' > /tmp/rev_in
  $ gdb -q -batch -ex 'file pwn3/revolution' -ex 'break *0x4013d9' -ex 'run < /tmp/rev_in' \
        -ex 'p/x $rsp+0x120' -ex 'info registers rdi'
  # → rsp+0x120 == rdi == buf ⇒ overflow_arg_area 就是使用者的輸入緩衝區 ✅
  ```
* 新手照閱讀順序（先 `wp/00`、再 `pwn3`）會被直接誤導，而且是**兩份文件互相打架**。

### 建議替換文字（整行換掉）

```
| revolution | `pwn3/revolution` | 26002 | 自製 printf 的 `va_list.overflow_arg_area` 指向輸入緩衝區 → `%N$s` / `%N$w` 任意讀寫 → `strcspn@got` 覆寫成 `system` | `../pwn3/notes.md` |
```

---

## P2〔高〕`wp/00_基礎知識_從零開始.md:440`：把 pwn3 從「Missing bounds check」那一列拿掉

### 現況（原文，第 440 行）

```
| **Missing bounds check** | 長度沒檢查就 `memcpy(dst, src, len)` | pwn3、pwn6 |
```

### 為什麼是錯的

pwn3 **不是**「長度沒檢查的 `memcpy`」：它沒有匯入 `memcpy`，`read(0, buf, 0x1ff)` 讀 511 bytes
進 512 bytes 的緩衝區（沒有溢位，見 `pwn3/notes.md` §3、§6「為什麼不是堆疊溢位？」）。
把 pwn3 放在這一列等於重複 P1 的錯誤。

### 建議替換文字（整行換掉）

```
| **Missing bounds check** | 長度沒檢查就 `memcpy(dst, src, len)` | pwn6 |
```

> （若 `pwn6` 也是別的原因，請以 `pwn6/notes.md` 為準；本條只負責把 **pwn3** 從這列移除。）

---

## P3〔低〕`wp/00:733-736`：`cd` 進題目目錄的警告對 pwn2/pwn3 不成立

### 現況（原文，第 733-736 行）

```
> ⚠️ 一定要 `cd` 進**題目自己的目錄**再跑（例如 `cd pwn1/`），
> 因為 exploit 用的是相對路徑 `./challenge` / `./service`。
> 在 repo 根目錄執行會看到 `[ERROR] './challenge' does not exist`。
> 或直接用 `wp/run_all.sh`（它會自動 cd 進各題目目錄）。
```

### 為什麼要補

`pwn2/exploit.py` 與 `pwn3/exploit.py` 已經改用**絕對路徑**：

```python
# pwn2/exploit.py
HERE = os.path.dirname(os.path.abspath(__file__))
process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./mad_libs"], cwd=HERE)
# pwn3/exploit.py
BASEDIR = os.path.dirname(os.path.abspath(__file__))
BINARY  = os.path.join(BASEDIR, 'revolution')
```

所以從任何 cwd 執行都會成功（本輪複驗，`cd /` 之後直接跑，兩題都 PASS）：

```console
$ cd / && python3 /home/kzzz/Documents/code/ctf/sunshine/pwn2/exploit.py < /dev/null | tail -3
DONE

FLAG: sun{LOCAL_DUMMY_FLAG}
$ cd / && python3 /home/kzzz/Documents/code/ctf/sunshine/pwn3/exploit.py < /dev/null | tail -3
score>
FLAG: sun{LOCAL_TEST_FLAG}
```

新手如果只讀 `wp/00` 會以為一定要 `cd`，反而多做一步。

### 建議追加一行（接在上面那條 ⚠️ 之後）

```
> 💡 例外：本系列 **pwn2 / pwn3** 的 exploit 已改用 `os.path.dirname(os.path.abspath(__file__))`
> 組出題目路徑（並用 `cwd=` 指定工作目錄），所以**不受 cwd 影響**，從 repo 根目錄直接跑也可以。
> 其他題目請仍以各題 `notes.md` 的說明為準。
```

---

## P4〔低〕`wp/00` 名詞表／§12 pwntools API 清單缺少 pwn2/pwn3 的核心術語

`wp/00` 目前完全沒有出現 `fmtstr_payload` / `FmtStr` / `va_list` / `IFUNC` / `setvbuf` / `_IONBF`
（已用 grep 確認：`grep -n "fmtstr_payload\|FmtStr\|va_list\|IFUNC\|setvbuf\|_IONBF" wp/00_基礎知識_從零開始.md` → 0 筆），
但 pwn2 整題的核心就是 `fmtstr_payload`，pwn3 整題的核心就是 `va_list` / `IFUNC`。

> 註：`pwn3/notes.md` 本輪已經自己補上 **IFUNC**（§2.5）與 **`_IONBF`**（§1.2）的定義，
> `pwn2/notes.md` 也補了 `fmtstr_payload` 的 `write_size_max` 行為，所以兩題已能自足；
> 這裡只是建議讓 `wp/00` 的名詞表不缺口，方便跨題引用。

### 建議（名詞表）追加兩條

```
| **va_list** | 可變參數清單。SysV AMD64 的 `va_list` 是 24 bytes：`gp_offset`(+0x18)、`fp_offset`(+0x1c)、`overflow_arg_area`(+0x20)、`reg_save_area`(+0x28)。暫存器用完（`gp_offset > 0x2f`）之後，參數就從 `overflow_arg_area` 往高位址拿 → **如果它被初始化成使用者的緩衝區，就等於「使用者控制了參數」。** |
| **IFUNC（indirect function）** | 載入時執行一小段「選擇器」挑出 CPU 最適合的實作（例如 `__strcspn_avx2`）。所以 GOT 裡放的是**被挑中的實作**的位址，**不等於** `readelf -s` 看到的符號值 → 拿這種符號當 libc 指紋會誤判。 |
```

### 建議（§12 pwntools API 清單）追加最小範例

```python
# 格式化字串漏洞（pwn2）：自動產生 %n 家族 payload
from pwn import *
context.arch = 'amd64'                       # ★ 一定要先設，否則 p64() 會用 32-bit
payload = fmtstr_payload(
    8,                                       # 我們控制的第一個參數編號（要先自己量出來！）
    {0x404010: p64(0x7ffff7c58740)[:6]},      # {目標位址: 要寫的值}
    write_size='byte',                       # 想以 1 byte 為單位寫
    # write_size_max='byte',                 # ★ 想「保證只用 %hhn」才要加這行（預設是 'long'，會自動合併成 %hn/%n）
    numbwritten=0,                           # 在這之前已經印出幾個字元
    badbytes=b'\n',                          # 不能出現在 payload 裡的位元組
)
# 自動找參數編號（原理同 pwn2 §4 技巧 A）：
# autofmt = FmtStr(execute_fmt=lambda p: (io.sendline(p), io.recvline())[1])
# print(autofmt.offset)   # → 8
```

> ⚠️ 提醒下一輪的文件維護者：`fmtstr_payload` 的 `write_size_max` **預設是 `'long'`**，
> 所以 `write_size='byte'` **不保證**輸出 6 個 `%hhn`。這正是 review round 2 的 **[E3]**
> （已修在 `pwn2/notes.md` §3.4 與 `pwn2/exploit.py`），`wp/00` 若引用請照這個事實寫。

---

## P5〔可選〕一致性：`wp/00` 的其他小項（本輪**沒有**發現需要改的地方）

以下是 review round 2 §3 檢查過、**結論是 OK** 的項目，列出來避免重複勞動：

| 檢查項 | 結果 |
|---|---|
| PIE / Partial RELRO / GOT 可寫 / 小端 / canary / NX 的說法 | ✅ 三份文件一致 |
| `process(['./ld-linux-x86-64.so.2','--library-path','.','./chal'])` | ✅ `wp/00` §12 與 `pwn2` §0/§7 一致 |
| `FLAG.txt`（真 flag）/ `flag.txt`（假 flag）命名 | ✅ 與 pwn2／pwn3 實測一致 |
| Format String 的辨識與指向 `../pwn2/notes.md` | ✅ 正確 |
| `jg` vs `ja`（有號/無號） | ✅ `wp/00` §5.2 有 🔴 提醒；`pwn2/notes.md` 本輪已補上「（有號）/（無號）」措辭 |
| COPY relocation | ✅ `pwn3` §7.1 自己解釋得很清楚，`wp/00` 不補也可接受 |

---

## 套用後建議的驗證

```bash
cd /home/kzzz/Documents/code/ctf/sunshine
# 1) pwn3 不是 .bss 溢寫、也不是 memcpy 長度問題
readelf -sW pwn3/revolution | grep -c memcpy          # 期望 0
readelf -SW pwn3/revolution | grep -E "\.bss"          # .bss = 0x404040, size 0x30 → 0x4060 不在裡面
printf '%6$p\n' > /tmp/rev_in
gdb -q -batch -ex 'file pwn3/revolution' -ex 'break *0x4013d9' -ex 'run < /tmp/rev_in' \
    -ex 'p/x $rsp+0x120' -ex 'info registers rdi'      # 兩者相等 ⇒ overflow_arg_area == buf
# 2) 改完 wp/00 之後確認沒有殘留矛盾字串（注意：用單引號，避免反引號被 shell 當成命令替換）
grep -n 'bss 溢寫' wp/00_基礎知識_從零開始.md
grep -n 'memcpy(dst, src, len)' wp/00_基礎知識_從零開始.md
# 期望：第一條 0 筆；第二條只剩 pwn6（沒有 pwn3）
# 3) pwn2/pwn3 exploit 不受 cwd 影響（P3）
cd / && python3 /home/kzzz/Documents/code/ctf/sunshine/pwn3/exploit.py < /dev/null | tail -3   # 應印出 FLAG
```
