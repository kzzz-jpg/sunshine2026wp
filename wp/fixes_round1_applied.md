# Review Round 1 — 修正套用紀錄

> 對象：`review_round1.md`（Round 1 審查）中所有 E / B / T / S 項目。
> 原則：**動手改之前先用 `objdump` / `readelf` / `gdb` / `python3` 重跑一次審查者的驗證指令**，
> 只有自己驗證成立才套用；審查者說法有誤的地方不套用，記在最後一節。
>
> 修改的檔案（僅這些）：
> `pwn1/notes.md`、`pwn1/exploit.py`、`pwn7/notes.md`、`pwn7/exploit.py`、
> `wp/00_基礎知識_從零開始.md`、`wp/99_速查表.md`
> （未動 `review_round1.md`，未動 `pwn2`~`pwn6`）

---

## 1. 嚴重錯誤 E1 ~ E16

| # | 狀態 | 檔案 | 改了什麼（一行說明） |
|---|---|---|---|
| E1 | **已修** | `pwn7/notes.md` | §10 一頁速查的 `write(1, 0x405060, 0xff)` 改成「鏈一開始 `rax = 3`（被 SUBMIT 的 `write(1,"OK\n",3)` 蓋掉），兩次 `write(...,3)` 只洩漏 6 bytes」；§7 內文與 exploit 註解在 00:34 已正確，不動 |
| E2 | **已修** | `pwn7/notes.md` | §7 階段 4：`rsp = A3+0x58` → **`rsp = A3+0x50`**，並改用 `rsp+0x10`（`0x40200a` / `0x402032` 的標頭解析基準）推導 `RESP = A3+0x60`；補上「`0x401fda` 的 `mov rsi,rbx` 用的是 `rbx`，所以 `d3[0x40:0x48]` 必須設成 `RESP`」 |
| E3 | **已修** | `pwn7/notes.md`（§6、§9 #5）、`pwn7/exploit.py`（漏洞 2 註解） | 刪掉「glibc `read`/`write` wrapper 會把 `rdx` 弄髒」這個錯說法，改成「這支 binary 沒有 `pop rdx` gadget → 設不了長度」，並補一句「wrapper 動的是 `rdi`/`rcx`/`r8`/`r9`，不會動 `rdx`」 |
| E4 | **已修** | `pwn1/notes.md` | §6「第二次 read 從 `buf+0x00` 開始」→ **`buf + 0x08`**（`rsp=buf+0x88`，`rsi=rsp-0x80`），並補「15 bytes 蓋在 `buf+0x08`~`buf+0x16` 的 padding，所以安全」；§階段 4 的註解同步精確化 |
| E5 | **已修** | `pwn7/notes.md` | §3.6 組語清單補上漏掉的 `0x401fb2 xor eax,eax`、`0x401fb4`、`0x401fb9`；說明改成「`ax = 0` 是 `xor eax,eax` 造成的」，刪掉誤植的 `test al,al` |
| E6 | **已修** | `wp/99_速查表.md` | §8 chunk 結構改為 glibc 正確定義：`+0x00 prev_size`、`+0x08 size`、**`+0x10 user data`（malloc 回傳值）**，並讓 free 表與之自洽 |
| E7 | **已修** | `pwn1/notes.md`、`pwn1/exploit.py` | §4 `0x401069` 的註解改成「唯一『syscall 後面接 ret』的位置」，並補「全檔共 4 條 syscall（`0x401014`/`0x40102f`/`0x40104c`/`0x401069`）」；exploit.py 第 58 行的常數註解同步改成「唯一『syscall 後面接 ret』的 gadget」 |
| E8 | **已修** | `pwn7/notes.md` §2、`pwn7/exploit.py` 第 14 行 | `key` 儲存位置 `.data:0x405060` → **`.bss:0x405060`**（`readelf -S`：`.data` = 0x405000 + 0x10、`.bss` = 0x405020 + 0x5360） |
| E9 | **已修** | `wp/00_基礎知識_從零開始.md` §2 | `pip install seccomp-tools` → `gem install seccomp-tools`（並註明是 Ruby gem，要先裝 ruby） |
| E10 | **已修** | `wp/99_速查表.md` §9 | `p = process('./chal'):` → `p = process('./chal')`（去掉冒號） |
| E11 | **已修** | `wp/00_基礎知識_從零開始.md` §10.4 | 16-byte 對齊條件改寫：**`call` 前 `rsp % 16 == 0`**；被呼叫函式第一道指令時 **`rsp % 16 == 8`**，並說明「對齊用 `ret`」的真正作用 |
| E12 | **已修** | `pwn7/notes.md` §3.1 | 輸入緩衝區 `0x401 bytes` → **`0x400` bytes**（`rsp+0x420`~`rsp+0x81f`，最多 `0x3ff` 字元 + `\0`） |
| E13 | **已修** | `pwn1/notes.md` §6 步驟 1 | 「`sigreturn` 洩漏出來的值」→「**`0x401016` 的 leak 函式**用 `push rsp` + `write(1,rsp,8)` 印出來的（跟 sigreturn 無關）」 |
| E14 | **已補** | `pwn7/notes.md` §6 | 補一段 `0x401c20` 的完整組語：`pop rbx` 在 `0x401c31`、`mov rdx,rax` 在 `0x401c32`，說明「跳進函式中段」會跳過 `push rbx`/`call strlen`，`rbx` 不會被覆蓋 |
| E15 | **已修** | `pwn1/notes.md` §5.3 frame 表 | `csgsfs` 大小 `6` → `8 (用到 6)`，註明 `cs/gs/fs` 各 2 bytes + 2 bytes padding，`err` 從 `0xc0` 開始 |
| E16 | **已修** | `pwn7/notes.md` §9 #3 | 「`SUBMIT 256` 的 `bl` = 0 → `read` 讀 0 bytes」→ 更正為「**還沒進 `read` 就被擋掉**：`0x401eed test al,al` / `0x401eef je 0x401f38` → 印 `ERR bad size` 後返回」 |

**E1 ~ E16：16 項全部已修（0 項略過）。**

### 驗證方式（實跑結果節錄）

* E1：`gdb -q -batch`（附錄 A 腳本重建三段鏈）→ `[0x401c32] rax=3 rdi=1 rsi=0x405060`、`rsi=0x405063`（各 3 bytes = 共 6 bytes）。
* E2：同腳本 → `[0x401fda] rsp=0x40a330 rbx=0x40a340 => rsp+0x10=0x40a340`，而 `A3=0x40a2e0` ⇒ `rsp = A3+0x50`。
* E3：`objdump -d -M intel service | grep -E '\bpop\s+rdx'`（無輸出）；glibc 2.44 的 `write`/`read` wrapper 反組譯只有 `movsxd rdi,edi`、`xor r9d,r9d`、`xor r8d,r8d`、`xor ecx,ecx`。
* E4：附錄 B 腳本 → `[0x401054] rsi=0x…de98`（第一次）→ `0x…dea0`（第二次）= `buf+0x08`；`[0x401069] rsp=0x…df28 rax=15` = `buf+0x90`。
* E5：`objdump --start-address=0x401fa6 --stop-address=0x401fc8` → 確認 `401fb2: xor eax,eax`。
* E6：glibc `malloc_chunk` 標準定義 + 與本檔 free 表自洽。
* E7：`objdump -d -M intel challenge | grep syscall`（4 筆：`401014`/`40102f`/`40104c`/`401069`）。
* E8：`readelf -S service | grep -A1 -E '\.data|\.bss'`。
* E9：`python3 -m pip index versions seccomp-tools` → `No matching distribution found`。
* E10：`python3 -c "p = process('./chal'):"` → `SyntaxError`。
* E11：System V AMD64 ABI 定義。
* E12：`objdump --start-address=0x4014b5 --stop-address=0x401537` → `lea rbx,[rsp+0x81f]`；`0x81f-0x420 = 0x3ff`。
* E13：`pwn1/challenge` 反組譯（`0x401016 push rsp`）。
* E14：`objdump --start-address=0x401c20 --stop-address=0x401c3a`。
* E15：`bytes(SigreturnFrame())[0xb8:0xc0].hex()` = `3300000000000000`（8 bytes）。
* E16：`printf 'SUBMIT 256\n' | ./service` → `ERR bad size`。

---

## 2. 新手卡點 B1 ~ B18

| # | 狀態 | 檔案 | 改了什麼 |
|---|---|---|---|
| B1 | **已補** | `pwn1/notes.md` §3.3 | 新增「怎麼自己重現這張表」：可複製的 `make_input.py` + `/tmp/t.gdb` + `gdb -q -batch -x`，並說明「ASLR 每次不同，要看**差值**（`0x08` / `0x90`）」與「`0x401069` 會被命中 4 次」。已實跑驗證腳本可照抄使用 |
| B2 | **已補** | `pwn1/notes.md` §6 步驟 3 後 | 新增「⚠️ 為什麼 `payload.ljust(0x400)` 不能省」：送太多/太少分別會發生什麼、為什麼要「先送 0x400 再單獨送 15 bytes」 |
| B3 | **已補** | `pwn1/notes.md` §6 | 把「執行流程（第一輪）」圖換成「**3 次 read、2 次 send**」對照表（誰吃掉哪個 payload、送完 `rax` 是多少），並補上 payload 記憶體佈局圖 |
| B4 | **已補** | `pwn1/notes.md` §5.1 開頭 | 先定義 `rt_sigframe` / `ucontext` / `struct sigcontext` / `sigframe`（本筆記簡稱）四者差別的表 |
| B5 | **已補** | `wp/00_基礎知識_從零開始.md` §1 名詞表 + §12 | 名詞表新增 **little-endian** 一列（含 `p64(0x401040)` 的 byte 範例）；§12 補「🔴 端序」提醒（`p16(4)` 不能用在大端協定，pwn7 要自己寫 `b"\x00\x04"`） |
| B6 | **已補** | `pwn1/notes.md` §5.3 | 同 E15（`csgsfs` 大小 8，用到 6） |
| B7 | **已補** | `pwn1/notes.md` §7、`pwn1/exploit.py` | §7 新增**本地**執行輸出並說明 `pwn1/flag.txt` 是假 flag；exploit 的 `flag not found` 訊息改成「本地會看到 `sun{LOCAL_DUMMY_FLAG}`；真 flag 要打 REMOTE」 |
| B8 | **已補** | `pwn1/notes.md` §9、`pwn7/notes.md` §10、`wp/00` §12 | 三處都加上「⚠️ 一定要 `cd pwn1/`（或 `cd pwn7/`）再跑，exploit 用相對路徑 `./challenge`、`./service`；或直接用 `wp/run_all.sh`」 |
| B9 | **已補** | `pwn7/notes.md` §2.2 | 在 BPF 清單前補 `struct sock_filter` 8-byte 欄位拆解，並用 5 條實際立即數（`0x400000020`…）示範怎麼拆成 code/jt/jf/k；附 `seccomp-tools dump`（Ruby gem）說明 |
| B10 | **已補** | `pwn7/notes.md` §6.2 | 新增 `.bss` 記憶體地圖（`0x405060` key / `0x405080` fd 槽 / `0x4060b0` 槽表 / `0x40a168` / `0x40a180` / `0x40a188`）與「SUBMIT 溢位後每一步 `rsp`」的逐步圖 |
| B11 | **已補** | `pwn7/notes.md` §7 階段 1、`pwn7/exploit.py` | 註解改成明確說明「`p64(0)*3` 其實不會被讀到（`pop rsp` 一執行完 `rsp` 就跑到 `.bss`），留著只是為了長度剛好 112」 |
| B12 | **已補** | `pwn7/notes.md` §6.3 | 新增兩張表：每段鏈的固定佈局（`A+0x00`/`A+0x40`/`A+0x48`）與 d1/d2/d3 的位址對照 |
| B13 | **已補** | `pwn7/notes.md` §6.3 | 補「💡 為什麼鏈的起點等於 `read` 目標」（`0x401f07` 是 `ret` 進去的，`rsp` 正好指向下一段鏈起點），並警告不要誤解成「鏈放在 read 目標 + 0x48」 |
| B14 | **已補** | `pwn7/notes.md` §1 | 補「`SHSTK`/`IBT` 只是 ELF 屬性註記（`readelf -n`），不等於執行時啟用」，並指出本題純 `ret` ROP 實測成功 |
| B15 | **已補** | `wp/00` §11.4、`wp/99_速查表.md` §6 | 兩處都加「用 `SigreturnFrame()` 前一定要 `context.arch = 'amd64'`，否則 `kernel architecture must be specified`」 |
| B16 | **已補** | `wp/00` §10.2 開頭 | 加「`0x401234` / `BINSH_ADDR` / `SYSTEM_ADDR` / `POP_RDI` / `RET` 都是**佔位符**，要用自己題目的 binary 找真位址」 |
| B17 | **已補** | `wp/00` §1 名詞表、§4.1、§5.2 | 名詞表新增 **shellcode**；`fs:0x28` 註解補上 TLS 說明；`jg`/`ja` 提示後補 `ZF`（`je` 看的是「上一次 `cmp`/`test` 是否為 0」） |
| B18 | **略過** | — | 原因：重跑 `for d in pwn1..pwn7; [ -f $d/notes.md ]` → **全部 YES**，`../pwn2`~`../pwn7/notes.md` 現在都存在，沒有壞連結可修（詳見 S1） |

---

## 3. 術語 T1 ~ T15

| # | 狀態 | 檔案 | 改了什麼 |
|---|---|---|---|
| T1 | **已補** | `wp/00` §3 | non-PIE 首次出現處改成「（這種 binary 叫 **non-PIE**，見 4.3 節）」 |
| T2 | **已補** | `wp/00` §4.4 | RELRO 開頭加「（`.got` / `.got.plt` 是什麼見第 8 節）」 |
| T3 | **已補** | `wp/99_速查表.md` §4 | 補「`@plt` 結尾＝呼叫外部函式的跳板（見 00 第 8 節）」 |
| T4 | **已補** | `wp/00` §1 名詞表 | 新增 **canary**、**RELRO** 兩列（附「見 4.1 / 4.4」） |
| T5 | **已補** | 同 B17 | `ZF` / `TLS` / `shellcode` 三個詞都已定義 |
| T6 | **已修** | 同 E11 | `movaps` 對齊條件已更正 |
| T7 | **已補** | 同 B4 | `sigframe` 的定義移到第一次出現之前 |
| T8 | **已修** | `pwn1/notes.md` §6 步驟 1 | 改成「`R0` = `_start` 第一道指令執行時的 `rsp`（本題 `leak = R0-8`）」 |
| T9 | **已補** | 同 B5 | little-endian 已有定義 |
| T10 | **已補** | 同 B9 | seccomp / BPF 先解釋再給清單 |
| T11 | **已補** | `pwn7/notes.md` §2 | 補「這裡的『IPC』指的是父子行程用 `socketpair` 那條 fd 3 通道互相傳封包」 |
| T12 | **已補** | 同 B10 | stack pivot 已有記憶體圖 |
| T13 | **已補** | `pwn7/notes.md` §2 | 補 `PR_SET_NO_NEW_PRIVS`(38) 與 `SECCOMP_SET_MODE_FILTER`(1) / `seccomp()`(317) 的意義 |
| T14 | **已補** | 同 B5 | 端序知識已在 00 鋪好 |
| T15 | **已補** | `wp/99_速查表.md` §8 | 補「hook = glibc 內部特定時機會呼叫的函式指標，改掉它就等於劫持控制流（2.34 後已移除）」 |

---

## 4. 結構與一致性 S1 ~ S7

| # | 狀態 | 檔案 | 改了什麼 |
|---|---|---|---|
| S1 | **略過** | — | 原因：實測 `pwn1`~`pwn7` 的 `notes.md` **全部存在**，`wp/00` 的閱讀順序與附錄對照表的 7 個連結全部指得到檔案；§9 的 pwn4 那格本來就沒有連結。沒有需要修的地方 |
| S2 | **已補** | 同 B8 | 兩篇 notes 的一頁速查 + 00 §12 都寫上「要在題目目錄下執行」 |
| S3 | **已修** | 同 B7 | `pwn1/exploit.py` 訊息更正 + notes §7 補本地輸出 |
| S4 | **部分已補** | `pwn7/notes.md` §7 階段 4 | notes 新增 `recvall(timeout=3)` 與 `recvn(6)` 的用途說明（`time.sleep(0.7)` 本來就在 §9 #8 有解釋）；程式碼與 notes 的逐字比對結果其餘項目皆為 ✅，無需修改 |
| S5 | **部分已補** | `pwn1/notes.md` §1、`pwn7/notes.md` §1 | pwn1 補「`NX unknown - GNU_STACK missing` ⇒ 沒有 `GNU_STACK` segment ⇒ 核心預設給可執行堆疊」的解釋；pwn7 補 `RUNPATH: b'$ORIGIN'` 說明與「本地/遠端 libc 不同不影響本題」。**註：審查者說 pwn1「把兩行合併成一行」與現況不符（原本就是五行），故只補解釋、未改輸出區塊** |
| S6 | **已修** | `wp/00`、`wp/99`、`pwn1/notes.md`、`pwn7/notes.md` | ①00 §6.3 補「`offset=(rbp-&buf)+8` 與 `buf+0x80` 兩種講法等價」；②`sigframe` 在 pwn1 §5.1 第一次出現處定義；③99 §5.1 與 00 §10.4 都註明「對齊用 `ret` 放哪裡都行，重點是總共多走 8 bytes」；④00 §12 的 `./ld-linux.so` 統一為 `./ld-linux-x86-64.so.2`；⑤00 附錄補 **flag 檔命名規則**（`FLAG.txt`/`FLAG_REMOTE.txt`＝遠端實打真 flag、`flag.txt`＝題目附的假 flag）；⑥pwn7 §10 一頁速查的漏洞編號改回與 §6、exploit 註解一致（漏洞 1 SUBMIT／漏洞 2 RELAY 只送 len=0／漏洞 3 負索引） |
| S7 | **已補** | `pwn7/notes.md` §7 階段 3 | 補上「第 9 個 byte 是 `d2[8]`（= 0x00），會留在 socket 裡等保險箱下一次讀標頭；能混過去是因為我們不在乎下一條訊息」，並警告「這不是通則」 |

---

## 5. 審查者說法有誤 / 未完全套用的地方

| 項目 | 審查者說法 | 實際查證 | 處理 |
|---|---|---|---|
| E2 的**推導理由** | 「`RESP` 的來源不是 `rsp+8`，是 `RELAY` 內部的 `lea rbx,[rsp+0x10]`（`0x401fb9`）」 | `0x401fb9` 確實在 `RELAY` 裡，但我們是**跳到 `0x401fda`（函式中段）**，那條 `lea` **不會執行**；`0x401fda` 的第一道指令是 `mov rsi,rbx`，`rbx` 來自我們鏈上的 `pop rbx`（`d3[0x40:0x48] = p64(RESP)`）。審查者的 `A3+0x58→A3+0x50`、`RESP=A3+0x60` 結論正確，但「`rbx` 由 RELAY 自己設」的理由不成立 | **結論照改**（`rsp=A3+0x50`、`RESP=A3+0x60`），但推導**自己重寫**成「標頭解析以 `rsp+0x10` 為基準」＋「`rbx` 必須由鏈設成 `RESP`，兩者要一致」，並加註「`0x401fb9` 不會執行」 |
| S5（pwn1） | 「pwn1 notes §1 把兩行合併成 `NX: NX unknown…(實際上是 Stack: Executable)`，實際輸出是五行」 | 檔案本來就完整貼了五行（RELRO/Stack/NX/PIE/Stack），只是多了一句括號註解，沒有「合併」 | 只補「`GNU_STACK` 缺失 ⇒ 可執行堆疊」的解釋；**未重貼輸出**（原本就正確） |
| B18 / S1 | 文件指向不存在的 `pwn4/pwn6 notes.md`，會卡死新手 | 重跑存在性檢查：`pwn1`~`pwn7` 的 `notes.md` **全部存在**（pwn4 00:39、pwn6 00:34 已補上），`wp/00` 的連結全部有效 | **略過**（已無壞連結） |
| S4 末列 | notes 沒引用 `time.sleep(0.7)` / `recvall` | `time.sleep(0.7)` 其實在 §9 #8 已有完整說明，只有 `recvall` 真的沒解釋 | 只補 `recvall` / `recvn` 的說明，其餘不動 |

---

## 6. 迴歸測試（改完後實跑，四個全部 PASS）

```
=== [1] pwn1 local（cd pwn1 && python3 exploit.py < /dev/null）===
[x] Starting local process './challenge'
[+] Starting local process './challenge': pid 3527093
[+] stack leak  = 0x7ffe739058a8
[*] vuln buffer = 0x7ffe73905828

[+] raw output:
sun{LOCAL_DUMMY_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

[+] FLAG: sun{LOCAL_DUMMY_FLAG}
[*] Stopped process './challenge' (pid 3527093)

=== [2] pwn1 remote（cd pwn1 && python3 exploit.py REMOTE < /dev/null）===
[x] Opening connection to chal.sunshinectf.games on port 26003
[x] Opening connection to chal.sunshinectf.games on port 26003: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26003: Done
[+] stack leak  = 0x7ffc1056f998
[*] vuln buffer = 0x7ffc1056f918

[+] raw output:
sun{r3caLl_ev3Ry_reGist3r_sR0p}
uid=1337(total_recall) gid=1337(total_recall) groups=1337(total_recall)
DONE

[+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}
[*] Closed connection to chal.sunshinectf.games port 26003

=== [3] pwn7 local（cd pwn7 && python3 exploit.py < /dev/null）===
[x] Starting local process './service'
[+] Starting local process './service': pid 3527243
[*] stage2 pre=b'OK\n' leak=3d2573f00000 A2=0x40a228
[+] XOR key = 3d2573f0
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 30B
[+] Receiving all data: Done (30B)
[*] Process './service' stopped with exit code -11 (SIGSEGV) (pid 3527243)

[+] raw  : b'OK\nSUNSHINE{local_test_flag}\n\n'
[+] FLAG: SUNSHINE{local_test_flag}

=== [4] pwn7 remote（cd pwn7 && python3 exploit.py REMOTE < /dev/null）===
[x] Opening connection to chal.sunshinectf.games on port 26007
[x] Opening connection to chal.sunshinectf.games on port 26007: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26007: Done
[*] stage2 pre=b'OK\n' leak=c4fbacd30000 A2=0x40a228
[+] XOR key = c4fbacd3
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 3B
[x] Receiving all data: 44B
[+] Receiving all data: Done (44B)
[*] Closed connection to chal.sunshinectf.games port 26007

[+] raw  : b'OK\nsun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}\n\n'
[+] FLAG: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
```

| 測試 | 結果 | flag |
|---|---|---|
| pwn1 local | **PASS** | `sun{LOCAL_DUMMY_FLAG}` |
| pwn1 REMOTE | **PASS** | `sun{r3caLl_ev3Ry_reGist3r_sR0p}` |
| pwn7 local | **PASS** | `SUNSHINE{local_test_flag}` |
| pwn7 REMOTE | **PASS** | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` |

> pwn7 本地結尾的 `SIGSEGV` 是預期行為（flag 印完後鏈走到盡頭），不是失敗。
> 這次對兩支 exploit 只改了**註解**（`pwn1/exploit.py`：本地 flag 訊息 + 15 bytes 落點註解；
> `pwn7/exploit.py`：`.bss` 位置、漏洞 2 註解、`p64(0)*3` 說明），
> **邏輯完全沒有動**，四項測試改前改後都 PASS。

---

## 7. 一句話總結

E1~E16 全數修正；B1~B17 全數補上（B18 因檔案已存在而略過）；T1~T15 全數處理；
S1 略過（連結已全部有效）、S2~S7 已修（S4/S5 為部分補強）。
審查者有三處說法與實況不符（E2 的推導理由、S5 的「兩行合併」、S1/B18 的壞連結），
已在上表列明並以實測為準。
