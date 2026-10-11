# 第 3 輪審查（最終驗證）— Part A：端到端功能驗證

> 驗證者：自動化審查 agent
> 驗證時間：2026-09-28 01:20 ~ 01:45（CST）
> 驗證環境：Arch Linux、Python 3.14.6、pwntools 4.15.0、ROPgadget 7.7、checksec（pwntools 版）、
> GDB 17.2、gem 3.4.0（one_gadget 1.10.0）、patchelf 0.19.1
> **未安裝**：ropper、pipx、pwndbg、seccomp-tools、tmux
>
> 本檔只做「實跑驗證」。**沒有修改任何其他檔案**（僅本檔為新建）。

---

## 1. 7 題重現結果

### 1.1 總表

| # | local 模式 | REMOTE 第 1 次 | REMOTE 第 2 次 | REMOTE 第 3 次（逐 byte） | 等於預期 flag | 判定 |
|---|---|---|---|---|---|---|
| pwn1 | `sun{LOCAL_DUMMY_FLAG}` | `sun{r3caLl_ev3Ry_reGist3r_sR0p}` | 同左 | 同左 | ✅ | **PASS** |
| pwn2 | `sun{LOCAL_DUMMY_FLAG}` | `sun{f1ll_iN_th3_g0T_eNtry}` | 同左 | 同左 | ⚠️ 見 1.3 | **PASS（有文件瑕疵）** |
| pwn3 | `sun{LOCAL_TEST_FLAG}`（印兩次） | `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}` | 同左 | 同左 | ✅ | **PASS** |
| pwn4 | `sun{LOCAL_TEST_FLAG}` | `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` | 同左 | 同左 | ✅ | **PASS** |
| pwn5 | `sun{LOCAL_DUMMY_FLAG}` | `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}` | 同左 | 同左 | ✅ | **PASS** |
| pwn6 | `sun{local_test_flag}` | `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` | 同左 | 同左 | ✅ | **PASS** |
| pwn7 | `SUNSHINE{local_test_flag}` | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` | 同左 | 同左 | ✅ | **PASS** |

* 「REMOTE 第 1 次」＝ `./wp/run_all.sh` 第一次完整執行。
* 「REMOTE 第 2 次」＝ `./wp/run_all.sh` 第二次完整執行（穩定性複驗）。
* 「REMOTE 第 3 次」＝ 逐題單獨執行並用 `grep -oaE 'sun\{[^}]*\}'` 逐 byte 抓取，用來排除肉眼誤判大小寫。
* `run_all.sh` 兩次的 stdout 都是 `[+] FLAG: sun{...}` 或 `FLAG: sun{...}`；pwn6 額外會噴二進位雜訊（已用 `tr -d '\000'` 處理，符合文件說明）。
* **7 題在 3 次獨立遠端執行中全部拿到 flag，無任何一次失敗、無 timeout、無需重試**（pwn2 的 exploit 內建 5 次重試，三次都在 `attempt 1/5` 就成功）。

### 1.2 LOCAL 模式逐題輸出（`cd pwnN && python3 exploit.py < /dev/null`）

| # | 指令 | 關鍵輸出 | 印出的 flag |
|---|---|---|---|
| pwn1 | `cd pwn1 && python3 exploit.py < /dev/null` | `[+] stack leak = 0x7ffc77d1bc48` / `[*] vuln buffer = 0x7ffc77d1bbc8` / `uid=1001(kzzz) ... DONE` | `sun{LOCAL_DUMMY_FLAG}` |
| pwn2 | `cd pwn2 && python3 exploit.py < /dev/null` | `[+] canary` / `[+] saved rbp` / `[+] libc base` / `[+] PIE base` / `[+] system` / `[*] write payload (112 bytes)` / `[*] printf@GOT should now contain system()` | `sun{LOCAL_DUMMY_FLAG}` |
| pwn3 | `cd pwn3 && python3 exploit.py < /dev/null` | `[*] target libc: local libc /usr/lib/libc.so.6` / `[+] strcspn@got overwritten` / 結尾多一行 `score> ` | `sun{LOCAL_TEST_FLAG}`（**印兩次**） |
| pwn4 | `cd pwn4 && python3 exploit.py < /dev/null` | `[+] unsorted bin head` / `[+] safe-linking key = 0x55557222c` / `[+] libc fingerprint: Ubuntu glibc 2.39` / 選單 | `sun{LOCAL_TEST_FLAG}` |
| pwn5 | `cd pwn5 && python3 exploit.py < /dev/null` | `[+] canary` / `[+] saved rbp` / `[+] PIE base` / `[+] shell should be up` / 行程最後 `SIGSEGV` 收尾 | `sun{LOCAL_DUMMY_FLAG}` |
| pwn6 | `cd pwn6 && python3 exploit.py < /dev/null` | `[+] handshake ok` / `[+] heap leak` / `[*] triggering system(...)` / `[*] local test flag -> FLAG.txt left untouched` | `sun{local_test_flag}` |
| pwn7 | `cd pwn7 && python3 exploit.py < /dev/null` | `[+] XOR key` / `[+] raw : b'OK\nSUNSHINE{local_test_flag}\n\n'` / 行程 `SIGSEGV` 收尾 | `SUNSHINE{local_test_flag}` |

**7 題 local 模式全部在 `</dev/null`（無 TTY）下正常結束、exit code 0，符合 README 第 80-85 行與 `00_recon.md` 第 54 行的說明。**

`pwn3` 本地 flag 印兩次 + 結尾 `score> ` 與 `pwn3/notes.md` §10.1 的描述**逐字一致**；
`pwn2` 本地確實**沒有**出現 `sh: -c:` 訊息，與 §9-14（E6 修正後）的描述一致。

### 1.3 ⚠️ pwn2 flag 大小寫不一致（本輪最重要的發現）

以原始 byte 抓取（`grep -oaE 'sun\{[^}]*\}' | xxd`）：

* **實際遠端回傳**（3 次都一樣）＝ `sun{f1ll_iN_th3_g0T_eNtry}`
  ```
  00000000: 7375 6e7b 6631 6c6c 5f69 4e5f 7468 335f  sun{f1ll_iN_th3_
  00000010: 6730 545f 654e 7472 797d 0a              g0T_eNtry}.
  ```
  → 第 17 個字元是 **小寫 `g`（0x67）**。
* **`pwn2/FLAG.txt`**、**`pwn2/notes.md`** 也都是小寫 `g0T` ✅ 與遠端一致。
* **`wp/README.md` 第 15 行** 與 **`wp/00_recon.md` 第 19 行** 寫的是 `sun{f1ll_iN_th3_G0T_eNtry}`
  （第 17 個 byte 是 **大寫 `G`（0x47）**）❌ **與真實 flag 差 1 個 byte**。

程式化比對結果：

```
expected(README): ['s','u','n','{','f','1','l','l','_','i','N','_','t','h','3','_','G','0','T', ...]
got(FLAG.txt)   : ['s','u','n','{','f','1','l','l','_','i','N','_','t','h','3','_','g','0','T', ...]
equal? False     diff at index 16: 'G' vs 'g'
```

**結論：`pwn2/FLAG.txt` 是對的（＝真實遠端 flag）；`wp/README.md` 與 `wp/00_recon.md` 各有一個大小寫錯字。**
（註：本次任務指示中列出的「預期 flag」也寫成大寫 `G`，與 README 相同 —— 若該清單是從 README 抄來的，
則清單本身也繼承了這個錯字。以**實測遠端回應為準**，正確的是小寫 `g0T`。）

### 1.4 flag.txt / FLAG.txt 檢查

| 檔案 | 內容 | 判定 |
|---|---|---|
| `pwn1/FLAG.txt` | `sun{r3caLl_ev3Ry_reGist3r_sR0p}` | ✅ |
| `pwn2/FLAG.txt` | `sun{f1ll_iN_th3_g0T_eNtry}` | ✅（README/recon 有錯字，見 1.3） |
| `pwn3/FLAG.txt` | `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}` | ✅ |
| `pwn4/FLAG.txt` | `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` | ✅ |
| `pwn5/FLAG.txt` | `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}` | ✅ |
| `pwn6/FLAG.txt` | `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` | ✅ |
| `pwn7/FLAG.txt` | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` | ✅ |
| `pwn7/FLAG_REMOTE.txt` | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` | ✅（與 FLAG.txt 相同內容） |
| `pwn1..pwn5/flag.txt` | `sun{LOCAL_DUMMY_FLAG}` / `sun{LOCAL_TEST_FLAG}` | ✅ 明顯假 flag |
| `pwn6/flag.txt` | `sun{local_test_flag}` | ✅ 明顯假 flag |
| `pwn7/flag.txt` | `SUNSHINE{local_test_flag}` | ✅ 明顯假 flag |

* 7 個 `FLAG.txt` 全部存在、全部與實測遠端 flag 逐字相同（pwn2 見 1.3）。
* 7 個 `flag.txt` **全部是明顯的假 flag**（含 `LOCAL_DUMMY` / `LOCAL_TEST` / `local_test` 字樣），
  沒有一個誤放真 flag。
* `wp/00_基礎知識_從零開始.md` §附錄（第 1191-1195 行）對 `FLAG.txt` / `FLAG_REMOTE.txt` / `flag.txt`
  三種命名的說明，與實際檔案狀態**完全相符** ✅。

### 1.5 ⚠️ 副作用：跑 exploit 會改寫 `FLAG.txt`

`pwn4/exploit.py:218-221` 與 `pwn6/exploit.py:262-273` 在成功拿到 flag 後會**寫回 `FLAG.txt`**：

```python
# pwn4
if flag != 'sun{LOCAL_TEST_FLAG}':       # never clobber the real flag
    open(os.path.join(HERE, 'FLAG.txt'), 'w').write(flag + '\n')
```

* 這是刻意的保護設計（不會被 local 假 flag 蓋掉），本次驗證後內容仍與真實 flag 相同，**無損害**。
* 但**每次跑 REMOTE 都會更新 `pwn4/FLAG.txt` 與 `pwn6/FLAG.txt` 的 mtime**（本次驗證中兩檔 mtime 被更新到
  `01:24:37` / `01:25:10`）。若這些檔案有進版控，重跑驗證會產生無意義的 diff —— 建議在 README 註明，
  或讓 exploit 只在內容不同時才寫檔。

---

## 2. 指令實測結果

### 2.1 `wp/README.md` 與 `wp/run_all.sh` 文件化的指令

| # | 文件中的指令 | 出處 | 實測結果 | 判定 |
|---|---|---|---|---|
| 1 | `./run_all.sh`（跑全部 7 題） | README:92 | 從 `wp/` 目錄執行 → **7 題全過** | ✅（限在 `wp/` 內） |
| 2 | `./run_all.sh`（同上） | README:92 | 從**專案根目錄**執行 → `bash: ./run_all.sh: No such file or directory` | ❌ **README 沒說要先 `cd wp`** |
| 3 | `./run_all.sh pwn1 pwn4` | README:93 | 只跑 pwn1、pwn4，兩題都拿到 flag，exit 0 | ✅ |
| 4 | `./wp/run_all.sh pwnN` | README:26、00:990、99:300 | 從根目錄 `./wp/run_all.sh pwn6` → `FLAG: sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` | ✅ |
| 5 | `cd pwnN && python3 exploit.py` | README:82-83 | 7 題全部正常結束並印出 local 假 flag | ✅ |
| 6 | `cd pwnN && python3 exploit.py REMOTE` | README:84 | 7 題全部拿到真 flag | ✅ |
| 7 | `checksec --file=./pwnN/<binary>` | README:23 | 7 支 binary 實跑成功，輸出與 README 成果總表的保護機制欄**逐項相符** | ✅ |
| 8 | `python3 -c "from pwn import *; print(ELF('./pwnN/<binary>',checksec=False).checksec())"` | README:24 | 7 支全部成功，結果與 `checksec` 一致 | ✅ |
| 9 | `ls wp/` | README:70 | 可執行 | ✅ |
| 10 | `cat flag.txt`（題目目錄內） | README:76 | 7 題都印出假 flag | ✅ |
| 11 | `python3 exploit.py REMOTE PORT=<port>` | run_all.sh:25 | run_all.sh 內部就是用這個形式，實跑成功 | ✅ |

**保護機制逐項核對（`checksec` 實測 vs README 成果總表）**

| # | README 寫的 | 實測 | 判定 |
|---|---|---|---|
| pwn1 | 靜態、non-PIE、NX off、無 canary、stripped | `statically linked`、`No PIE (0x400000)`、`NX unknown - GNU_STACK missing`+`Stack: Executable`、`No canary`、`stripped`；`.text = 0x6c`（＝108 bytes，與 README 一致） | ✅ |
| pwn2 | PIE、canary、NX、Partial RELRO | `PIE enabled` / `Canary found` / `NX enabled` / `Partial RELRO` | ✅ |
| pwn3 | non-PIE、無 canary、NX、Partial RELRO | 全數相符 | ✅ |
| pwn4 | non-PIE、canary、NX、Partial RELRO | 全數相符 | ✅ |
| pwn5 | PIE、canary、NX、Full RELRO | 全數相符 | ✅ |
| pwn6 | PIE、canary、NX、Partial RELRO | 全數相符 | ✅ |
| pwn7 | non-PIE、無 canary、NX、Full RELRO、seccomp | `No PIE` / `No canary` / `NX enabled` / `Full RELRO`；`readelf -s` 確認匯入 `prctl@GLIBC_2.2.5`（`seccomp-tools` 未安裝，無法 dump 規則，但 seccomp 存在的證據充分） | ✅ |

### 2.2 `wp/00_基礎知識_從零開始.md` §2（環境安裝）

| # | 指令 | 實測結果 | 判定 |
|---|---|---|---|
| 1 | `sudo pacman -S python-pwntools ropgadget ropper gdb`（註解說「都在 extra」） | `pacman -Si` 逐一查證：`python-pwntools 4.15.0-2`(extra)、`ropgadget 7.7-1`(extra)、`ropper 1.13.13-2`(extra)、`gdb 17.2-1`(extra) — **四個都在 extra，敘述正確** | ✅ |
| 2 | `python-pwntools 就在 extra（4.15.0-2）` | 實查版本正是 `4.15.0-2` | ✅ 逐字正確 |
| 3 | `sudo apt install python3-pwntools ropgadget gdb` | 本機是 Arch（無 apt），**無法驗證** | ⚠️ 不可驗證 |
| 4 | `apt-cache policy python3-pwntools` | 無 apt，無法驗證 | ⚠️ 不可驗證 |
| 5 | `python3 -m venv ~/.pwn && source ~/.pwn/bin/activate` | `import venv` 成功；實際建立會寫入 `$HOME`（本次沙箱 `$HOME` 唯讀）→ **未實際執行**，指令形式正確 | ⚠️ 形式正確、未實跑 |
| 6 | `pip install pwntools ropgadget`（venv 內） | 未實跑（依賴 #5） | ⚠️ 未實跑 |
| 7 | `sudo pacman -S python-pipx && pipx install pwntools` | `python-pipx 1.15.0-1`(extra) 存在 ✅；但 `pipx` **本機未安裝**，故 `pipx install` 需先做前半段（文件有寫，OK） | ✅ |
| 8 | `pip install --break-system-packages pwntools ropgadget` | `python3 -m pip install --help` 中含 `--break-system-packages` → **flag 存在** | ✅ |
| 9 | `sudo pacman -S python-pwntools gdb` | 兩套件都存在（同 #1） | ✅ |
| 10 | `python3 -c "from pwn import *; print('pwntools ok')"` | 實際輸出 `pwntools ok` | ✅ |
| 11 | `sudo apt update` / `sudo apt install gdb python3-pwntools` | 無 apt，無法驗證 | ⚠️ 不可驗證 |
| 12 | `git clone https://github.com/pwndbg/pwndbg` | `git ls-remote` 成功（repo 可達） | ✅ |
| 13 | `cd pwndbg && ./setup.sh` | GitHub API 確認 `setup.sh` 存在（7248 bytes, ref=dev）→ 指令形式正確 | ✅ |
| 14 | `sudo pacman -S ropgadget` | `ropgadget 7.7-1`(extra) | ✅ |
| 15 | `sudo pacman -S ropper` | `ropper 1.13.13-2`(extra) | ✅ |
| 16 | `gem install one_gadget` | `gem list one_gadget` → `one_gadget (1.10.0)` **已安裝**，指令形式正確 | ✅ |
| 17 | `gem install seccomp-tools` | `gem list seccomp-tools` → **空（未安裝）**；且 `gem list -r` 因 `$HOME/.cache/gem` 唯讀而 `Errno::EROFS` → **本環境無法驗證安裝**（沙箱限制，非文件錯誤） | ⚠️ 不可驗證 |
| 18 | `sudo pacman -S patchelf` | `patchelf 0.19.1-1`(extra) | ✅ |
| 19 | `sudo pacman -S ruby`（`gem` 的前置） | `ruby 3.4.10-1`(extra) | ✅ |
| 20 | `checksec --file=./challenge` | 成功，輸出 `No RELRO / No canary found / NX unknown - GNU_STACK missing / No PIE` | ✅ |
| 21 | `python3 -c "from pwn import *; print(ELF('./challenge', checksec=False).checksec())"` | 成功，結果同上 | ✅ |

**§2 判定：所有「可在本機驗證」的指令 14/14 全過，其中 `python-pwntools 4.15.0-2`、`ropper 1.13.13`
兩個版本號敘述與 `pacman -Si` 逐字相符。** 5 條 Ubuntu / venv / seccomp-tools 指令因環境（無 apt、
`$HOME` 唯讀）無法實測，**不列為文件錯誤**，但也不應宣稱已驗證。

### 2.3 `wp/00_基礎知識_從零開始.md` §13（gdb 速查）

| # | 指令 | 文件聲稱 | 實測結果 | 判定 |
|---|---|---|---|---|
| 1 | `set pagination off` | — | 正常 | ✅ |
| 2 | `set disassembly-flavor intel` | — | 正常（反組譯輸出為 Intel 語法） | ✅ |
| 3 | `b *0x401234` | 對 non-PIE 有效 | `Breakpoint 1 at 0x401234` | ✅ |
| 4 | `b *main+42` | 「stripped → 會回 `No symbol table is loaded.`」 | 實跑 `pwn1/challenge`（stripped）→ 逐字輸出 **`No symbol table is loaded.  Use the "file" command.`** | ✅ 逐字命中 |
| 5 | `b *0x555555554000+0x1a7d` | PIE 檔先看 base 再加 offset | `Breakpoint 1 at 0x555555555a7d` | ✅ |
| 6 | `run < input.txt` | 餵輸入檔 | **沒有任何題目目錄有 `input.txt`** → 新手照抄會得到 `No such file or directory` | ⚠️ 佔位符，未標明 |
| 7 | `c` / `si` / `ni` | — | 皆為合法 gdb 指令 | ✅ |
| 8 | `x/10gx $rsp` | — | 實際印出 10 個 8-byte | ✅ |
| 9 | `x/20i $rip` | — | 實際印出 20 行指令 | ✅ |
| 10 | `info registers` | — | 正常 | ✅ |
| 11 | `p/x $rdi` | — | 正常 | ✅ |
| 12 | `vmmap` | 標了 `(pwndbg)` | 原生 gdb → `Undefined command: "vmmap".` —— **與文件警告一致**（本機未裝 pwndbg） | ✅ 已預警 |
| 13 | `telescope $rsp 20` | 標了 `(pwndbg)` | `Undefined command: "telescope".` —— 同上 | ✅ 已預警 |
| 14 | `heap` / `bins` / `vis_heap_chunks` | 標了 `(pwndbg)` | 原生 gdb 全部 undefined —— 同上 | ✅ 已預警 |
| 15 | `python3 -c "from pwn import *; p=process('./chal'); print(p.pid); input()"` | 用來拿 pid 再 `gdb -p <pid>` | 在**終端機**可行；若 stdin 是 `/dev/null` → `EOFError: EOF when reading a line`（互動用途本來就需要 TTY，合理） | ✅（附條件） |
| 16 | `gdb -p <pid>` | — | 合法 gdb 用法 | ✅ |
| 17 | `p = gdb.debug('./chal', gdbscript='b *0x401234\nc')` | 「或用 pwntools」 | 本機實跑 → `PwnlibException: Could not parse PID from tmux output (b''). Start tmux first.` —— **pwntools 預設要找 tmux／終端機；本機沒裝 tmux** | ⚠️ 文件未提要先設 `context.terminal` 或裝 tmux |

**§13 判定：15 條可直接驗證的 gdb 指令全部行為與文件描述相符，其中第 4 條的錯誤訊息逐字命中；
2 條需要外部依賴（`input()` 需 TTY、`gdb.debug` 需 tmux／`context.terminal`）文件未加註。**

### 2.4 `wp/00_基礎知識_從零開始.md` §14（找 gadget）

| # | 指令 | 實測結果 | 判定 |
|---|---|---|---|
| 1 | `ROPgadget --binary ./chal \| grep "pop rdi"` | 可執行（在 `pwn5/homemaker` 上實跑有輸出） | ✅ |
| 2 | `ROPgadget --binary ./pwn5/homemaker \| grep -E ": pop rdi ; ret$"` | 實際輸出 **`0x00000000000012aa : pop rdi ; ret`** —— 與文件宣稱的 `0x00000000000012aa : pop rdi ; ret` **逐字相同** | ✅ |
| 3 | `ROPgadget --binary ./chal \| grep "syscall"` | `pwn5/homemaker` 無 syscall gadget → 空輸出（正常） | ✅ |
| 4 | `ROPgadget --binary ./chal --string "/bin/sh"` | 正常執行（印 `Strings information` 區塊） | ✅ |
| 5 | `ROPgadget --binary ./chal --opcode 0f05` | 正常執行（印 `Opcodes information` 區塊） | ✅ |
| 6 | `sudo pacman -S ropper`（註解說 extra/ropper 1.13.13） | 實查 `ropper 1.13.13-2` (extra) —— 敘述正確 | ✅ |
| 7 | `pipx install ropper` | **`pipx` 本機未安裝 → 指令直接失敗**；且文件說「見第 2 節的 PEP 668」，但第 2 節只在選項 B 提到要 `pacman -S python-pipx`，第 14 節沒重述 | ❌ **照抄會失敗** |
| 8 | `rop = ROP(ELF('./chal')); rop.find_gadget(['pop rdi','ret'])` | 可執行；回傳 `Gadget(0x12aa, ['pop rdi', 'ret'], ['rdi'], 0x10)` —— **是 `Gadget` namedtuple，不是 int**（要 `.address` 才能丟進 `p64()`；`int(g)` 會 `TypeError`） | ✅ 可跑，但文件未說明回傳型別 |
| 9 | `rop.find_gadget(['syscall','ret'])` | 可執行；`pwn2/mad_libs` 找不到時回 `None`（不是拋錯） | ✅ |
| 10 | `one_gadget ./libc.so.6` | **`bash: one_gadget: command not found`** —— gem 已安裝（1.10.0）但 executable 落在 `~/.local/share/gem/ruby/3.4.0/bin/`，**該目錄不在 `$PATH`**。用完整路徑即可正常運作（實測 `~/.local/share/gem/ruby/3.4.0/bin/one_gadget ./pwn2/libc.so.6` → 正常列出 `0x583dc posix_spawn(...)`） | ❌ **照抄會失敗** |
| 11 | `pip install ropper` 在 Python 3.14 編不起來（警告） | 本機 Python 恰好是 **3.14.6**，與警告情境相符；未實際嘗試安裝 | ✅ 警告合理 |

### 2.5 其他文件提及、但未安裝／無法驗證的工具

| 工具 | 文件出處 | 實測 | 判定 |
|---|---|---|---|
| `seccomp-tools dump` | `99_速查表.md` §12 最後一列、`pwn7/notes.md` | **未安裝**（`gem list seccomp-tools` 空） | ⚠️ 文件已說明是 Ruby gem 且需先裝 ruby；本機無法驗證 |
| pwndbg（`vmmap`/`telescope`/`heap`） | `99_速查表.md` §10、00 §13 | **未安裝**，原生 gdb 回 `Undefined command` | ✅ 文件已在三處明確預警「原生 gdb 沒有」 |
| tmux | 未被文件提及 | **未安裝**，導致 `gdb.debug()` 失敗 | ⚠️ 文件缺註 |

---

## 3. 文件參照與結構問題

### 3.1 Dangling reference 清單

掃描範圍：`wp/*.md` 與 `pwn*/notes.md` 內所有反引號包住的類路徑字串（117 個相異 token），
逐一以「相對於專案根目錄」與「相對於引用檔案所在目錄」兩種基底檢查存在性。

**A. 主文件（`wp/README.md`、`wp/00_recon.md`、`wp/00_基礎知識_從零開始.md`、`wp/99_速查表.md`、
`pwn1..pwn7/notes.md`）— 相異 token 65 個**

| # | 參照 | 出現位置 | 判定 |
|---|---|---|---|
| 1 | `` `pwn2/selfcheck.py` `` | `pwn2/notes.md:655,702` | ❌ **真 dangling**：文中說「把下面存成 `pwn2/selfcheck.py` 執行」並附上完整程式碼與實測輸出，但**該檔案不存在**。雖然讀者可以自己複製貼上（不至於卡死），但「`pwn2/selfcheck.py`」以檔案形式被引用卻找不到實體 |
| 2 | `` `wp/00` `` | `pwn2/notes.md:145,780,982`、`pwn3/notes.md:999`、`wp/99_速查表.md:316` | ⚠️ **不是路徑**：實際檔名是 `wp/00_基礎知識_從零開始.md`。5 處都以縮寫 `wp/00` 引用，`ls wp/00` 會失敗 |
| 3 | `` `ld.so` `` | `pwn3/notes.md:46`、`pwn5/notes.md:84,262` | ⚠️ 通用術語（動態連結器），非檔案路徑 —— 語意上可接受，但對完全新手可能誤以為是專案內檔案 |
| 4 | `` `input.txt` `` | `wp/00_基礎知識_從零開始.md:1028`（`run < input.txt`） | ⚠️ 佔位符：7 個題目目錄都沒有 `input.txt`，文件未標明要自己準備 |
| 5 | `` `/tmp/t.gdb` `` | `pwn1/notes.md`（§3.3） | ✅ 讀者自行建立，文中已說明是「可複製的腳本」，不算 dangling |
| 6 | `` `make_input.py` `` | `pwn1/notes.md:265`（程式碼區塊註解） | ✅ 同上，是「存成這個名字」的指示 |
| 7 | `FLAG_REMOTE.txt` | `wp/README.md:78`、`00:1193` | ✅ 存在（`pwn7/FLAG_REMOTE.txt`），我的掃描器因相對路徑解析而誤報 |
| 8 | `dis.txt` / `disasm.txt` / `rev.asm` / `local_run.log` / `remote_run.log` / `remote_run.txt` / `gdb_evidence*.{sh,py,txt}` / `exploit_input.bin` / `scratch_leak.py` / `NOTES_SUMMARY.txt` / `libc-2.39-0ubuntu8.3.so.6` | 各題 notes | ✅ 全部存在 |

**主文件真正的 dangling reference 數：1（`pwn2/selfcheck.py`）**，
另加 3 個「非路徑／佔位符」的模糊引用（`wp/00`、`ld.so`、`input.txt`）。
**跨題相對引用（`../pwnN/notes.md`、`pwn2/libc.so.6`、`pwn5/exploit.py` 等）全部有效，0 個壞連結。**

**B. 審查／修正紀錄檔（`wp/review_round*.md`、`wp/fixes_round*.md`、`wp/pending_wp00_fixes_*.md`）**

這些是**過程文件**，內容本身就在討論「哪些檔名不存在」。逐項檢視後：

| 參照 | 出現位置 | 判定 |
|---|---|---|
| `review_round2.md` / `review_round3.md` | `wp/review_round2_rop_foundations.md:249-250,258,267,285`、`wp/fixes_round2_rop_foundations.md:30` | ✅ **非 dangling**：這幾處正是在**引述舊版 README 的錯誤**並指出「實測 MISSING」，屬於審查內容 |
| `./setup.sh` | `wp/review_round2_rop_foundations.md:812` | ✅ pwndbg 的 `setup.sh`（已驗證存在於 repo） |
| `README`、`selfcheck.py`、`wp/00`、`wp/00_基礎知識`、`wp/99`、`dis.txt` | 多處 | ⚠️ 縮寫或省略前綴，非完整路徑 |
| `/app/flag.txt` | `wp/review_round2_fmtstr.md` | ✅ 遠端容器路徑 |
| `/tmp/sec7.py` | `wp/fixes_round2_stack.md` | ✅ 執行期暫存檔 |

**→ 審查／修正紀錄檔內没有真正的檔案壞連結。**

### 3.2 `wp/README.md` 檔案樹 vs 實際目錄

**（a）樹上有、實際不存在的「幽靈條目」：0 個 ✅**
（第 2 輪回報的 P0-5「列了 `review_round2.md`/`review_round3.md` 兩個不存在的檔案」**已確實修好**，
現在的樹改用 `review_round2_*.md` / `fixes_round2_*.md` glob，且這兩個 glob 都命中實體檔案。）

**（b）實際存在、但樹上沒列的檔案：24 個 ❌（樹不完整）**

| 目錄 | 漏列的檔案 |
|---|---|
| `wp/` | `pending_wp00_fixes_from_fmtstr.md`、`pending_wp00_fixes_from_heap.md`、`pending_wp00_fixes_from_rop.md` |
| `pwn1/` | `web_migurimental.tar.gz`（題目原始附件） |
| `pwn2/` | `NOTES_SUMMARY.txt` |
| `pwn3/` | `NOTES_SUMMARY.txt`、`local_run.log`、`remote_run.log`、`rev.asm` |
| `pwn4/` | `NOTES_SUMMARY.txt`、`cm_dbg`、`dis.txt`、`work/`（整個子目錄，內含 14 個檔案） |
| `pwn5/` | `NOTES_SUMMARY.txt`、`disasm.txt`、`exploit_input.bin`、`gdb_evidence.py`、`gdb_evidence_raw.txt`、`remote_run.txt`、`scratch_leak.py` |
| `pwn6/` | `NOTES_SUMMARY.txt`、`cb.asm`、`cb_new.asm`、`proto.py` |
| `pwn7/` | `dis.txt`、`__pycache__/` |

* 樹上用 `pwnN/  a  b  c` 的單行並列寫法，卻只挑了一部分檔案 —— 新手照著樹找檔案時，
  `pwn3/local_run.log`（notes §10.2 明確引用）、`pwn5/gdb_evidence.py`、`pwn6/proto.py`、
  `pwn4/dis.txt` 這些**被 notes 引用到的檔案**都會找不到。
* 尤其是 **`pwn3/local_run.log` / `pwn3/remote_run.log`（notes §10 直接指路）** 與
  **`pwn5/gdb_evidence.py`（README 樹只列了 `.sh`，notes 兩個都引用）** 建議至少補進樹裡。
* 另外：本檔 `wp/review_round3_verification.md` 產出後，樹又會少列一個檔案 —— 樹的
  「`review_round2_*.md`／`fixes_round2_*.md`」glob 寫法建議擴充成 `review_round*.md`。

**（c）樹的層級正確** ✅：樹根為 `sunshine/`，`wp/` 為子目錄並包含所有教學／審查文件，
`pwn1`~`pwn7` 為同層子目錄 —— 與實際目錄結構一致。

### 3.3 flag 表與 port 表一致性

**（a）`wp/README.md` 成果總表**

| 檢查項 | 結果 |
|---|---|
| port（26003/26001/26002/26004/26008/26005/26007） | ✅ 與 `run_all.sh` 的 `PORTS` 陣列、7 支 `exploit.py` 內寫死的 port **三方完全一致** |
| 檔案名稱（`pwnN/<binary>`） | ✅ 7/7 全部存在 |
| 保護機制 | ✅ 7/7 與 `checksec` 實測相符（見 §2.1） |
| Flag 欄位 | ⚠️ **6/7 正確；pwn2 大小寫錯字（`G0T` 應為 `g0T`）** |
| 「Flag 與 `pwnN/FLAG.txt` 逐字相同」的宣稱 | ❌ pwn2 例外（README 寫 `G0T`、FLAG.txt 寫 `g0T`） |
| 「每一題也都能用 `wp/run_all.sh pwnN` 重跑一次拿到同樣的結果」 | ✅ 實測 pwn6（單題）、pwn1+pwn4（多題）、全 7 題兩次，全過 |

**（b）`wp/00_recon.md` flag 表**

| 檢查項 | 結果 |
|---|---|
| port 表 | ✅ 7/7 與實測一致；「26006 沒有開」的註記與實測一致（26006 未使用） |
| 保護機制表 | ✅ 7/7 與 `checksec` 相符 |
| 「連上去看到什麼」對照表（26001 Mad Libs、26002 PRINT PRINT REVOLUTION、26003 8 bytes 二進位、26004 CACHE MONEY、26005 二進位、26007 SafeHouse、26008 MODEL 7） | ✅ 與本次 3 輪遠端輸出的實際 banner 全部相符 |
| flag 清單 | ⚠️ **6/7 正確；pwn2 同一個 `G0T` 大小寫錯字** |
| `ld-linux-x86-64.so.2 --library-path .` 的說明（pwn2/pwn6） | ✅ 實測正確：直接跑系統 ld 會出 `undefined symbol: __nptl_change_stack_perm, version GLIBC_PRIVATE`，必須用 bundled loader |
| `7 題的 exploit 都不需要 TTY，< /dev/null 也能跑完並印出 flag` | ✅ 7/7 實測成立 |

**（c）`wp/00_基礎知識_從零開始.md` 附錄「7 題對照表」（第 1167-1177 行）**

| 檢查項 | 結果 |
|---|---|
| 檔案欄（`pwn1/challenge` … `pwn7/service`） | ✅ 7/7 存在 |
| 遠端 port 欄（26003/26001/26002/26004/26008/26005/26007） | ✅ 7/7 與 `run_all.sh`、各 exploit、README、recon 一致 |
| 「對應筆記」欄（`../pwn1/notes.md` … `../pwn7/notes.md`） | ✅ 7/7 連結有效（相對 `wp/` 解析） |
| 核心技巧欄 | ✅ 與各題 notes 的手法一致（SROP / fmtstr→printf@got / va_list 任意讀寫→strcspn@got / heap tcache→strtol@got / off-by-one→ROP / heap→.bss 函式指標 / seccomp+stack pivot+負索引） |
| flag 欄 | ➖ 附錄**沒有** flag 欄，故此表不受 pwn2 錯字影響 |

**→ 附錄對照表 100% 準確（檔案、port、連結、技巧四欄全對），無 flag 可錯。**

### 3.4 其他文件一致性檢查

| 檢查項 | 結果 |
|---|---|
| README「閱讀順序」9 個連結 | ✅ 全部有效 |
| README「兩種 flag 檔不要搞混」說明 | ✅ 與實際狀態相符 |
| README「每一支 exploit.py 都支援兩種模式，而且不需要 TTY」 | ✅ 實測成立 |
| `00` §附錄「flag 檔命名規則」舉例（`sun{LOCAL_DUMMY_FLAG}` / `SUNSHINE{local_test_flag}`） | ✅ 兩個例子都在實際 `flag.txt` 中出現 |
| `pwn3/notes.md` §10.1「本機 flag 印兩次、結尾多一行 `score> `」 | ✅ 實測逐字相符 |
| `pwn2/notes.md` §9-14「本機看不到 `sh: -c:` 訊息」 | ✅ 實測相符 |
| `99_速查表.md` §11「在題目目錄裡跑 / 用 `wp/run_all.sh pwnN`」 | ✅ 兩者都實測成功 |

---

## 4. 速查表模板實測

實測環境：pwntools **4.15.0**、Python 3.14.6。以下每一項都真的執行了。

### 4.1 §5 ROP 模板（`99_速查表.md:75-111`）

| 項目 | 實測結果 | 判定 |
|---|---|---|
| §5.1 `p64(RET)` + `POP_RDI` + `binsh` + `SYSTEM` 的排版 | 語法正確；`RET`/`POP_RDI`/`binsh`/`SYSTEM` 是佔位符（`00` §10.2 開頭已明確標示「都是佔位符，要用自己題目的 binary 找真位址」） | ✅ |
| §5.1 對齊說明（「`ret` 放 `POP_RDI` 前或 `SYSTEM` 前都可以，重點是總共多走 8 bytes」） | 與 `00` §10.4 一致，敘述合理 | ✅ |
| §5.2 `execve("/bin/sh",0,0)` 純 syscall 鏈（`POP_RDI/RSI/RDX/RAX` + `SYSCALL_RET`） | 語法正確；`pwn3/notes.md` 與 `pwn1` 的實作可佐證 gadget 名稱慣例 | ✅ |
| §5.3 `read` 到 `.bss` + `POP_RSP` pivot | 語法正確；`pwn7` 實作即為此型 | ✅ |
| §4 表格 `mov rdx, rax ; jmp write@plt` 作為「沒有 `pop rdx` 的替代方案」 | 這是 `pwn7` 真實用到的技巧，非 API 呼叫，無法「執行」；描述與 `pwn7/notes.md` §6 相符 | ✅ |

### 4.2 §6 SROP 模板（`99_速查表.md:115-146`）

| 項目 | 文件聲稱 | 實測結果 | 判定 |
|---|---|---|---|
| `SigreturnFrame()` 產生 **0xf8 bytes** | 「產生 0xf8 bytes」 | `len(bytes(frame)) == 0xf8` → **完全相同** | ✅ |
| `frame.rax` / `.rdi` / `.rsi` / `.rdx` / `.rip` / `.rsp` 六個屬性 | 模板全部用到 | 6 個屬性**全部可設定**，無 AttributeError | ✅ |
| 未設 `context.arch` 的錯誤訊息 | 「pwntools 會直接報 `[ERROR] kernel architecture must be specified`」 | 實跑 → 終端印 **`[ERROR] kernel architecture must be specified`**，並拋 `PwnlibException`；原因確認：pwntools 預設 `context.arch == 'i386'` 且 `context.kernel is None`（原始碼 `pwnlib/rop/srop.py:364-365`） | ✅ **逐字命中** |
| `frame.rip = SYSCALL_RET`、`frame.rsp = binsh + 0x200`（合法可寫、建議 16-byte 對齊） | — | 屬性存在且可設；敘述與 `pwn1/exploit.py` 一致 | ✅ |
| 「送出剛好 15 bytes 讓 rax = 15 = `__NR_rt_sigreturn`」 | 15 | 系統呼叫表 `rt_sigreturn = 15`（速查表 §3 亦列 15）→ 自洽 | ✅ |
| `frame` 必須剛好落在當時的 `rsp` | — | 與 `pwn1/exploit.py` 的 `p64(SYSCALL_RET) + bytes(frame)` 排版一致 | ✅ |

**§6 SROP 模板：完全可用，無任何一項與 4.15.0 不符。**

### 4.3 §7 Format String 模板（`99_速查表.md:150-197`）

| 項目 | 文件聲稱 | 實測結果 | 判定 |
|---|---|---|---|
| `context.arch` 未設時是 32-bit | 「pwntools 預設是 32-bit（`context.bytes = 4`）」 | 實測 `context.arch == 'i386'`、`context.bytes == 4` → **正確** | ✅ |
| `for i in range(1,30): p.sendline(('%{}$p'.format(i)).encode())` | 找 offset 用 | 語法正確、可執行 | ✅ |
| `payload = fmtstr_payload(offset, {target_addr: value}, write_size='short')` | — | 可執行（實測 6 個參數位置、`0x404028: 0xdeadbeef` → 正確產生 payload） | ✅ |
| `write_size_max` 參數存在 | 「`write_size_max='byte'`」 | `inspect.signature(fmtstr_payload)` 含 **`write_size_max`（預設 `'long'`）** → **接受** | ✅ |
| `badbytes=b'\n'` | 「`fgets()` 收輸入時必加」 | 參數存在，可接受 `bytes`；預設 `frozenset()` | ✅ |
| `numbwritten=N` | — | 參數存在（預設 `0`） | ✅ |
| 額外發現 | — | 簽章完整為 `offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy='small', badbytes=frozenset(), offset_bytes=0, no_dollars=False` | — |
| **⚠️ `write_size='byte'`「每個 byte 一次 `%hhn`」** | 第 172 列：「`write_size='byte'` \| 預設值：每個 byte 一次 `%hhn`，payload 較長但最穩」 | 實測**不是這樣**：`write_size='byte'` 的**預設值確實是 `'byte'`**，但因 `write_size_max` 預設 `'long'`，pwntools 會把相鄰 byte **合併**成 `%hn`/`%lln`：<br>`{'write_size':'byte'}` → len=80，規格 = `['hhn','lln']`（混用！）<br>`{'write_size':'byte','write_size_max':'byte'}` → len=144，規格 = `['hhn']`（純 `%hhn`）<br>`{'write_size':'short'}` → len=48，規格 = `['hn','lln']`<br>`{'write_size':'long'}` → len=32，規格 = `['lln']` | ❌ **第 172 列的敘述不準確**（要保證純 `%hhn` 必須**同時**指定 `write_size_max='byte'`，也就是同表第 174 列那個參數） |
| 排版順序警告（位址不能放最前面、要「格式字串 → 補齊 8 的倍數 → 位址」） | — | 與實測產出的 payload 結構一致（`b'%16$hhn%17$hhn...aaaabaa' + 位址`） | ✅ |
| 「`offset=N-1` 或 `N+1` 都會直接 SIGSEGV（實測）」 | — | 是作者自製測試程式的實測結論，本次無法獨立重現（無該測試程式），**列為未複驗** | ⚠️ 未複驗 |

> ⚠️ **重要**：`pwn2/notes.md` 的 E3 修正（`fixes_round2_fmtstr.md` E3）**已經把這個錯誤改掉了**，
> 但**同樣的錯誤敘述還留在 `wp/99_速查表.md` 第 172 列**。建議同步修正（把第 172 列改成
> 「`write_size='byte'` 是預設值，但真正的『絕不合併』開關是 `write_size_max='byte'`」）。

### 4.4 §9 pwntools 常用一行（`99_速查表.md:246-261`）逐條實跑

| 一行指令 | 實測結果 | 判定 |
|---|---|---|
| `p = process('./chal')` | ✅ 成功（`process('./pwn1/challenge')` → pid 取得） | ✅ |
| `p = remote('h', 1234)` | ✅ 函式存在、簽章正確（未實際撥號） | ✅ |
| `p.sendafter` / `p.sendlineafter` / `p.recvuntil` / `p.recvn` / `p.recvrepeat` | ✅ 5 個方法全部存在；`recvrepeat(1)` 實跑回 `bytes` | ✅ |
| `p64(0x401234); u64(b'12345678')` | ✅ `b'4\x12@\x00\x00\x00\x00\x00'` / `4050765991979987505` | ✅ |
| `flat([0x1, 0x2, 0x3])` | ⚠️ 回傳 `b'\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'` —— **每個值只佔 4 bytes**，因為**預設 `context.arch == 'i386'`**。64-bit 題目照抄會得到 32-bit 打包結果 | ⚠️ **新手陷阱**：§9 沒提醒要先 `context.arch = 'amd64'`（其他章節有提醒，但這行沒有） |
| `cyclic(100); cyclic_find(0x6161616b)` | ✅ `b'aaaabaaacaaadaaa'` / `40` | ✅ |
| `ELF('./chal').symbols['main']` | ⚠️ 本系列 7 支有 6 支是 stripped → `e.symbols['main']` 會 **KeyError**（`pwn5`/`pwn2` 實測 `symbols.get('main')` 皆為 `None`） | ⚠️ 未提醒 stripped 的情況（§12 有提到 stripped，但 §9 這行沒有） |
| `ELF('./chal').got['printf']` | ✅ 可執行（`pwn2/mad_libs` → `0x4010`；對 static binary 則 `KeyError`） | ✅ |
| `ROP(ELF('./chal')).find_gadget(['pop rdi','ret'])` | ⚠️ 可執行；回傳 **`Gadget(0x12aa, ['pop rdi','ret'], ['rdi'], 0x10)`**（namedtuple），**不是 int**；`pwn1` 上找不到時回 `None`。要塞進 `p64()` 必須寫 `.address` | ⚠️ **未說明回傳型別** |
| `next(ELF('./libc.so.6').search(b'/bin/sh'))` | ✅ `pwn2/libc.so.6` → `0x1cb42f` | ✅ |
| `log.success('FLAG: %s' % flag)` | ✅ 正常輸出 | ✅ |

### 4.5 §8 / §10 / §12 的技術性敘述抽查

| 項目 | 文件聲稱 | 實測 / 判定 |
|---|---|---|
| §8 chunk 結構 `+0x00 prev_size`、`+0x08 size`、**`+0x10 user data`（malloc 回傳值）** | — | ✅ 正確（第 1 輪 E6 已修正，本輪複查正確） |
| §8 `malloc(0x18)` 實際拿到 `0x20` chunk | — | ✅ 正確（16-byte 對齊） |
| §8 safe-linking `fd = 目標 ^ (chunk_addr >> 12)`，`chunk_addr` = malloc 回傳的 user 位址 | — | ✅ 正確；`pwn4/exploit.py` 實測 safe-linking key = `0x14cea`（純高位）可作證 |
| §8 `__free_hook`/`__malloc_hook` 在 glibc ≥ 2.34 已不再被呼叫 | — | ✅ 正確；本系列 glibc 2.39（`pwn2/libc.so.6` 實測 = 2.39） |
| §10 `vmmap`/`telescope`/`heap`/`bins`/`vis_heap_chunks` 是 pwndbg 指令 | — | ✅ 實測原生 gdb 回 `Undefined command` |
| §10 `b *0x401234` 只對 non-PIE 有效 | — | ✅ 正確 |
| §12 `error: externally-managed-environment` → PEP 668 | — | ✅ 常見正確；本機 Arch 無此錯誤，未實測 |
| §12 `[ERROR] kernel architecture must be specified` | — | ✅ **逐字實測命中**（見 §4.2） |
| §12 `No symbol table is loaded` → stripped binary 用符號下中斷點 | — | ✅ **逐字實測命中**（見 §2.3 #4） |
| §12 `seccomp-tools dump` | — | ⚠️ 本機未安裝該 gem，無法實測 |

---

## 5. 結論

### 5.1 逐項判定

| 驗證項目 | 判定 | 依據 |
|---|---|---|
| **7 題遠端穩定重現** | ✅ **PASS** | 每題各跑 3 次獨立遠端連線（`run_all.sh` ×2 + 逐題 ×1），**21/21 全數成功**，無失敗、無重試、無 timeout |
| **7 題 local 模式可跑** | ✅ **PASS** | 7/7 在 `</dev/null`（無 TTY）下 exit 0 並印出 local 假 flag |
| **7 題 `FLAG.txt` 正確** | ✅ **PASS** | 7/7 與實測遠端 flag 逐字相同（pwn2 的檔案本身是對的，見下） |
| **7 題 `flag.txt` 是明顯假 flag** | ✅ **PASS** | 7/7 含 `LOCAL_DUMMY`/`LOCAL_TEST`/`local_test` 字樣，無一誤放真 flag |
| **README / run_all.sh 文件化的指令可執行** | ⚠️ **大部分 PASS** | 11 條中 10 條照抄可跑；`./run_all.sh`（從根目錄）1 條會失敗 |
| **`00` §2 / §13 / §14 指令可執行** | ⚠️ **大部分 PASS** | §2 可驗證的 14 條全過；§13 可驗證的 15 條全過（2 條需 TTY/tmux）；§14 **10 條中 2 條照抄會失敗**（`pipx install ropper`、`one_gadget`） |
| **文件內部參照無壞連結** | ⚠️ **幾乎 PASS** | 主文件 dangling 1 個（`pwn2/selfcheck.py`）+ 3 個模糊縮寫；審查/修正紀錄檔 0 個 |
| **README 檔案樹 = 實際** | ❌ **FAIL** | 幽靈條目 0 個 ✅，但**漏列 24 個實際存在的檔案**（含 notes 會引用到的 `pwn3/local_run.log`、`pwn4/dis.txt`、`pwn5/gdb_evidence.py`、`pwn6/proto.py`） |
| **README / 00_recon flag 表正確** | ❌ **FAIL（1 個 byte）** | **pwn2 寫成大寫 `G0T`，真實 flag 是小寫 `g0T`**；其餘 6 題與全部 port 均正確 |
| **00 附錄「7 題對照表」正確** | ✅ **PASS** | 檔案、port、筆記連結、核心技巧四欄 100% 準確（該表無 flag 欄） |
| **速查表 ROP / SROP 模板可貼上執行** | ✅ **PASS** | SROP 模板 7 項全部實測相符（含 `0xf8` 長度與錯誤訊息逐字命中） |
| **速查表 format-string 模板可貼上執行** | ⚠️ **可用但有一列錯述** | API 全部可用（`write_size_max`/`badbytes`/`numbwritten` 都存在）；但第 172 列「`write_size='byte'` → 每個 byte 一次 `%hhn`」與 4.15.0 行為不符 |
| **速查表 §9 一行指令** | ⚠️ **可用但 3 個陷阱未註明** | `flat()` 預設 32-bit、`symbols['main']` 對 stripped 會 KeyError、`find_gadget()` 回傳 `Gadget` 而非 int |

### 5.2 最終回答：可否宣稱「全部 7 題都能穩定重現、文件可執行」？

* **「全部 7 題都能穩定重現」→ ✅ 可以宣稱，而且是強證據**：
  21 次獨立遠端執行（7 題 × 3 次）全部拿到真實 flag，21/21 無一例外；local 模式 7/7 通過。

* **「文件可執行」→ ⚠️ 只能**有條件**地宣稱**，因為實測到下列 6 個具體缺陷
  （全部照抄文件就會踩到，或與實測不符）：

  1. ❌ **`wp/README.md:15` 與 `wp/00_recon.md:19` 的 pwn2 flag 有 1 個 byte 大小寫錯誤**
     （寫 `G0T`，真實是 `g0T`）。這同時讓 README 第 25 行「Flag 與 `pwnN/FLAG.txt` 逐字相同」的宣稱失效。
  2. ❌ **`00` §14 的 `one_gadget ./libc.so.6` 照抄會 `command not found`**
     （gem 已裝但 executable 不在 `$PATH`）。需補「或用 `gem environment` 找 executable directory」。
  3. ❌ **`00` §14 的 `pipx install ropper` 照抄會失敗**（本機無 `pipx`，且該節沒重述要先裝）。
  4. ❌ **README §「▶️ 一鍵驗證」的 `./run_all.sh` 沒有先 `cd wp`**，
     從專案根目錄執行會 `No such file or directory`。
  5. ❌ **`wp/README.md` 的檔案樹漏列 24 個實際檔案**（含 notes 直接指路的 log/腳本），
     新手照著樹找檔案會找不到。
  6. ⚠️ **`99_速查表.md:172` 的 `write_size='byte'` 敘述與 pwntools 4.15.0 實測行為不符**
     （會被合併成 `%hn`/`%lln`），需同步套用 `pwn2/notes.md` 已做過的 E3 修正。
     另加 §9 三個未註明的陷阱（`flat()` 32-bit、stripped 的 `symbols['main']`、`find_gadget()` 回傳型別）。

* **建議措辭**：
  > 「7 題 exploit 已通過 21 次獨立遠端執行，可穩定重現；
  > 教學文件的指令與模板**絕大多數可照抄執行**，但 README/recon 的 pwn2 flag 有 1 個 byte 大小寫錯字、
  > README 檔案樹不完整、`./run_all.sh` 缺 `cd wp`、§14 的 `one_gadget`/`pipx` 兩條指令在本機環境會失敗、
  > 速查表 §7 有一列敘述與 pwntools 4.15.0 行為不符 —— 這 6 項修掉之後才能無條件宣稱「文件可執行」。」

### 5.3 未能在本環境驗證的項目（不列為 PASS 也不列為 FAIL）

1. Ubuntu / Debian 的 `apt` 相關指令（本機為 Arch，無 apt）。
2. `sudo pacman -S ...` 的**實際安裝**（未動系統；只以 `pacman -Si` 驗證套件存在與版本）。
3. venv 建立與 `pip install`（`$HOME` 在審查沙箱內唯讀）。
4. `gem install seccomp-tools`（gem 遠端索引快取目錄唯讀 → `Errno::EROFS`）。
5. pwndbg 的 `./setup.sh` 實際安裝（只驗證 repo 與 `setup.sh` 存在）。
6. 速查表 §7「`offset=N-1`/`N+1` → SIGSEGV」的實測（缺作者當時的自製測試程式）。
7. pwn7 的 seccomp 規則內容（只以 `readelf -s` 確認 `prctl` 匯入，無 `seccomp-tools` 可 dump）。

---

## 附錄：本次驗證執行過的指令（節錄）

```bash
# 重現
cd /home/kzzz/Documents/code/ctf/sunshine && ./wp/run_all.sh                 # 第 1 次：7/7 拿到 flag
cd /home/kzzz/Documents/code/ctf/sunshine && ./wp/run_all.sh                 # 第 2 次：7/7 拿到 flag
for n in 1 2 3 4 5 6 7; do (cd pwn$n && timeout 180 python3 exploit.py < /dev/null); done   # local 7/7
for n in 1..7; do (cd pwn$n && python3 exploit.py REMOTE PORT=$p) | grep -oaE 'sun\{[^}]*\}'; done  # 逐 byte
cd wp && ./run_all.sh pwn1 pwn4          # 指定題目：2/2 OK
./wp/run_all.sh pwn6                     # 單題：OK
./run_all.sh                             # 從根目錄：FAIL（README 未寫 cd wp）

# flag 逐 byte 比對
grep -oaE 'sun\{[^}]*\}' wp/README.md | sort -u | xxd
xxd pwn2/FLAG.txt

# 檢查工具
checksec --file=./pwn1/challenge
for n in 1..7; do checksec --file=./pwnN/<binary>; done
python3 -c "from pwn import *; print(ELF('./pwnN/<b>',checksec=False).checksec())"
pacman -Si python-pwntools ropgadget ropper gdb patchelf ruby python-pipx
gem list seccomp-tools ; gem list one_gadget ; gem environment
python3 -c "from pwn import *; print('pwntools ok')"
python3 -m pip install --help | grep break-system-packages
git ls-remote --heads https://github.com/pwndbg/pwndbg
curl -sI https://raw.githubusercontent.com/pwndbg/pwndbg/dev/setup.sh

# gdb
gdb -q -batch -ex 'b *main+42' ./pwn1/challenge        # → No symbol table is loaded.  ✅ 逐字命中
gdb -q -batch -ex 'b *0x401234' -ex 'info break' ./pwn1/challenge
gdb -q -batch -ex 'b *0x555555554000+0x1a7d' -ex 'info break' ./pwn1/challenge
gdb -q -batch -ex 'vmmap' ./pwn1/challenge             # → Undefined command ✅（文件已預警）
gdb -q -batch -ex 'telescope $rsp 20' ./pwn1/challenge # → Undefined command ✅

# ROPgadget（§14）
ROPgadget --binary ./pwn5/homemaker | grep -E ": pop rdi ; ret$"   # 0x12aa ✅ 逐字命中
ROPgadget --binary ./pwn5/homemaker --string "/bin/sh"
ROPgadget --binary ./pwn5/homemaker --opcode 0f05
one_gadget ./pwn2/libc.so.6     # FAIL: command not found
~/.local/share/gem/ruby/3.4.0/bin/one_gadget ./pwn2/libc.so.6       # OK

# 模板實測（pwntools 4.15.0）
python3 -c "SigreturnFrame()"                      # [ERROR] kernel architecture must be specified ✅
len(bytes(SigreturnFrame()))                       # 0xf8 ✅
fmtstr_payload(6, {0x404028:0xdeadbeef}, write_size='byte')                      # hhn+lln 混用 ⚠️
fmtstr_payload(6, {0x404028:0xdeadbeef}, write_size='byte', write_size_max='byte')  # 純 hhn ✅
ROP(ELF('./pwn5/homemaker')).find_gadget(['pop rdi','ret'])   # Gadget namedtuple ⚠️
flat([1,2,3])                                      # 4-byte 打包（預設 arch=i386）⚠️
```
