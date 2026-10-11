# round 2 修正紀錄 — `wp/00_基礎知識_從零開始.md`

> **本輪唯一被改動的檔案**：`wp/00_基礎知識_從零開始.md`（895 → 1197 行）。
> 其他檔案（三份 pending、兩份 review、`wp/99`、`wp/README.md`、所有 `pwnN/`）**完全沒有動**。
> 來源：`wp/pending_wp00_fixes_from_rop.md`（含附錄 A = heap 原文、附錄 B = fmtstr 原文、附錄 C = 衝突調解）、
> `wp/pending_wp00_fixes_from_fmtstr.md`、`wp/pending_wp00_fixes_from_heap.md`、
> `wp/review_round2_rop_foundations.md`。
> 驗證環境：Arch Linux、Python 3.14.6、glibc 2.44、pwntools 4.15.0、gcc 16.1.1、gdb 16.x。

## 0. 統計（**去重後**，同一處被多份 pending 檔提到只算一條）

| 狀態 | 條數 |
|---|---|
| **已修**（原本寫錯 → 改掉） | 11 |
| **已補**（原本缺失 → 新增） | 11 |
| **略過**（不需要改／不在本檔／無法驗證 → 附原因） | 6 |
| **推翻的宣稱**（pending 檔本身寫錯，未照抄） | 1（canary offset 的範例值，見 §4.1） |

「已修／已補」對應的驗證指令與實際輸出列在 §4；略過的 6 條是
附錄 A 的 `C`、`D`、附錄 B 的 `P5`、pending ROP 的 `§18`、`§11` 的 ropper CLI、
以及交付說明裡的 `vulnerability-leak`（見 §5）。

---

## 1. `pending_wp00_fixes_from_rop.md`（§1–§18）

| # | 位置（新行號） | 狀態 | 一行說明 |
|---|---|---|---|
| §1 | `426–487`（§6.3） | **已修＋已補** | 堆疊圖 `buf`/`canary` 上下顛倒 → 改成 `canary` 在 `rbp-0x8`（靠近 `rbp`）、`buf` 在 `rbp-0x40`；並補上「canary 的 offset 怎麼算」的規則與 **實測表**（`buf[0x30]` → canary `0x38`、返回位址 `0x48`）。⚠️ pending 給的範例值 `0x28`/`0x38` 是**錯的**（見 §4.1） |
| §2 | `93–153`（§2） | **已修** | `pip install pwntools` / `pip install ropgadget` 在 Arch 上必失敗（PEP 668）→ 改成 `sudo pacman -S python-pwntools gdb`、`sudo pacman -S ropgadget`，並加上 A（發行版套件）／B（venv、pipx）／C（`--break-system-packages`）三選項的警告區塊；Ubuntu 段落改成 `apt install python3-pwntools`（24.04+）＋ 22.04 的替代方案 |
| §3 | `979–984`（§12） | **已修** | `DEBUG=1 python3 exploit.py` 無效 → 改成 `python3 exploit.py DEBUG`，並註明 `pwnlib.args` 會把裸字從 `sys.argv` 吃掉 |
| §4 | `250–316`（新 §4.3.1） | **已補** | 新增一整節「libc base + offset」：PIE vs libc 對照表、`readelf -s … grep ' system@@'`、`libc.address = leaked_printf - libc.symbols['printf']`、手算範例，以及「libc 版本必須一致」的實測表 |
| §5 | `581–590`（§9） | **已修** | pwn6 從「Missing bounds check」與「Uninitialised memory」兩列移除；新增 `Reference count bug` 列；`Missing bounds check` 列註明本系列沒有直接例子 |
| §6 | `1175`（附錄） | **已修** | pwn6 的核心技巧由「PIE + canary → ROP」改成「Heap（refcount → double free + UAF → tcache poisoning）→ 覆寫 `.bss` 函式指標 → `system()`（不需要 ROP）」 |
| §7 | `583`（§9） | **已修** | `Stack Buffer Overflow` 列補上 pwn5（`state` 陣列在堆疊上） |
| §8 | `837–846`（§11.4） | **已補** | 補上 `rt_sigframe` / `ucontext` / `struct sigcontext` / `SigreturnFrame()` 的四名詞表，改成引用 `../pwn1/notes.md` §5.1、§5.3（原句在定義前就往前指） |
| §9 | `907–908`（§12） | **已修** | `e.address` 註解改為「磁碟上的 PIE 檔是 `0x0`；接上 process 後才有意義，真正 base 要靠 leak」 |
| §10 | `1024–1027`（§13） | **已修** | `b *main+42` 加註「只有未 strip 才能用；本系列大多是 stripped → `No symbol table is loaded.`」，並補 PIE 的 `b *base+offset` 寫法 |
| §11 | `711–714`、`1080–1091` | **已修＋略過** | `ret2csu` 補上定義；`ropper` 不裝也無妨 → 依 pending 的選項 ②「只留 ROPgadget 示範」，保留安裝說明但**刪掉未經實測的 `ropper -f …` 指令**（見 §4.6） |
| §12 | `206–210`（§4 開頭） | **已補** | §4 開頭加「📌 這節會用到 `rbp`/`rsp`/`fs:0x28`/`je`，不熟先看第 5、6 節」的提示 |
| §13 | `716–771`（新 §10.8） | **已補** | 新增「動手做一次：你人生第一條 ROP 鏈（pwn5）」，含實跑輸出、真實 gadget offset、`ret` 一格一格吃掉堆疊的步驟表 |
| §14 | `996–1010`（§12） | **已補** | 端序提醒後面補上可執行的寫法範例（`p16(0x500)` vs `p16(0x500,endian='big')`、`u16(...,endian='big')`）與「看組語判斷」的方法 |
| §15 | `1174`、`1178–1188`（附錄） | **已修** | 附錄 pwn5 技巧移除「命令注入」，改成 off-by-one → 洩漏堆疊 → ROP；另加一條「假線索」註記（ECHO 執行的是寫死的 `"/bin/echo -n ''"`） |
| §16 | `1172`、`588`、`1180–1184` | **已修** | pwn3 描述由「長度整數問題 → `.bss` 溢寫」改成「`va_list.overflow_arg_area` 指向輸入緩衝區 → `%N$s`/`%N$w` 任意讀寫 → `strcspn@got` 覆寫成 `system`」；並把 pwn3 從 `Missing bounds check` 列移除；附錄加「`.bss`/`memcpy` 是假線索」的說明 |
| §17 | `11–13`、`36–39`、`592–595` | **已補** | 檔頭、目錄、§9 都補上「heap 題請先讀 `wp/99` §8 + `pwn4/notes.md` §5 + `pwn6/notes.md` §3.5」的指路 |
| §18 | — | — | 純說明（附錄 A/B/C 的出處），無需動作 |

### 附錄 A（heap 原文）

| # | 位置 | 狀態 | 說明 |
|---|---|---|---|
| A1 | `1175` | **已修** | 同 §6（採附錄 C 的仲裁：用 A1 的資訊較多版本，但保留下表「核心技巧」欄的寫法） |
| A2 | `586` | **已修** | Heap Overflow / UAF 列補上 pwn6（refcount 算錯 → double free + UAF） |
| A3 | `590` | **已修** | `Uninitialised memory` 列改成「本系列沒有；pwn6 是候選但已被短讀檢查排除」（採 A3 的替換文字） |
| B1 | `11–13`、`36–39`、`592–595` | **已補** | heap 入門路徑（同 §17） |
| C | — | **略過** | `wp/00` 的 Partial RELRO 敘述與 `r8/r9` 是第 5、6 參數**本來就正確**，未改動（避免白改） |
| D | — | **略過** | S3/S4/S7 屬於 `wp/99_速查表.md` §8，不在本檔允許編輯範圍內 |

### 附錄 B（fmtstr 原文）

| # | 位置 | 狀態 | 說明 |
|---|---|---|---|
| P1 | `1172` | **已修** | pwn3 敘述改成 `va_list.overflow_arg_area` 版本（與 `pwn3/notes.md` §11-7 一致） |
| P2 | `588` | **已修** | pwn3 從 `Missing bounds check` 列移除（附錄 C 仲裁：連 pwn6 一起移，另開 `Reference count bug`） |
| P3 | `992–995` | **已補** | `cd` 警告後補「pwn2 / pwn3 已用絕對路徑，不受 cwd 影響」的例外行 |
| P4 | `86–87`、`922–946` | **已補** | 名詞表補 `va_list`、`IFUNC`；§12 補最小 `fmtstr_payload` 範例＋`write_size_max` 預設是 `'long'` 的 🔴 警告 |
| P5 | — | **略過** | 「一致性複查結果全部 OK」的清單，本輪未動那些段落 |

### 附錄 C（衝突調解）

| 衝突行 | 採用結果 |
|---|---|
| `440`（Missing bounds check） | 採兩份都對的合併版：pwn3 / pwn6 都移除，另開 `Reference count bug`（pwn6） |
| `886`（附錄 pwn6） | 採資訊較多的 A1 版本，並保留「`不需要 ROP`」字樣 |
| `439` / `442` | 直接採 A2 / A3 的替換文字 |
| `733–736`（cd 警告） | 追加例外行（pwn2 / pwn3） |

---

## 2. `pending_wp00_fixes_from_fmtstr.md`

與附錄 B 內容相同（`P1`–`P5`），逐條對照見上表，全部已處理。

---

## 3. `pending_wp00_fixes_from_heap.md`

與附錄 A 內容相同（`A1`–`A3`、`B1`、`C`、`D`），逐條對照見上表，全部已處理。

---

## 4. 我實際跑過的驗證指令與結果

### 4.1 §6.3 的 canary offset（**推翻了 pending 給的範例值**）

```console
$ for n in 0x10 0x20 0x30 0x40; do gcc -O0 -o /tmp/sz sz.c; objdump -d -M intel /tmp/sz | grep -E "sub +rsp|lea +rax,\[rbp"; done
buf[0x10]: sub rsp,0x20   mov QWORD PTR [rbp-0x8],rax   lea rax,[rbp-0x20]
buf[0x20]: sub rsp,0x30   mov QWORD PTR [rbp-0x8],rax   lea rax,[rbp-0x30]
buf[0x30]: sub rsp,0x40   mov QWORD PTR [rbp-0x8],rax   lea rax,[rbp-0x40]
buf[0x40]: sub rsp,0x50   mov QWORD PTR [rbp-0x8],rax   lea rax,[rbp-0x50]
```

* canary 永遠在 `rbp-0x8`（＝圖中「最靠近 `rbp`」）✅。
* **但** GCC 會把框架對齊 16 bytes，所以 `char buf[0x30]` 實際落在 `rbp-0x40`，
  canary 的 offset 是 **`0x38`**、返回位址是 **`0x48`** ——
  pending §1／review P0-2 寫的「以 `buf[0x30]` 為例 → canary `0x28`、返回位址 `0x38`」**是錯的**
  （那組數字對應的是 `buf[0x20]`）。文件採用實測值，並加了「不要用陣列大小 + 8 猜」的 🔴 警告。

### 4.2 §2 環境安裝（PEP 668）

```console
$ ls /usr/lib/python3.14/EXTERNALLY-MANAGED          → 檔案存在
$ python3 -m pip install --dry-run pwntools          → error: externally-managed-environment
$ pacman -Si python-pwntools                         → extra/python-pwntools 4.15.0-2
$ pacman -Ss ropgadget                               → extra/ropgadget 7.7-1
$ pacman -Ss ropper                                  → extra/ropper 1.13.13-2
$ pacman -Ss one_gadget                              → extra/one_gadget 1.10.0-4
$ pacman -Ss pipx                                    → extra/python-pipx 1.15.0-1
$ pacman -Ss seccomp-tools                           → 無輸出（確認 Arch 沒有這個套件 → 只能用 Ruby gem）
$ command -v gem ruby gdb checksec ROPgadget patchelf → 全部存在
$ python3 -m venv /tmp/v3 && /tmp/v3/bin/pip install --dry-run pwntools
  → Would install … pwntools-4.15.0 … ROPGadget-7.7 …（venv 這條路真的可行）✅
$ curl -s -o /dev/null -w "%{http_code}" https://packages.ubuntu.com/noble/python3-pwntools   → 200
$ curl -s -o /dev/null -w "%{http_code}" https://packages.ubuntu.com/jammy/python3-pwntools   → 404
  （Ubuntu 24.04 有 `python3-pwntools`；22.04 沒有 → 文件據此分成兩條路）
$ curl … https://packages.ubuntu.com/noble/ropgadget → 200；…/noble/python3-ropper → 200
```

### 4.3 §12 `DEBUG`（pwntools 讀 argv 不讀環境變數）

```console
$ DEBUG=1 python3 -c "from pwn import *; print('env  ->', context.log_level)"   → env  -> 20
$ python3 -c "import sys; sys.argv=['x.py','DEBUG']
              from pwn import *; print('argv ->', context.log_level)"           → argv -> 10
$ # 而且裸字會被吃掉：
  before pwn: ['x.py','REMOTE','DEBUG']   after pwn: ['x.py']   args.REMOTE=True  log=10
```

### 4.4 §4.3.1 libc base + offset

```console
$ readelf -s pwn2/libc.so.6 | grep ' system@@'   → 1050: 0000000000058740 … system@@GLIBC_2.2.5
$ readelf -s pwn2/libc.so.6 | grep ' printf@@'   → 2611: 00000000000600f0 … printf@@GLIBC_2.2.5
$ readelf -s /usr/lib/libc.so.6 | grep ' system@@'  → 1066: 0000000000054580 … system@@GLIBC_2.2.5
$ strings pwn2/libc.so.6 | grep -m1 'GNU C Library'
  → GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.3)   ；本機 ldd --version → 2.44
$ python3：libc.address = 0x7f12345600f0-0x600f0 → 0x7f1234500000（& 0xfff == 0 ✅）
           libc.symbols['system'] → 0x7f1234558740；next(libc.search(b'/bin/sh')) → 0x7f12346cb42f
```

### 4.5 pwn3 / pwn6 / cwd（附錄與 §9 的事實修正）

```console
$ readelf -sW pwn3/revolution | grep -c memcpy          → 0（確認「沒有匯入 memcpy」）
$ readelf -SW pwn3/revolution | grep '\.bss'            → .bss 0x404040 size 0x30（0x4060 不在 .bss）✅
$ printf '%6$p\n' > /tmp/rev_in
$ gdb -q -batch -ex 'file pwn3/revolution' -ex 'break *0x4013d9' -ex 'run < /tmp/rev_in' \
      -ex 'p/x $rsp+0x120' -ex 'info registers rdi'
  → $1 = 0x7fffffffdbe0 ／ rdi = 0x7fffffffdbe0   ⇒ overflow_arg_area == buf ✅
$ sed -n '17,28p' pwn6/notes.md
  → 「clone 的 refcount 算錯 ⇒ double free + UAF → tcache poisoning → 覆寫 [PIE+0x40c0]」
  → 「完全不需要 ROP chain」✅
$ readelf -sW pwn5/homemaker 的 ECHO 字串：objdump -d -M intel pwn5/homemaker | grep 'lea    rax,\[rip+0xec2\]'
  → 0x12ed → 0x21b6；pwn5 rodata@0x21b6 = b"/bin/echo -n ''\0" ⇒ 沒有注入點（命令注入是假線索）✅
$ cd / && python3 …/pwn2/exploit.py < /dev/null | tail -3   → FLAG: sun{LOCAL_DUMMY_FLAG} ✅
$ cd / && python3 …/pwn3/exploit.py < /dev/null | tail -3   → FLAG: sun{LOCAL_TEST_FLAG} ✅
  （⇒「一定要 cd 進題目目錄」對 pwn2/pwn3 不成立，已加例外行）
$ cd pwn5 && python3 exploit.py   （實跑，作為 §10.8 的輸出範例）
  → canary 0x4cef3d7131e99900 / saved rbp 0x7ffda2ccc360 / PIE base 0x564a62832000 / FLAG ✅
$ ROPgadget --binary pwn5/homemaker | grep -E ": pop rdi ; ret$"  → 0x…12aa : pop rdi ; ret ✅
$ gdb -q -batch -ex 'b *main+42' ./pwn1/challenge
  → No symbol table is loaded.  Use the "file" command.  （pwn1/pwn3/pwn5/pwn7 全部 stripped）✅
$ python3 -c "from pwn import *; print(hex(ELF('pwn5/homemaker',checksec=False).address))"  → 0x0 ✅
$ python3 -c "…SigreturnFrame()…" → len(frame)=248(0xf8)、r8 在 offset 0x28 ✅（§11.4 的表是對的）
```

### 4.6 ropper（**略過的指令**）

```console
$ command -v ropper        → 無輸出（本機未安裝）
$ python3 -m venv /tmp/rv && /tmp/rv/bin/pip install ropper
  → ERROR: Failed to build 'filebytes' when getting requirements to build wheel
```

`ropper` 在 Python 3.14 上**裝不起來**，所以它的 CLI 我無法實測 →
依 pending §11 的選項 ②，**刪掉 `ropper -f ./chal --search …` 兩行**，
只留下「可選的第二套工具」說明與安裝方式（`sudo pacman -S ropper` / `pipx install ropper`，
兩個套件都經 `pacman -Ss ropper`、`pacman -Ss pipx` 查證存在），
並註明 ROPgadget 才是本文件一貫使用的工具（本機 `ROPgadget` 存在且已實測）。

### 4.7 其他被確認「不需要改」的項目

| 項目 | 結論 |
|---|---|
| `cyclic_find(0x6161616b6161616a)` → `36`（§6.4 的範例） | 實測 `36`，範例自洽，保留 |
| `§4.4` Partial RELRO 敘述、`§6.1` `r8`/`r9` 是第 5、6 個參數 | 正確，未改（附錄 A 的 C 段） |
| `§5.2` `jg`/`ja`、`§3` 小端、`§8` GOT、`§11.4` `context.arch` 警告 | 正確，未改 |

---

## 5. 「vulnerability-leak」的處理

交付說明要求名詞表定義 `vulnerability-leak`，但三份 pending 檔都**沒有**這個字串
（`grep -rn "vulnerability.leak" wp/ pwn*/` → 0 筆），也沒有這個詞的定義來源。
因此本檔採最接近的讀法：**名詞表原有的 `leak（洩漏）` 保留**，並新增一條
**「漏洞（vulnerability）」** 說明「用它製造 leak（讀）或控制 `rip`（寫），兩者常常要先 leak 再打」，
把「漏洞 → 洩漏」這個連結補起來。其餘要求的名詞
（`va_list`、`IFUNC`、`shellcode`、`TLS`、`ZF`、`one-gadget`、`tcache`）都已在名詞表中定義。
