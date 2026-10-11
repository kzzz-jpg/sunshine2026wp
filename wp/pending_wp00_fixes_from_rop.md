# 待修清單 → `wp/00_基礎知識_從零開始.md`

> **來源**：`wp/review_round2_rop_foundations.md`（ROP 基礎／pwn5 那一輪）＋ 我逐條重跑驗證後的新發現
> **本檔只是清單**：負責 `wp/00` 的 agent 請自行套用（我這一輪完全沒有改動 `wp/00`）。
> **行號基準**：檔案現況 **895 行**（2025-09-28，與審查時相同 → 下面的行號仍有效）。
> **驗證環境**：Arch Linux、Python 3.14、glibc 2.44、pwntools 4.15.0。

---

## 0. 摘要（共 17 條，依嚴重度排序）

| # | 嚴重度 | 位置 | 一句話 |
|---|---|---|---|
| 1 | **P0** | §6.3（`312–332`） | 堆疊圖 `buf` / `canary` **上下顛倒**，且全篇沒有「canary 的 offset 怎麼算」 |
| 2 | **P0** | §2（`78–110`） | `pip install pwntools` 在本檔自己指定的 Arch 上**直接失敗**（PEP 668） |
| 3 | **P0** | §12（`730`） | `DEBUG=1 python3 exploit.py` **沒有作用**（pwntools 讀 `sys.argv`，不讀環境變數） |
| 4 | **P1** | 全篇 | **沒有教「libc base + offset」**（只有名詞，沒有算式） |
| 5 | **P1** | §9（`440`） | pwn6 被掛在「Missing bounds check」與「Uninitialised memory」兩個錯的類型上 |
| 6 | **P1** | 附錄（`886`） | pwn6 的核心技巧寫成「ROP」（實際完全不用 ROP） |
| 7 | **P1** | §9（`436`） | 「Stack Buffer Overflow」漏了 pwn5 |
| 8 | **P1** | §11.4（`617`） | 在定義之前就要求讀者去看還沒讀的 `pwn1` §5.3 |
| 9 | **P2** | §12（`679`） | `e.address` 註解「PIE base（本地）」會誤導（磁碟上的 PIE 檔是 `0x0`） |
| 10 | **P2** | §13（`755`） | `b *main+42` 對 stripped binary 無效 |
| 11 | **P2** | §10.7（`547`）／§14（`799`） | `ret2csu` 沒定義；`ropper` 本機沒裝、§2 也沒教怎麼裝 |
| 12 | **補充** | §4 開頭（`165` 前） | §4.1 的 canary 範例先用了 `fs:0x28`/`rbp`/`je`/`call`（§5、§6 才教） |
| 13 | **補充** | §10.7 之後 | 讀完 ROP 觀念後**沒有任何能立刻跑出結果的範例**（§12 是 `0x401234` 佔位符，必炸） |
| 14 | **補充** | §12（`738–741`） | 只提醒「長度欄位可能是大端」，沒給「怎麼寫」的實例 |
| 15 | **新發現** | 附錄（`885`） | pwn5 的核心技巧寫成「ROP / **命令注入**」——命令注入是**假線索** |
| 16 | **來自 fmtstr 報告 [W1]** | 附錄（`883`）／§9（`440`） | pwn3 的描述與 `pwn3/notes.md` 互相矛盾（見 §16） |
| 17 | **來自 heap 報告 [S1]** | 目錄（`13–29`）／§9 | 全篇沒有 heap 章節，卻預設讀者看得懂 pwn4/pwn6（見 §17） |

---

## 1.【P0】§6.3 堆疊框架圖：`buf` 與 `canary` 上下顛倒（`312–332`）

**現況**（`324–330`）：

```
        │  saved rbp  ← push rbp    │  ← rbp+0  ← rbp 指向這
        ├──────────────────────────┤
        │  char buf[0x30]           │  ← rbp-0x30
        ├──────────────────────────┤
        │  canary                   │  ← rbp-0x8
        └──────────────────────────┘  ← rsp
```

**錯在哪**：圖是「高位址在上、低位址在下」畫的，而 `rbp-0x30` **比** `rbp-0x8` **低** →
`canary` 應該畫在 `buf` **上面**（更靠近 `rbp`）。現在的畫法會讓新手推出
「溢位先撞到 canary 再撞到 buf」的相反結論，也跟同檔第 340 行自己寫的
「`canary` 通常緊貼 `rbp-8`」互相矛盾。pwn5 的實測值就是反例：`state` 陣列起點到 `state[0x108]` 才是 canary。

**建議替換文字**：

```
        │  saved rbp  ← push rbp    │  ← rbp+0  ← rbp 指向這
        ├──────────────────────────┤
        │  canary                   │  ← rbp-0x8   ← 最靠近 rbp，所以最先被撞到
        ├──────────────────────────┤
        │  char buf[0x30]           │  ← rbp-0x30
        └──────────────────────────┘  ← rsp ≈ rbp-0x40
位址低
```

並在圖下補（**目前全篇缺這條規則**，而 pwn1/pwn5/pwn7 都會用到）：

```markdown
**溢位時你依序會蓋到：`buf` 尾端 → canary → saved rbp → 回傳位址。**所以：

```
canary 的 offset   = (rbp - 8) - &buf = 0x28     # 以 buf[0x30] 為例
回傳位址的 offset  = (rbp + 8) - &buf = 0x38
```

有 canary 的題目，payload 一定要長成：
`b"A" * canary_offset + <原封不動的 canary> + <saved rbp（可填垃圾）> + <回傳位址>`。
canary 的**最後一個 byte 一定是 `0x00`**（它來自 `fs:0x28`，最低位 byte 固定為 0），
但**不要只補那一個 byte**——要整條 8 bytes 用洩漏到的原值寫回去（見 pwn5 §7.3）。
```

**驗證**：GCC 標準佈局；且 `pwn5` 實測 `state[0x108]` = canary（比緩衝區起點**高** `0x108`）。

---

## 2.【P0】§2 環境安裝：`pip install` 在 Arch 上直接失敗（`80`、`88`、`105`、`107`）

**實測（本機 Arch + Python 3.14）**：

```
$ ls /usr/lib/python3.14/EXTERNALLY-MANAGED
/usr/lib/python3.14/EXTERNALLY-MANAGED
$ python3 -m pip install --dry-run pwntools
error: externally-managed-environment
× This environment is externally managed
╰─> To install Python packages system-wide, try 'pacman -S ...
$ pacman -Si python-pwntools
Repository      : extra
Name            : python-pwntools
Version         : 4.15.0-2
```

**建議**：Arch 區塊改成

```bash
# Arch / Manjaro（推薦：用官方套件，不要用 pip 裝系統 Python）
sudo pacman -S python-pwntools gdb      # python-pwntools 就在 extra
```

並在「常用工具」區塊最前面加：

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

---

## 3.【P0】§12 `DEBUG=1 python3 exploit.py` 沒有作用（`730`）

**實測**：

```
$ DEBUG=1 python3 -c "from pwn import *; print(context.log_level)"
20                                  # info ← 環境變數完全沒用
$ python3 -c "import sys; sys.argv=['x.py','DEBUG']
from pwn import *; print(context.log_level)"
10                                  # debug ← 命令列參數才有效
```

**建議替換文字**：

```bash
python3 exploit.py DEBUG       # pwntools 除錯模式（注意：是「命令列參數」不是環境變數）
DEBUG=1 python3 exploit.py     # ← 這個沒有用！pwntools 不看環境變數
```

並補一句：`pwnlib.args` 會把 `DEBUG` 從 `sys.argv` 吃掉，
**要自己讀 `sys.argv` 的參數必須在 `from pwn import *` 之前讀**
（`pwn5/exploit.py` 第 17 行就是這樣處理 `REMOTE` 的，可當範例）。

---

## 4.【P1】全篇沒有「libc base + offset」的教學（只有名詞）

**現況**：`libc base` 只出現在 `763`（`vmmap # 找 libc base`）與 `844`（「需要 leak 嗎？」），
卻在 §12 直接給 `libc = ELF('./libc.so.6')` / `libc.symbols['system']` / `next(libc.search(b'/bin/sh'))`。
新手會卡在「leak 到一個 `0x7f…` 之後呢？」

**建議新增**（放在 §4.3「PIE / ASLR」之後，那裡已經講了 base + offset）：

```markdown
### 4.3.1 PIE base + offset 與 libc base + offset 是兩個不同的東西

| | PIE（執行檔本體） | libc（`libc.so.6`） |
|---|---|---|
| 位移從哪來 | `objdump` / `readelf` 看到的位址 | `libc.symbols['system']`、`libc.search(b'/bin/sh')` |
| 洩漏來源 | 堆疊上「指回程式碼段」的回傳位址、`.got` 內容 | `libc` 函式的 GOT 值、`__libc_start_main+…`、`environ`、`%N$s` 讀 GOT |
| 換算 | `PIE_base = 洩漏值 - <該位置的 offset>` | `libc_base = 洩漏值 - <該符號的 offset>` |
| 之後怎麼用 | `gadget = PIE_base + 0x12aa` | `system = libc_base + libc.symbols['system']` |

```python
libc = ELF('./libc.so.6', checksec=False)
libc.address = leaked_printf - libc.symbols['printf']   # ← libc base
system = libc.symbols['system']                         # pwntools 會自動加 libc.address
binsh  = next(libc.search(b'/bin/sh'))
```

> ⚠️ 兩個常見錯誤：① 把 PIE 的 offset 拿去加 libc base（或反過來）→ SIGSEGV；
> ② **libc 版本必須跟遠端一致**（本系列本機 Arch glibc 2.44、遠端 Ubuntu 22.04 glibc 2.35），
> 有附 libc 就用附的，並用 `./ld-linux-x86-64.so.2 --library-path . ./chal` 在本機重現。
> ③ PIE base 與 libc base 都一定是 `0x1000` 對齊，算完 assert 一下最省事。
```

---

## 5.【P1】§9 漏洞類型表把 pwn6 掛錯（`440`）

現況：

```
| **Missing bounds check** | 長度沒檢查就 `memcpy(dst, src, len)` | pwn3、pwn6 |
| **Uninitialised memory** | 沒初始化就讀 → 洩漏堆疊 | pwn6 |
```

* pwn6 `code_breaker` 的漏洞是「clone 時 **refcount 算錯** ⇒ 同一塊 chunk 被 `free()` 兩次 ⇒ double free + UAF」
  （`pwn6/notes.md` 第 18–19 行），**不是**長度沒檢查、也**不是**未初始化記憶體
  （`pwn6/notes.md` 第 1042–1043 行明確寫「沒有『nonce 沒讀到 ⇒ 用殘留 stack』的漏洞」）。
* pwn3 也不屬於「Missing bounds check」（見 §16：那是 `va_list.overflow_arg_area` 問題）。
  → **合併修正建議**：

```
| **Missing bounds check** | 長度沒檢查就 `memcpy(dst, src, len)` | （本系列沒有直接例子：pwn3 是 va_list、pwn6 是 refcount） |
| **Reference count bug**  | 引用計數算錯 → 同一塊被 `free()` 兩次 | pwn6 |
| **Logic bug** | 程式邏輯本身有洞（迴圈上界、簽章檢查…） | pwn5（off-by-one）、pwn6（refcount） |
```

「Uninitialised memory」這一列建議**刪掉**（本系列沒有對應題目），或改成反例教學：
「**本系列沒有**：pwn6 檢查過短讀，所以沒有殘留 stack 洩漏」。

---

## 6.【P1】附錄對照表：pwn6 的核心技巧寫成 ROP（`886`）

**現況**：`| code_breaker | pwn6/code_breaker | 26005 | PIE + canary → ROP | ../pwn6/notes.md |`
**正確**：pwn6 **完全不用 ROP chain**（`pwn6/notes.md` 第 24 行），
真正技巧是 heap double free / UAF → tcache poisoning → 覆寫 `.bss` 函式指標 `[PIE+0x40c0]` 成 `system@plt`。
（`wp/README.md` 第 19 行寫的是對的，只有這裡錯。）

**建議替換文字**：

```
| code_breaker | `pwn6/code_breaker` | 26005 | PIE + canary + Heap（refcount → double free/UAF）→ tcache poisoning → 覆寫 .bss 函式指標 | `../pwn6/notes.md` |
```

---

## 7.【P1】§9「Stack Buffer Overflow」漏了 pwn5（`436`）

**現況**：`| **Stack Buffer Overflow** | char buf[64]; read(0, buf, 1024); | pwn1、pwn7 |`
pwn5 的 `state` 陣列就在 `service_loop` 的堆疊上（`lea rax,[rbp-0x110]`），被 APPEND 的 off-by-one 溢寫
——標準的 stack buffer overflow。`wp/README.md` 也把 pwn5 歸在「堆疊類（pwn1、pwn5、pwn7）」。

**建議**：`| **Stack Buffer Overflow** | char buf[64]; read(0, buf, 1024); | pwn1、pwn5（state 在堆疊上）、pwn7 |`

**驗證**：`objdump -d -M intel --start-address=0x19e5 --stop-address=0x19f7 pwn5/homemaker` → `lea rax,[rbp-0x110]`；
`pwn5/gdb_evidence.sh` 顯示 `rbp=0x7fffffffddd0 state=0x7fffffffdcc0`（差 `0x110`）。

---

## 8.【P1】§11.4 在「定義之前」就引用 `pwn1` §5.3（`617`）

**現況**：
> `struct sigcontext` 的欄位順序是固定的（offset 請見 `../pwn1/notes.md` 第 5.3 節），pwntools 幫你排好，**不要自己手刻**。

閱讀順序是 `00` → `pwn1`，讀者還沒讀到那張四個名詞的表。

**建議替換文字**：

```markdown
這裡的四個名字很容易混，先記這張表（完整版在 `../pwn1/notes.md` §5.1）：

| 名字 | 是什麼 |
|---|---|
| `rt_sigframe` | 核心在處理 signal 時，放在使用者堆疊上的「整包」結構（x86-64 約 `0xf8` bytes） |
| `struct sigcontext` | 這包裡面真正存「所有暫存器」的那一段，`r8` 從 offset `0x28` 開始 |
| `SigreturnFrame()` | pwntools 產生的那 `0xf8` bytes；**它就是我們要塞上堆疊的東西** |

`struct sigcontext` 的欄位順序是固定的，pwntools 幫你排好，**不要自己手刻**。
```

---

## 9.【P2】§12 `e.address` 註解會誤導（`679`）

**實測**：`python3 -c "from pwn import *; print(hex(ELF('pwn5/homemaker',checksec=False).address))"` → `0x0`
（對磁碟上的 PIE 檔就是 `0x0`；只有接上 `process`/`remote` 之後才有意義，
而且本系列是 PIE → 真正的 base 只能靠 leak）。

**建議**：`e.address   # 磁碟上的 PIE 檔是 0x0；接上 process 後才是真正的 base（PIE 要靠 leak 才知道）`

---

## 10.【P2】§13 `b *main+42` 對 stripped binary 無效（`755`）

**實測**：`gdb -q -batch -ex 'b *main+42' ./pwn1/challenge`
→ `No symbol table is loaded.  Use the "file" command.`（本系列 pwn1、pwn5 都是 stripped）。

**建議**：`b *main+42                        # 只有「未 strip」才能這樣寫；stripped 請用 b *0x401234`
（`wp/99` §10、§12 已經補上同一件事。）

---

## 11.【P2】`ret2csu` 沒定義（`547`）＋ `ropper` 沒安裝（`799`）

* `547`：`* 找 mov rdi, ...; call ... 之類的片段（「ret2csu」也是一招）` → 加一句定義
  「`ret2csu`＝用 libc 初始化時留下的 `__libc_csu_init` 那兩個 gadget 一次設定 `rdi/rsi/rdx`」。
* `799`：`ropper -f ./chal --search "pop rdi"` → `command -v ropper` **無輸出**（本機沒裝），§2 也沒教怎麼裝。
  建議二選一：① §2 補 `pip install ropper`（記得 PEP 668，見 §2）；② 直接刪掉 ropper 那兩行，只留 ROPgadget。

---

## 12.【補充】§4 開頭先用了還沒教的東西（`165` 之前）

§4.1 的 canary 範例（`169–178`）用了 `fs:0x28`、`[rbp-8]`、`je`、`call`，但暫存器在 §5、堆疊框架在 §6 才教。
建議在 §4 開頭加一行：

```markdown
> 📌 這一節會用到 `rbp`、`rsp`、`fs:0x28`、`je` 這些名字。
> 如果還不熟，**先跳到第 5、6 節看完再回來**（保護機制要先知道「它保護什麼」才看得懂）。
> 這五個保護的「結論」比「原理」重要：先記住它們對解題的限制，原理稍後補。
```

---

## 13.【補充】缺一個「立刻能跑出結果」的動手範例（建議放在 §10.7 之後）

§12 的骨架用 `p64(0x401234)` 佔位符，跑起來一定 SIGSEGV。
建議加 §10.8「你人生第一條 ROP 鏈（用 pwn5 當教材，5 分鐘）」：

```bash
cd pwn5 && python3 exploit.py        # 本機，會印出 canary / PIE base / flag
```

```python
pop_rdi = pie + 0x12aa          # gadget：pop rdi; ret
system  = pie + 0x10c0          # 目標：system@plt
binsh   = pie + 0x4a54          # 參數："/bin/sh" 的位址（自己寫在 .bss 的）
ret     = pie + 0x101a          # 對齊用 ret

chain  = [pop_rdi, binsh, system]      # 「最小鏈」
if (saved_rbp + 0x10) % 16 == 0:       # 需要對齊時
    chain = [ret] + chain
```

（`pwn5/notes.md` §6.3.1 有一張「每個 `ret` 吃掉哪一格、`rsp` 跑到哪」的實測表，
很適合當這一節的圖；`chain[0]` 蓋在 `state[0x118]`、`state[0x120]` 才是鏈的本體。）

---

## 14.【補充】§12 只提醒「長度欄位可能是大端」，沒給寫法（`738–741`）

建議直接接在 🔴 提醒後面補：

```python
p16(0x101)                          # → b'\x01\x01'（小端）剛好一樣，看不出差別
p16(0x500)                          # → b'\x00\x05'（小端）❌ 伺服器讀成 0x0500 → 卡死
(0x500).to_bytes(2, 'big')          # → b'\x05\x00'（大端）✅ 正確
u16(hdr[2:4], endian='big')         # 讀回來也要指定大端
```

> 判斷方法：**看組語**。像 pwn5 那樣先 `shr ax,8` 再存高位 byte（`0x1400`）就是大端；
> 直接 `mov WORD PTR [..],ax` 就是小端（x86 原生順序）。

---

## 15.【新發現】附錄把 pwn5 的技巧寫成「ROP / 命令注入」（`885`）

```markdown
| homemaker | `pwn5/homemaker` | 26008 | PIE + canary + Full RELRO → ROP / 命令注入 | `../pwn5/notes.md` |
```

* **「命令注入」是假線索**（題目提示故意放的餌）：ECHO 指令執行的是**寫死的**
  `lea rax,[rip+0xec2]` → `.rodata:0x21b6 = "/bin/echo -n ''"`，全程沒有讀任何使用者輸入
  （`pwn5/notes.md` §4.3、`objdump` 可證）。`wp/README.md` 第 18 行也已經寫成
  「Off-by-one 改大容量 → 洩漏堆疊 → ROP」，本檔應該對齊。
* **建議替換文字**：

```
| homemaker | `pwn5/homemaker` | 26008 | PIE + canary + Full RELRO → off-by-one 改大容量 → 洩漏堆疊 → ROP（`pop rdi; ret` + `system@plt`；完全不需要 libc） | `../pwn5/notes.md` |
```

---

## 16.【來自 fmtstr 報告 [W1]】pwn3 的兩處描述與 `pwn3/notes.md` 矛盾（`883`、`440`）

（若負責 fmtstr 的 agent 已在自己的 pending 檔寫過，請以那份為準，這裡只是避免漏掉。）

* `883` 現況：`| revolution | pwn3/revolution | 26002 | 自製 printf 的長度整數問題 → .bss 溢寫 | ../pwn3/notes.md |`
  → `pwn3/notes.md` §11-7 花了一整段**駁斥**這個說法，真正原因是 `overflow_arg_area` 被初始化成 `buf`。
  **建議**：`| revolution | \`pwn3/revolution\` | 26002 | 自製 printf 的 \`va_list.overflow_arg_area\` 指向輸入緩衝區 → \`%N$s\` / \`%N$w\` 任意讀寫 → \`strcspn@got\` 覆寫成 \`system\` | \`../pwn3/notes.md\` |`
* `440` 的「Missing bounds check … pwn3、pwn6」→ 兩題都不屬於這類（已併入本檔 §5 的建議）。

---

## 17.【來自 heap 報告 [S1]/[S2]】全篇沒有 heap 內容（目錄 `13–29`；§9 `439`；`442`；`886`）

* **S1**：`wp/00` 沒有任何 heap / chunk / tcache / safe-linking 章節，卻在開頭建議
  「讀完 00 就能看懂每一題的 notes」——但 pwn4/pwn6 需要的 heap 知識只在 `wp/99` §8（迷你版）
  與 `pwn4/notes.md` §5（完整版）。
  **建議**：§9 或 §15 加一行「heap 題（pwn4/pwn6）請先讀 `wp/99_速查表.md` §8 + `pwn4/notes.md` §5」。
  （`wp/99` §8 我這一輪已補上 `_IO_2_1_stdout_` / `environ` 的定義、以及「`__free_hook` 在 glibc ≥ 2.34
  只是不再被呼叫（compat 符號還在）」的精確說法，可以放心引用。）
* **S2**：`439` 的 Heap Overflow / UAF 只列 `pwn4（heap 題）` → 應補 pwn6；
  `442` 的 `Uninitialised memory → pwn6` 應刪（已併入本檔 §5）；
  `886` 的 pwn6 ROP 描述（見本檔 §6）。

---

## 18. 附註：其他 pending 檔（已合併，見附錄 A／B）

* 上述 §16 / §17 是我直接從 `review_round2_fmtstr.md`（[W1]）與 `review_round2_heap.md`（[S1]/[S2]）
  抓出來、與 `wp/00` 有關的部分。
* 完成本檔時，`wp/pending_wp00_fixes_from_heap.md` 與 `wp/pending_wp00_fixes_from_fmtstr.md`
  **都已經出現**，依指示已**整份逐字附在附錄 A／B**（未套用）；它們是該主題的第一手報告，
  內容優先於 §16／§17 的轉述。
* 三份清單的重疊與衝突已在 **附錄 C** 逐行調解（主要是 `wp/00:440`、`886`）。
* 附錄 A 的 **D 段（S3／S4／S7）是 `wp/99_速查表.md` §8 的問題**，而 `wp/99` 屬於我這一輪的檔案
  → 我已經直接修好（見 `wp/fixes_round2_rop_foundations.md` §3.6），**`wp/00` 不需要動**。
* 這一輪我（ROP / pwn5）實際改過的檔案：`pwn5/notes.md`、`pwn5/exploit.py`（僅註解）、
  `wp/99_速查表.md`、`wp/README.md`，詳見 `wp/fixes_round2_rop_foundations.md`。

---
---

# 附錄 A：`wp/pending_wp00_fixes_from_heap.md`（heap 修正作業的原文，逐字附上）

> 依指示把另一份 pending 檔的內容整份併進來（**未套用**，只是集中在同一份交接清單）。
> 來源：heap round 2 審查（`pwn4`/`pwn6`），完成時間與本檔相同的一輪。

# `wp/00_基礎知識_從零開始.md` 待修清單（來自 heap round 2 審查）

> 本檔由 heap 修正作業（`pwn4`/`pwn6`）產生，**只列出必須在 `wp/00` 做的修改**。
> 我**沒有**、也不能改 `wp/00`（它由另一位 agent 擁有），所以列在這裡交接。
> 來源：`wp/review_round2_heap.md` §3（S1、S2），以及我在驗證過程中確認的實況。
> 每一項都附「行號 / 原文 / 建議替換文字」，可直接照改。

---

## A. 必改（與 pwn6 筆記直接矛盾，3 處）

### A1. `wp/00:886`（§附錄：本系列 7 題對照表）— pwn6 被寫成「→ ROP」

**原文**

```
| code_breaker | `pwn6/code_breaker` | 26005 | PIE + canary → ROP | `../pwn6/notes.md` |
```

**為什麼錯**：`pwn6/notes.md:24` 明寫「**完全不需要 ROP chain**」；§4 的核心是
`clone` 的 refcount 算錯 ⇒ double free / UAF ⇒ tcache poisoning ⇒
把 `system@plt` 寫進 `.bss` 的函式指標 `[PIE+0x40c0]` ⇒ `cmd 0x15` 的
`call qword ptr [0x40c0]` 直接變成 `system(我們送的字串)`。
實跑（local + REMOTE 都 PASS）完全沒用到任何 gadget。
（PIE + canary 只是「保護機制」，不是「技巧」；`wp/00` 這一欄的欄名是「核心技巧」。）

**建議替換文字**

```
| code_breaker | `pwn6/code_breaker` | 26005 | **Heap**（UAF / double free → tcache poisoning）→ 覆寫函式指標 → `system()`（不需 ROP） | `../pwn6/notes.md` |
```

### A2. `wp/00:439`（§9 常見漏洞類型）— UAF 只列 pwn4

**原文**

```
| **Heap Overflow / UAF** | `malloc` 系列操作錯誤 | pwn4（heap 題） |
```

**為什麼要改**：`pwn6` 也是 heap 題（`pwn6/notes.md:17-19`：refcount 算錯 ⇒ double free +
UAF ⇒ tcache poisoning），而且它才是「UAF 寫入 tcache metadata」的完整示範。
只列 pwn4 會讓讀者以為 pwn6 不是 heap 題（正好與 A1 的錯誤互相強化）。

**建議替換文字**

```
| **Heap Overflow / UAF** | `malloc` 系列操作錯誤（free 後指標仍可用 / 同一塊 free 兩次） | pwn4（UAF + tcache poisoning）、pwn6（refcount 算錯 → double free + UAF） |
```

### A3. `wp/00:442`（§9 常見漏洞類型）— pwn6 被列在「Uninitialised memory」

**原文**

```
| **Uninitialised memory** | 沒初始化就讀 → 洩漏堆疊 | pwn6 |
```

**為什麼錯**：`pwn6/notes.md`（§9 坑 5）明確寫著 `/dev/urandom` 的 `fread`
**有** `cmp rax,0x10; jne 失敗` 的檢查，所以「nonce 沒讀到 ⇒ 用殘留 stack」是
**檢查過但不存在**的候選漏洞。把它列成本題的漏洞類型是錯的。
pwn6 真正的類型是 heap UAF / double free（見 A2），以及 §9:441 已經列的
「Logic bug」（refcount 邏輯）。

**建議替換文字（二選一）**

```
| **Uninitialised memory** | 沒初始化就讀 → 洩漏堆疊 | （本系列沒有；pwn6 是候選但已排除） |
```

或直接刪掉這一列（若不想留空欄）。

---

## B. 建議改（S1：`wp/00` 沒有任何 heap 內容／指路）

### B1. `wp/00` 目錄（`:13-29`）與 §9 都沒有 heap；§9:439 只是一個名詞

**問題**：`wp/00` 的章節只有 ELF/保護/組語/stack/syscall/PLT-GOT/ROP/SROP/pwntools/gdb/SOP，
**沒有 chunk / bin / tcache / safe-linking**。但檔頭（`:6` 附近）要求讀者
「讀完 00 就能看懂每一題的 notes」，而 `pwn4`/`pwn6` 需要的 heap 知識
只在 `wp/99_速查表.md` §8（迷你版）與 `pwn4/notes.md` §5（完整版）。
（`grep -n "wp/99\|速查表" pwn4/notes.md pwn6/notes.md` 原本是 **0 筆**；
本次已在兩份 notes 的檔頭補上指路，見 `wp/fixes_round2_heap.md` §3。）

**建議**：在 `wp/00` §9 的表格後（或 §9 開頭）加一段「heap 題的入門路徑」，
並在目錄加一個指標列：

```
> 💡 **heap 題（pwn4 `cache_money`、pwn6 `code_breaker`）**：本檔不含 heap 章節。
> 請先讀 `wp/99_速查表.md` §8（chunk / bin / tcache / safe-linking 的迷你版），
> 再讀 `pwn4/notes.md` §5（完整版，含 gdb 實測的 heap 佈局表）；
> `pwn6/notes.md` §3.5 也有一份 20 行的最小語彙整理。
```

---

## C. 確認「不需要改」的兩項（避免另一位 agent 白改）

* **S5（RELRO）**：`wp/00` §4.4 說「Partial RELRO → `.got` 唯讀、`.got.plt` 可寫」
  —— 這是**正確的**（`readelf` 實測 RELRO 覆蓋 `0x403dc0~0x404000`，
  含 `.got`（`0x403fd8`）；`.got.plt` 只有前 0x18 bytes 被保護，
  函式 GOT 從 `0x404000` 起仍可寫）。錯誤的是 `pwn4/notes.md`，已在本次修好。
  **`wp/00` 不用動。**
* **S6（暫存器術語）**：`wp/00` §6.1 寫「`r8`、`r9` 是第 5、6 個參數」——**正確**。
  錯誤的是 `pwn4/notes.md`（原本寫 `r8~r11`），已在本次修好。**`wp/00` 不用動。**

---

## D. 附註：屬於 `wp/99_速查表.md` §8（不是 `wp/00`，給負責 wp/99 的 agent）

以下三項也是 round 2 審查的一致性問題，但**不在 `wp/00`**，本檔僅代為列出以免漏掉：

1. **S3【中】** `wp/99:184-185` 說「偽造 `fd` 前**要先知道 chunk 位址**」——與事實相反。
   safe-linking 只用 `chunk >> 12`，所以「洩漏 `chunk>>12`（例如 free 到空鏈時讀 `next`）」
   就足以偽造 `fd`；這正是 pwn4 flag `s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che` 的意義。
   建議改成：「…存的是 `target ^ (chunk_addr >> 12)`；因為只用到 `chunk>>12`，
   只要洩漏 `chunk>>12` 就能偽造 `fd`（見 `pwn4/notes.md` §5.4、`pwn4/notes.md` §5.3 的 `entries[]` 明文註記）。」
2. **S4【中】** `wp/99` §8 補三個現代 glibc 細節（各一行）：
   (a) `tcache->entries[]` 是**明文** user 位址，只有 chunk 內的 `next` 才編碼；
   (b) `tcache_get()` 有 `aligned_OK(e)` 檢查 → 毒化目標必須 16-byte 對齊；
   (c) `tcache_put` 的寫入順序是 `key → next → entries → counts`（影響「先清 key 才能 double free」）。
   註：`pwn4` §5.3/§5.4/§10 與 `pwn6` §3.5/§4.3 現在都已經寫到這三點。
3. **S7【低】** `wp/99` §8 補一句欄位命名說明：
   「`+0x10`/`+0x18` 這兩格：在 tcache 叫 `next`/`key`，在 unsorted/small/large bin 叫 `fd`/`bk`；
   fastbin 只用到 `+0x10` 的 `fd`。」（`pwn6` §3.5 (2) 已有同樣說明。）

---
---

# 附錄 B：`wp/pending_wp00_fixes_from_fmtstr.md`（fmtstr 修正作業的原文，逐字附上）

> 同上，整份併進來（**未套用**）。

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

所以從任何 cwd 執行都會成功（本輪複驗：在 repo 根目錄用 `bash -c 'cd /home/kzzz/Documents/code/ctf/sunshine && python3 pwn3/exploit.py'` 同樣 PASS）。
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
# 2) 改完 wp/00 之後確認沒有殘留矛盾字串
grep -n "bss 溢寫\|memcpy(dst, src, len)\` | pwn3" wp/00_基礎知識_從零開始.md
# 3) pwn2/pwn3 exploit 不受 cwd 影響（P3）
cd / && python3 /home/kzzz/Documents/code/ctf/sunshine/pwn3/exploit.py < /dev/null | tail -3   # 應印出 FLAG
```

---
---

# 附錄 C：三份清單的重疊與衝突調解（給 `wp/00` 負責人）

三份 pending 檔（本檔 §1–§18、附錄 A 來自 heap、附錄 B 來自 fmtstr）有 4 處講到同一行，
照下面這樣合併就不會打架：

| `wp/00` 行 | 三份清單怎麼說 | 建議合併結果 |
|---|---|---|
| `440`（§9 Missing bounds check） | 本檔 §5：pwn6 不是 bounds check（是 refcount）；附錄 B P2：pwn3 不是 bounds check（是 `va_list`）；附錄 A 沒提 | **兩份都對 → 這一列在本系列沒有正確例子**，採本檔 §5 的版本（移除 pwn3 與 pwn6，另開 `Reference count bug` 列） |
| `886`（附錄 pwn6 技巧） | 本檔 §6 與附錄 A A1 是同一件事 | 用附錄 A1 的版本（資訊較多：`refcount → double free/UAF → tcache poisoning → 覆寫 .bss 函式指標`） |
| `439`／`442`（§9 heap、Uninitialised memory） | 本檔 §5 與附錄 A A2／A3 一致 | 直接採附錄 A 的兩段替換文字 |
| `733–736`（`cd` 警告） | 附錄 B P3：pwn2/pwn3 的 exploit 已用絕對路徑，不受 cwd 影響 | 追加那一行「例外」即可（與本檔 §1–§18 無衝突） |

另外兩件**不需要改 `wp/00`** 的事：

* **附錄 A 的 D 段（S3／S4／S7）是 `wp/99_速查表.md` §8 的問題**，而 `wp/99` 是本輪由我負責的檔案 →
  我已經**直接套用**（safe-linking 只需要 `chunk >> 12`、`entries[]` 明文、
  `aligned_OK` 的 16-byte 對齊要求、`tcache_put` 寫入順序、`next`/`key` vs `fd`/`bk` 的命名），
  詳見 `wp/fixes_round2_rop_foundations.md` §3；`wp/00` 不用動。
* **附錄 A 的 C 段**（RELRO 描述、`r8/r9` 術語）與附錄 B 的 P5（一致性複查）都確認
  **`wp/00` 原本就是對的**，不要白改。
