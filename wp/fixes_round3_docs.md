# Round 3 文件修正紀錄（新手教學完整性）

> **來源**：`wp/review_round3_cold_read.md`（冷讀新手模擬）＋ `wp/review_round3_regression.md`
> 第 2.2、2.3 節（`rt_sigframe` 大小、`DEBUG` 參數）。
> **可編輯檔案**：`wp/00_基礎知識_從零開始.md`、`wp/99_速查表.md`、`pwn2/notes.md`、`pwn4/notes.md`
> （其餘檔案依指示不動）。
> **環境**：Arch Linux、glibc **2.44**（題目附 glibc **2.39**）、gdb 17.2、pwntools 4.15.0。
> **原則**：**每一條都先實測／實跑再改**；審查者的說法只要與現況不符就記錄下來（見第 3 節）。

---

## 0. 統計

| 項目 | 數 |
|---|---|
| 指定修復項 | **10** |
| 已修／已補 | **10** |
| 完全略過 | **0** |
| 部分略過（同一項內有小部分做不到） | **1**（第 3 項：`wp/README.md` 不在可編輯清單） |
| 被推翻／需修正的宣稱 | **4**（其中 2 條是審查者說法與現況不符、2 條是**我自己草稿寫錯後自查改正**） |

---

## 1. 逐條紀錄

### 第 1 項｜heap 入門動線是斷的 —— **已修**

* **檔案**：`wp/00_基礎知識_從零開始.md`（檔頭導讀、§1 的 📌 區塊、§9 的 💡 區塊）、
  `wp/99_速查表.md` §8（開頭新增「入門三句話」與各名詞定義）。
* **怎麼改**：三處指路全部改成「**先讀 `pwn4/notes.md` §5.1～§5.4**（真正的 heap 教學），
  再回頭把 `99` §8 當**速查表**」，並明文寫「**不要從 §8 開始讀 heap**」；
  §8 標題下方補上「① chunk 是什麼 ② free 之後進 bin ③ malloc 先從桶拿 → 這就是 tcache poisoning」
  三句話，並就地補齊原本沒解釋的名詞：`fd`/`bk`、`size` 的三個 flag bit、
  `fastbin`/`small`/`large`/`unsorted bin` 各一句話、`FSOP`／`House of Apple`、`aligned_OK`。

### 第 2 項｜pwn4 沒說 safe-linking「防什麼」 —— **已補**

* **檔案**：`pwn4/notes.md` §5.4（新增「它到底在防什麼？（先講動機…）」整段）。
* **怎麼改**：新增一段說明它要切斷兩條路 —— ①**盲打（blind）tcache poisoning**：
  2.32 之前 `fd` 是明文，任何拿到 UAF／溢寫的人不必知道位址就能把 `fd` 改成 GOT／hook；
  ②**只改 `fd` 最低 1 byte 的 partial overwrite**。並說明 safe-linking 的後果：
  「攻擊前提被改成**必須先洩漏一次 heap 位址**」，以及 glibc 又在 `entries[]` 留明文才是本題能通的原因。

### 第 3 項｜safe-linking 基準位址自我矛盾 —— **已修（並用實測確定公式）**

* **檔案**：`pwn4/notes.md`（§5.1 圖說、§5.3 用字約定、§5.4 全文、§7.3、§8.2、§8.3、§12 總結）、
  `wp/99_速查表.md` §8（+ 新增 §8.1 實測小節）。
* **怎麼改**：統一寫成
  **`stored = ptr ^ ((u64)&e->next >> 12)`**，並在兩份文件都明文宣告
  「**key 用的是 user 位址（`&e->next` ＝ chunk 標頭 + `0x10`），不是 chunk 標頭位址**」；
  pwn4 §5.3 新增「本節用字約定」，把「chunk 位址（標頭）」與「user 位址（`malloc` 回傳值＝`e`）」
  兩個詞釘死，並說明 `&e->next` **恆等於** user 位址（`next` 就是 user data 前 8 bytes，
  不是只有鏈頭那塊）。同時解釋「為什麼是 `>> 12`」（ASLR 以 4 KB 頁為單位隨機化）。
* **實測（兩版 glibc 都做）**：見第 2 節指令 ③——`user >>12` 永遠 MATCH、
  `header >>12` 在跨頁時 FAIL。**審查者的判斷正確：pwn4 是四份文件裡唯一寫錯的。**
* **部分略過**：`wp/README.md` L143 仍是簡寫 `` `ptr ^ (chunk_addr >> 12)` ``，
  該檔**不在可編輯清單**（題目明確排除），因此未動；它只是簡寫、並非錯誤敘述，
  而且 README 第 37 行本來就把新手導向「`pwn4/notes.md` ← glibc heap 從零教」。
  `pwn6/notes.md` §3.5 本來就正確（L653–654 明寫 `pos = &e->next = e = P`（user 位址）），
  同樣不在可編輯清單，經核對後**不需要改**。

### 第 4 項｜`b *$base+0x1234` 照抄會報錯 —— **已修**

* **檔案**：`wp/99_速查表.md` §10（改寫 PIE 下中斷點的說明）與 §12 症狀表 2 列；
  `wp/00_基礎知識_從零開始.md` §13 同步加註。
* **怎麼改**：換成可執行的四步配方（`starti` → `info proc mappings` → `set $base = <實際位址>`
  → `b *$base+0x1234`），並附上實測輸出；同時把§12 症狀表裡另一處也寫錯的
  `` b *base+0x1234 `` 一起修掉。`wp/00` §13 補上「`$base` 不是 gdb 內建變數」的警語。
* **實測**：見第 2 節指令 ④（新配方 → `Breakpoint 1 at 0x555555555234`；
  舊寫法 → `Argument to arithmetic operation not a number or boolean.`）。

### 第 5 項｜`rt_sigframe` 被說成約 `0xf8` bytes —— **已修**

* **檔案**：`wp/00_基礎知識_從零開始.md` §11.4（名詞表第 1 列＋下面的 ⚠️ 區塊）。
* **怎麼改**：改寫成「`0xf8` 是 **pwntools `SigreturnFrame()`** 的長度；
  核心的 `rt_sigframe` 還含 `pretcode`／`siginfo`（`0x80`）／FPU 狀態，**大得多**」，
  並補一句「對解題重要的只有『你寫在 `rsp` 上的 bytes 要排得像 pwntools 的 frame（`0xf8`）」」。
* **實測**：`len(bytes(SigreturnFrame()))` → **248 = 0xf8**；
  另外自己寫程式量核心那一包（在 SIGSEGV handler 裡比較出事時的 `rsp` 與 `&ucontext - 8`）
  → 核心這次往下移了 **約 `0x6a8` bytes**（含 `siginfo 0x80` 與 xsave 狀態）。
  因此文件**沒有**採用審查者建議的「約 `0x1a8` 以上」這個數字，改用自己量到的實測值並註明會浮動。

### 第 6 項｜`python3 exploit.py DEBUG` 照做沒有效果 —— **已補**

* **檔案**：`wp/00_基礎知識_從零開始.md` §12（`DEBUG` 那幾行後面新增 🔴 區塊）。
* **怎麼改**：貼上實測的 `grep -n "context.log_level" pwn*/exploit.py` 七行輸出
  （6 支寫死 `'info'`、`pwn4` 是唯一有旗標的），說明「`from pwn import *` 先設好、
  下一行又蓋回 `info` ⇒ `DEBUG` 白打」，並給三種自己動手的做法。
* **實測**：見第 2 節指令 ⑥；`pwn4` 的旗標是 **`-v` / `--verbose`**（不是裸字 `VERBOSE`）。

### 第 7 項｜§10.8 的對齊算式沒有推導 —— **已補**

* **檔案**：`wp/00_基礎知識_從零開始.md` §10.8（貼在那段程式碼下面）。
* **怎麼改**：新增完整推導 —— ① 畫出 `R`(=洩漏到的 `saved_rbp`)／`R+0x08`／`R+0x10`／`R+0x18`／`R+0x20`
  的堆疊圖，指出**進 `system` 那一刻 `rsp = R+0x20`**；② 對照 SysV AMD64 的
  「`call` 時 `rsp%16==0` → 進函式 `rsp%16==8`」；③ 解出
  `需要 (R+0x20)%16==8` ⇔ `(R+0x10)%16==0`，兩種情形各寫一次；④ 解釋「**只含一個 `ret` 的 gadget
  只讓 `rsp` 多走 8 bytes、不改任何暫存器**，所以剛好把奇偶性翻過來」。
* **實測**：見第 2 節指令 ⑤（ABI 那一半用 gdb 精確入口點量到 `rsp&0xf == 8`；
  本題那一半把 `pwn5/exploit.py` 的對齊判斷改成 `if False:` 後跑 → `exit code -11 (SIGSEGV)`、
  拿不到 flag；改回來 → `sun{LOCAL_DUMMY_FLAG}`）。

### 第 8 項｜`checksec` 可能沒裝 —— **已修**

* **檔案**：`wp/00_基礎知識_從零開始.md` §2（`### checksec`）、§4 開頭、§15 SOP；
  `wp/99_速查表.md` §1。
* **怎麼改**：四處全部把 **pwntools 一行版改成「首選」**並放最前面：
  `python3 -c "from pwn import *; print(ELF('./chal', checksec=False).checksec())"`；
  後面才列 `checksec --file=` 並註明「沒裝會 `command not found`，不是你的錯」，
  以及三種取得方式（pwntools 的 console script／發行版套件／pwndbg 的 gdb 指令）。
* **實測**：pwntools 那行輸出與 `checksec` 指令一致（見第 2 節指令 ①）。

### 第 9 項｜只教掃 `%N$p`、沒教怎麼認出自己 —— **已補**

* **檔案**：`wp/99_速查表.md` §7（新增 `### 7.1 掃完 30 行 hex，哪一行才是「我」？`）。
* **怎麼改**：補上 ① 標記法（`AAAABBBB.` + `%p` ×16 → 找 `0x4242424241414141`）、
  ② 直接編號法（`%1$p %2$p …`，並示範「自己的格式字串也會出現在某一格」），
  以及「`printf(buf)` 前 5 個參數是 `rsi,rdx,rcx,r8,r9`、第 6 個以後才從堆疊來」的說明；
  最後強調**不要背編號、一律實測**（本系列 pwn2 是第 8 個）。
* **實測**：見第 2 節指令 ⑦（真的印出標記在第 6 格，暫存器 5 格在前）。

### 第 10 項｜pwn2 缺「為何只寫 6 bytes」與「控制 `buf` ＝ 控制參數」 —— **已補**

* **檔案**：`pwn2/notes.md` §3.4（新增 ★ 區塊）、§5（新增
  `### 為什麼只寫 6 bytes？（p64(system)[:6] 的那個 [:6]）`），並同步 §7 既有的那句說明。
* **怎麼改**：
  * (a) 新增小節：說明 x86-64 使用者空間是 **47-bit canonical**（實測本機該題行程所有映射
    排除 `[vsyscall]` 後最大值 `0x7ffc03846000`），所以 libc 位址高 2 bytes 恆為 `\x00\x00`，
    而 GOT 裡原本的 `printf` 位址高 2 bytes 也已是 0 ⇒ **寫 6 bytes 就等於寫 8 bytes**；
    並附「6 bytes = 112 bytes payload／8 bytes = 144 bytes」的實測長度差，
    說明 `fgets(buf,255)` 下 payload 越短越安全；另加 LA57（5-level paging）的例外提醒。
  * (b) 在 §3.4 新增表格，明文寫 **「控制 `buf` ＝ 控制參數（指標與值兩者都控制）」**，
    並回答新手一定會問的「參數不是呼叫端傳的嗎？為什麼寫在 buffer 裡也算參數？」
    （`printf` 只照編號去固定位置取 8 bytes，無從檢查真假；`buf` 就躺在呼叫者堆疊上）。

---

## 2. 驗證指令（全部實跑過）

```bash
# ① checksec fallback（本機：pwntools 4.15.0）
python3 -c "from pwn import *; print(ELF('./pwn4/cache_money', checksec=False).checksec())"
#  → RELRO/Stack/NX/PIE/RUNPATH/FORTIFY/SHSTK/IBT 八行，與 `checksec --file=` 相同

# ② $base 不是 gdb 內建（新 vs 舊）
gdb -q -batch -ex "p $base" -ex "b *\$base+0x1234" /tmp/t_base
#  → $1 = void ; Argument to arithmetic operation not a number or boolean.
gdb -q -batch -ex starti -ex "info proc mappings" \
    -ex "set \$base = 0x555555554000" -ex "b *\$base+0x1234" ./pwn2/mad_libs
#  → 0x0000555555554000 … r--p  …/mad_libs ; Breakpoint 1 at 0x555555555234

# ③ safe-linking 的 key 是 user 位址（寫成 /tmp/t.c，見 pwn4 §5.4）
gcc -O0 /tmp/t.c -o /tmp/t && /tmp/t                              # 系統 glibc 2.44
./pwn4/ld-linux-x86-64.so.2 --library-path pwn4 /tmp/t            # 題目 glibc 2.39
#  → 兩版都是 user>>12 MATCH、header>>12 NO（跨頁的那塊 chunk）
#  另：grep -n 'PROTECT_PTR' 對照 glibc 巨集 #define PROTECT_PTR(pos, ptr) ((pos)>>12)^(ptr)

# ④ SigreturnFrame 長度 / 核心 rt_sigframe 大小
python3 -c "from pwn import *; context.clear(arch='amd64'); print(len(bytes(SigreturnFrame())))"
#  → 248
gcc -O0 /tmp/sigframe_size.c -o /tmp/s && /tmp/s     # SIGSEGV handler 內量 &ucontext-8 與出事 rsp
#  → sp at fault 0x7ffd91c3a1e0 / frame 0x7ffd91c39b38 → 核心移了 ~0x6a8 bytes

# ⑤ 對齊算式：ABI 那一半 + 本題那一半
gdb -q -batch -ex start -ex "b *probe" -ex c -ex 'p/x $rsp' /tmp/a
#  → 0x7fffffffde48（&0xf == 8）；注意用 `b probe` 會因 gdb 跳過序言得到 %16 == 0
sed 's/^    if (saved_rbp + 0x10) % 16 == 0:/    if False:/' pwn5/exploit.py > /tmp/noalign.py
(cd pwn5 && python3 /tmp/noalign.py)   # → exit code -11 (SIGSEGV)、FLAG: <not found>
(cd pwn5 && python3 exploit.py)        # → FLAG: sun{LOCAL_DUMMY_FLAG}

# ⑥ DEBUG 參數
grep -n "context.log_level" pwn*/exploit.py     # 6 支寫死 'info'；pwn4 吃 -v/--verbose
(cd pwn4 && python3 exploit.py -v)              # → 進入 debug 等級（實跑確認）

# ⑦ 格式字串「認出自己」配方（自編 printf(buf) 小程式）
printf 'AAAABBBB.%%p.%%p.%%p.%%p.%%p.%%p.%%p\n' | ./m
#  → AAAABBBB.0x1c9c0011.0x7fff240cff10.0x7f1675218760.0x1c9c0049.(nil).0x4242424241414141…
#    （標記在第 6 格 ⇒ 前 5 格是 rsi/rdx/rcx/r8/r9）

# ⑧ 6-byte 寫入 vs 8-byte 寫入（payload 長度）
python3 -c "from pwn import *; ...fmtstr_payload(..., p64(sys)[:6])"   # 112 bytes
python3 -c "from pwn import *; ...fmtstr_payload(..., p64(sys))"       # 144 bytes

# ⑨ 回歸：確認文件描述的行為仍成立（只改 .md，沒動任何程式碼）
(cd pwn2 && python3 selfcheck.py)      # → printf@GOT after == system, match=True, SHELL_OK
(cd pwn4 && python3 exploit.py -v)     # → 跑到 libc fingerprint 比對全中
(cd pwn5 && python3 exploit.py)        # → FLAG: sun{LOCAL_DUMMY_FLAG}
```

---

## 3. 被推翻／需要修正的宣稱（含我自己的）

| # | 宣稱 | 查核結果 | 處置 |
|---|---|---|---|
| 1 | 第 8 項：「`wp/00` 保護機制那節的**第一個指令**就是 `checksec --file=…`」 | **與現況不符**：`wp/00` §4 原本**一個指令都沒有**（只有說明文字）；`checksec --file=` 實際出現在 §2、§15 SOP 與 `99` §1。 | 仍照建議全部改成 pwntools 優先（四處），但位置描述以現況為準記錄在此 |
| 2 | 第 8 項：「沒裝會 `command not found`」 | **本機其實有**：`~/.local/bin/checksec`（由 pwntools 4.15.0 的 console script 提供）。但用 pipx／venv 安裝時它不會進 `PATH`，Debian/Ubuntu 需 `apt install checksec` ⇒ **風險是真的**。 | 改成「**首選 pwntools 一行版**」並列出三種取得方式 |
| 3 | 我自己草稿：第 10(a) 原本寫「硬寫 8 bytes 會因 `\x00` 讓格式字串提早結束、排版麻煩」 | **我自己測出來是錯的**：`write_size_max='long'`（預設）時 6 bytes 與 8 bytes 都是 96 bytes（pwntools 會用一次 `%15$lln` 寫完）；只有強制 `write_size_max='byte'` 才是 112 vs 144。 | 丟掉錯誤理由，改寫成實測數字（真正的好處是 payload 更短） |
| 4 | 我自己草稿：第 7 項的 ABI 實測原本寫「對一個**沒有序言**的函式設中斷點」 | **描述不準**：我測的函式**有**序言；關鍵是用了 `b *probe`（精確入口）而不是 `b probe`（gdb 會跳過序言）。 | 改成正確描述，並把「`b probe` 會量到 `%16 == 0`」這件事當成額外的教學點寫進文件 |

> 另外查核但**確認審查者為正確**的：`$base` 不是 gdb 內建（實測 `$1 = void`）、
> `0xf8` 是 pwntools frame 而非核心結構、6/7 支 exploit 寫死 `log_level`、
> pwn4 §5.4 的基準位址自我矛盾（`pwn6` §3.5 與 `99` §8 本來就寫 user 位址）、
> `%p` 前 5 格是暫存器、`pwn4` 的旗標確實是 `-v`。

---

## 4. 檔案與行數

| 檔案 | 修改前 | 修改後 | 主要新增內容 |
|---|---|---|---|
| `wp/00_基礎知識_從零開始.md` | 1209 | **1355** | heap 動線（3 處）、`checksec` 四處、§10.8 對齊推導＋實測、§11.4 `rt_sigframe` 更正、§12 `DEBUG` 實測、§13 `$base` 警語 |
| `wp/99_速查表.md` | 336 | **488** | §1 `checksec`、§7.1 認出自己、§8 入門三句話＋名詞定義、§8.1 safe-linking 實測、§10 PIE 下中斷點、§12 症狀表 2 列 |
| `pwn2/notes.md` | 1041 | **1107** | §3.4「控制 `buf` ＝ 控制參數」、§5「為什麼只寫 6 bytes？」 |
| `pwn4/notes.md` | 1522 | **1619** | §5.1/§5.3 用字約定、§5.4 safe-linking 動機＋公式＋實測、§7.3/§8.2/§8.3/§12 用語統一 |

* 四份文件的程式碼圍籬（``` ）數量皆為**偶數**（116／28／104／134），結構完整。
* 所有新增的 console 輸出都是**實跑貼上**；位址類數值都註明「ASLR 每次不同」。
