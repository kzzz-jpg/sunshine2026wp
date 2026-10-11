# Review Round 3（最終）Part B — 冷讀新手模擬報告

**角色**：熟悉 C / Python / Linux，但**完全沒有 binary exploitation 經驗**的程式設計師。
不知道 gadget、SROP、tcache、safe-linking、PLT/GOT、`%n` 是什麼，沒用過 pwntools / gdb 做漏洞利用。
**只讀文件**，每次「必須靠猜才能繼續讀」都算一個 finding。

**讀過的**：`wp/README.md`（全）、`wp/00_基礎知識_從零開始.md`（§1–§15 關鍵節）、`wp/99_速查表.md`（全）、
`pwn2/notes.md`（§0–§12 關鍵節）、`pwn4/notes.md`（§5、§7、§8 關鍵節）、`pwn5`/`pwn6`（僅標題層級）。

**一句話總結**：`wp/00` 與 `pwn2` 是我看過最適合新手的教學之一（連「`jg` 是有號、`ja` 是無號」都教了）；
但**heap 的入門動線是斷的**（文件把新手導向一份為老手寫的速查），加上一條**照抄會直接報錯的 gdb 指令**，
以及 pwn4 對 safe-linking 基準位址的自我矛盾。分數 **7/10**。

---

## 1. 逐份文件的理解中斷點

格式：**引文** → 缺什麼 → 建議補的句子（可直接貼進文件）。

### 1.1 `wp/README.md`

**R-1｜「bin」未定義**
> 引文（L127）：「**看懂 tcache** | glibc ≥ 2.26 的 per-size 單向 bin，LIFO，每 size 最多 7 個」

缺什麼：整份 repo 的索引頁第一次出現「bin」，沒有任何解釋。
建議補：「**bin ＝ glibc 內部的「空閒 chunk 回收桶」**：`free()` 掉的記憶體會依大小分類丟進不同的桶，`malloc()` 再從桶裡拿。tcache 是其中最快的一種（完整說明見 `pwn4/notes.md` §5.3）。」

**R-2｜safe-linking 公式出現但沒有「為什麼」**
> 引文（L128）：`fd` 是 `ptr ^ (chunk_addr >> 12)`

缺什麼：`fd` 在哪裡？為什麼要 `>>12`？`chunk_addr` 指哪個位址（這點 pwn4 自己也寫錯，見 E-1）？
建議補：「`fd` 是**被 free 的 chunk 裡的前 8 bytes**（glibc 用它串起同一條鏈）。`>> 12` 取的是**頁號**——ASLR 只以 4 KB 頁為單位隨機化，所以位址的高 bits 是可猜的，glibc 就拿它當金鑰把指標加密。」

**R-3｜GOT 沒有定義就當動詞用**
> 引文（L120）：「把 `xxx@got` 改成 `system`，之後那個函式就變成執行 shell 指令」

缺什麼：索引頁沒有一句話說明 GOT 是「外部函式真實位址的表格」。
建議補：「GOT 是動態連結用的**函式位址表格**：程式每次呼叫外部函式都會先去表格查位址，所以改表格＝改行為（`wp/00` §8）。」

**R-4｜hook 未定義**
> 引文（L130）：「覆寫 GOT / 全域函式指標 / `__free_hook`（2.34 以後沒有 hook 了）」

建議補：「hook ＝ glibc 在特定時機會**主動呼叫的全域函式指標**；以前把 `__free_hook` 改成 `system`，`free(x)` 就會變成 `system(x)`。」

**R-5｜成果總表（L14–L20）術語密度過高**
「SROP」「stripped」「純組語」「va_list 別名問題」「seccomp」「stack pivot」「off-by-one」「Partial/Full RELRO」
全部只出現在表裡、沒有指向定義。建議在表下加一列對照：「表內術語首次定義處：SROP→`00` §11｜stack pivot→§10.6｜canary→§4.1｜RELRO→§4.4｜va_list→§1 名詞表」。

### 1.2 `wp/00_基礎知識_從零開始.md`

**W-1｜★ 唯一「無法從前文推導出來」的算式**
> 引文（§10.8，L744）：`if (saved_rbp + 0x10) % 16 == 0:         # §10.4：需要對齊時在最前面補一個 ret`

缺什麼：§10.4 只說「多插一個 `ret` 讓 `rsp` 多走 8 bytes」，但**沒有教怎麼判斷「這次要不要插」**。
`+0x10` 從哪來、為什麼用 `saved_rbp` 當基準，全篇沒有推導。這是整份 `00` 中我第一次必須停下來猜的地方。
建議補（接在該行下方）：「`saved_rbp` 是我們洩漏到的『被覆寫的那格 rbp』的位址；`+0x8` 是返回位址那一格、`+0x10` 是它後面第一格（＝鏈的起點）。`system` 執行第一道指令時 `rsp` 會指向鏈的下一格，所以只要 `rsp % 16 == 8` 就對齊。本題鏈只有 `pop rdi` 一格，化簡後就是上面的式子。**更保險的判準**：在 gdb 的 `system` 第一道指令看 `p $rsp & 0xf` 是不是 `8`（見 `99_速查表.md` §12）。」

**W-2｜★ `checksec` 是 shell 指令還是 gdb 指令？**
> 引文（§2，L139）：「裝好之後 gdb 會有 `checksec`、`telescope`、`heap`、`bins`…」
> 引文（§4，L206）：「解題第一件事就是 `checksec`。這五個保護決定了你能用哪些技巧」

缺什麼：§4 給的是 shell 指令 `checksec --file=./challenge`，但 §2 只說「裝了 pwndbg 之後 gdb 會有 checksec」。
沒裝 pwndbg 的人打這行會拿到 `command not found`，而且文件沒有說 `checksec` 這個獨立指令怎麼裝（Ubuntu 上不是預設）。
建議補：「`checksec` 有兩種：① 獨立指令 `checksec --file=<binary>`（Debian/Ubuntu 可 `sudo apt install checksec`）；② pwndbg 在 gdb 裡提供的 `checksec`。**兩者都沒有也能做事**，用下一行的 pwntools 寫法即可。」

**W-3｜§11.2 先用、§11.4 才定義**
> 引文（§11.1，L779）：「打包成一個 **`rt_sigframe`** 放在使用者堆疊上」
> 引文（§11.4，L837）：「這裡有三個名字很容易混，先記這張表」

缺什麼：`rt_sigframe` / `ucontext` / `struct sigcontext` 的定義表放在 §11.4，但 §11.1、§11.2 已經在用。
建議：把 §11.4 的那張對照表搬到 §11.1 開頭（或加一句「名詞對照見 11.4」）。

**W-4｜魔術數字 `0x1cb42f`**
> 引文（§4.3.1，L296）：`"/bin/sh" = libc_base + 0x1cb42f`  = `0x7f12346cb42f`

缺什麼：`system` 的 `0x58740` 有 `readelf -s` 的實測輸出可對照，但 `/bin/sh` 的 offset 憑空出現。
建議補：「`0x1cb42f` 是 `strings -tx ./libc.so.6 | grep '/bin/sh'`（或 `readelf -x .rodata`）查出來的檔案內 offset；程式裡用 `next(libc.search(b'/bin/sh'))` 自動找。」

**W-5｜§12 直接使用 format string 術語**
> 引文（§12，L926–L931）：「`8,  # 我們控制的「第幾個參數」（1-based，要自己先量出來）`」「`write_size_max='byte'`」「`numbwritten=0`」

缺什麼：`00` 沒有 format string 章節（只有 §9.2 指路），但 §12 直接端出 `%hhn`、`numbwritten`、`write_size`。
建議在該段開頭補：「（本段假設你已讀過 `pwn2/notes.md` §3；`%n`/`%hn`/`%hhn` 的一句話定義見 `99_速查表.md` §7。）」

**W-6｜`FmtStr` 的 lambda 魔法**
> 引文（§12，L934）：`autofmt = FmtStr(execute_fmt=lambda p: (p.sendline(b'%p'), p.recvline())[1])`

缺什麼：為什麼要 `[1]`？`execute_fmt` 要回傳什麼？新手照抄會失敗且不知為什麼。
建議補：「`execute_fmt` 必須是『**送出一段格式字串、並回傳這次輸出**』的函式。這裡用 tuple 索引 `[1]` 只是為了在 lambda 裡先 `sendline`、再回傳 `recvline()` 的結果（`[0]` 是 `sendline` 的回傳值，不是輸出）。」

**W-7（正評，列出來當對照組）**：§4 開頭主動提醒「本節會用到 `rbp`/`rsp`/`fs:0x28`，不熟先跳到第 5、6 節」——
**這正是整份文件最該推廣的寫法**，可惜只有這一處這樣做（heap、format string 都靠外部指路）。

### 1.3 `wp/99_速查表.md`

**C-1｜★★ 一條照抄就會報錯的 gdb 指令（實測驗證）**
> 引文（§10，L286）：「中斷點永遠不會命中 → 改成 `b *$base+0x1234`」
> 引文（§12 症狀表，L335）：「中斷點下了卻永遠不停 ｜ PIE binary 寫死位址（`b *0x401234`） ｜ 改成 `b *$base+0x…`」

缺什麼／**這是錯的**：`$base` **不是 gdb 的內建變數**，文件從頭到尾沒說它是誰定義的。實測（原生 gdb）：

```
(gdb) p $base                      → $1 = void
(gdb) b *$base+0x1234              → Argument to arithmetic operation not a number or boolean.
```

也就是說，§12 那張表用來「修『中斷點永遠不停』」的處方本身無法執行（若 gdb 把 `$base` 當 0，更糟：會變成 `b *0x1234`，症狀一模一樣）。
建議整段改成：「**PIE 檔請先讓程式停下來，再自己把 base 填進變數**：
```
starti                              # 停在動態連結器
info proc mappings                  #（或 pwndbg 的 vmmap）找 ./chal 的第一個映射起始位址
set $base = 0x555555554000          # ← 換成你剛剛看到的那個位址（ASLR 關閉時通常是這個值）
b *$base+0x1234
```
注意 `$base` 不是 gdb 內建變數，一定要先 `set $base = …`。」

**C-2｜★★ 被指定為「heap 入門」的章節其實不是入門**
> 引文（`00` §1，L37）：「請先讀 `wp/99_速查表.md` §8（chunk / bin / tcache / safe-linking 的**迷你版**）」

缺什麼：`99` §8 是給「已經會 heap 的人」查的速查。新手在這裡會連續撞到**沒有任何解釋**的：
`PREV_INUSE=1, IS_MMAPPED=2, NON_MAIN_ARENA=4`、`unsorted/small/large bin`、`fastbin`、
`aligned_OK(e)`、`tcache_get()` / `tcache_put()` 的呼叫順序、`House of Apple / FSOP`、
`_IO_2_1_stdout_`、`__free_hook`、`exit 的 hook`。我讀完 §8 仍然不知道「chunk 長什麼樣、free 之後發生什麼事」。
建議在 §8 標題下加**真正的入門三句話**：
「① `malloc(n)` 給你的是一塊**前面帶 8+8 bytes 標頭**的記憶體，這個單位叫 **chunk**；
② `free()` 之後 glibc 會把整塊塞進某個**回收桶（bin）**，桶依大小分類，最常用的是 **tcache**（每種大小最多放 7 塊、後進先出）；
③ `malloc()` 會**先從桶裡拿**——所以只要能改掉桶裡的連結資訊，就能讓 `malloc()` 回傳你指定的位址，這就叫 tcache poisoning（＝任意位址寫）。
其餘欄位名（unsorted bin、PREV_INUSE、FSOP…）第一輪讀不懂是正常的，看到就跳過。」
並把 `00`/`README` 的指路改成：「**先讀 `pwn4/notes.md` §5.1–§5.4（從零講，有圖），再回頭看 `99` §8 當速查。**」

**C-3｜只教「掃描」，沒教「怎麼認出自己」**
> 引文（§7，L157–L160）：`for i in range(1, 30): p.sendline(('%{}$p'.format(i)).encode()); print(i, p.recvline())`
> 引文（L165）：「`offset` = 你的輸入開頭在 printf 參數中的位置（1-based，就是上面掃到的那個編號）」

缺什麼：印出 30 行 hex，新手**怎麼知道哪一行是「我」**？
建議補：「認法有兩種：① 找 `0x70243725`（＝ `%7$p` 這幾個字元的 bytes）——那一行就是**格式字串自己**；② 更可靠：在格式字串**最前面**放 8 bytes 好認的標記 `AAAABBBB`，然後找哪一行印出 `0x4242424241414141`，那一行就是 `buf[0]`（見 `pwn2/notes.md` §4 技巧 A）。」

**C-4｜三個 `write_size*` 名字混用**
> 引文（§7，L164）`payload = fmtstr_payload(offset, {target_addr: value}, write_size='short')`
> 引文（§7 表格，L172）：「`write_size='byte'` ｜ **預設值**：每個 byte 一次 `%hhn`」
> 對照（`00` §12，L944）：「`fmtstr_payload` 的 `write_size_max` **預設是 `'long'`**」

缺什麼：新手會從 §7 表格得到「預設就是 byte」的印象，於是看到產出 `%1097c%19$hn` 時完全無法理解。
建議在 §7 參數表補一列：「`write_size_max`（預設 `'long'`）｜pwntools 會**自動把相鄰 byte 合併**成 `%hn`/`%n` 來縮短 payload，所以 `write_size='byte'` **不保證**產生 6 個 `%hhn`。要強制只用 `%hhn` 請再加 `write_size_max='byte'`（見 `wp/00` §12）。」

**C-5｜`&next` 這種寫法對新手不透明**
> 引文（§8，L235）：「（`chunk_addr` ＝ `malloc()` 回傳的 user 位址，也就是 `&next` 的位址）」

建議改成：「＝ `malloc()` 回傳的 user 位址（也就是 **fd/next 這個欄位自己所在的位址** ＝ chunk 標頭 + 0x10）」。

**C-6｜沒有場合說明的 gadget**
> 引文（§4，L67）：`mov rdx, rax ; jmp write@plt` ｜「沒有 `pop rdx` 時的替代方案」

建議補：「用法：先找一個能把值放進 `rax` 的 gadget，再用這條把 `rax` 搬到 `rdx`（詳細實戰見 `pwn1/notes.md`）。」

### 1.4 `pwn2/notes.md`

**P2-1｜「我可以控制 `buf`，就等於我控制了參數」少了最關鍵的一句**
> 引文（§3.4，L465）：「`%n` 需要『一個指標參數』。我們無法直接控制暫存器，但**可以控制 `buf` 的內容**，而 `buf[8k]` 就是第 `8+k` 個參數！」

缺什麼：§3.2 解釋了「第 6 個之後的參數在堆疊上」，但沒有把「**所以我把位址寫在 `buf` 裡，`printf` 就會把它當成參數值**」這一步接起來。
新手會在這裡卡住：「參數不是由呼叫端傳的嗎？為什麼我寫在 buffer 裡也算參數？」
建議補：「關鍵：`printf` 只是**照著編號從呼叫者的堆疊上取 8 bytes 當參數**，它無從檢查那些值『是不是真的參數』。`buf` 剛好就落在那段堆疊上，所以我們在 `buf` 裡寫入目標位址，`printf` 執行 `%17$hhn` 時就會把那個位址當成『第 17 個指標參數』拿去寫。」

**P2-2｜為什麼只寫 6 bytes？**
> 引文（§5，L687）：`fmtstr_payload(8, {printf_got: p64(system)[:6]}, ...)`

缺什麼：`[:6]` 沒有解釋（新手會想「位址不是 8 bytes 嗎？為什麼截掉 2 bytes」）。
建議補：「x86-64 使用者空間的 libc 位址只有低 **6 bytes** 有意義（高 2 bytes 永遠是 `\x00\x00`），所以只要寫 6 bytes；`fmtstr_payload` 會據此產生 6 次 1-byte 寫入。」

**P2-3｜實測表從 pos 43 跳到 pos 47**
> 引文（§3.3，L418–L419）：`pos 43: <libc 返回位址>` →（§5）→ 「第 47 個是 `PIE+0x11c9`」

缺什麼：中間 44–46 沒有交代，新手會懷疑自己的理解。
建議補一句：「pos 44–46 是 `main` 被 `__libc_start_call_main` 呼叫時留下的暫存器殘值（不穩定，不要用）；**pos 47 起才是 `_start` 那一層的堆疊**，所以第 47 個穩定等於 `PIE + 0x11c9`。」

**P2-4｜`%s` 任意讀只出現在附錄一句**
> 引文（§10(D)，L1021）：「`%<idx>$s` 需要位址在參數裡」

缺什麼：`99`/`00` 都把 `%N$s` 列為「任意位址讀」，但 pwn2 沒有教怎麼用（沒有範例、沒有「讀 8 bytes 要 `%s` + 位址在堆疊」的說明）。
建議在 §3.4 加一小段：「`%N$s` 把第 N 個參數當成**指標**並印出它指向的字串 —— 所以它也是『任意位址讀』：把目標位址寫進 `buf` 的對應格子，再用 `%N$s` 印出該位址的內容（讀到 `\x00` 為止；要讀乾淨的 8 bytes 通常改用 `%N$p`）。」

**P2-5（正評）**：§4 技巧 A–D + §9-1「參數編號不要猜」+ §9-11「PIE 與 libc 距離不固定，要各自洩漏」——
這**足以讓我在全新 binary 上自己找出參數索引**（見第 3 節）。

### 1.5 `pwn4/notes.md`

**P4-1｜★★ safe-linking 的基準位址自我矛盾（最嚴重的一條）**
> 引文（§5.4，L857–L858）：「`// 存：stored = (chunk位址 >> 12) ^ 目標位址`」
> 對照（同檔 §5.1，L731）：「`chunk 位址 = malloc 回傳值 - 0x10`」

缺什麼：同一份文件先用「chunk 位址」指**標頭**，接著又用「chunk 位址」指 glibc 實際用的 **user 位址（＝標頭 + 0x10 ＝ `&e->next`）**。
`99` §8 與 `pwn6` §3.5 都寫 user 位址，只有 pwn4 寫 chunk 位址。兩者差 0x10，`>>12` 後**大多數情況相同、跨頁時不同** —— 新手照字面算會錯，而且找不到原因。
建議把 pwn4 §5.4 的註解改成：
```c
/* PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr
   pos ＝ 這個 next 欄位「自己」的位址 ＝ malloc() 回傳的 user 位址
        （= chunk 標頭 + 0x10，★不是 chunk 標頭位址）
   本節以下提到的 chunk >> 12 一律指「user 位址 >> 12」。 */
```

**P4-2｜指紋表無法重製**
> 引文（§8.4，L1302–L1304）：「`free +0xadd20  puts +0x87bd0  write +0x11c560 …`」「Ubuntu 24.04 glibc 2.39 的已知 offset」

缺什麼：這些數字從哪查？新手無法自己生一份。
建議補：「用 `readelf -sW ./libc.so.6 | grep -E ' (free|puts|write|read|fgets|calloc|strtol|malloc|setvbuf)@@'` 就能自己生這張表。」

**P4-3｜unsorted bin 洩漏的常數**
> 引文（§8.1，L1232）：「`leak1[0x00..0x08] = main_arena.bins[0] = libc_base + 0x203ac0 + 0x60`」

缺什麼：`0x203ac0` 與 `0x60` 的來源只寫「gdb 實測」，且與 `OFF_UNSORTED = 0x203b20` 的關係要自己相加。
建議補：「`0x203ac0` ＝ `&main_arena` 相對 libc base 的位移、`+0x60` ＝ `main_arena.bins[0]` 在結構內的位置，兩者相加＝ `0x203b20`。實際解題不必背：在 gdb 印 `p/x &main_arena`、`p/x main_arena.bins[0]`，減掉 libc base 就得到這個值。」

**P4-4｜同一塊東西三種數字寫法，規則沒說出來**
> 引文（§5.3，L790）：「大小以 16 bytes 為一級：0x20、0x30、0x40、…」
> 引文（§5.3，L820）：「`tcache[0x90] (idx 7)` 的鏈 … `malloc(0x80)` 會先拿到 C3」
> 引文（§4.3，L469）：「Wallet 結構（`calloc(1, 0x30)`，chunk size 0x40）」

缺什麼：為什麼同一件事一下子是 `0x90`、一下子是 `0x80`、一下子是 `0x30`／`0x40`？「括號裡的數字是 chunk 大小還是請求大小」這條規則從沒寫出來。
建議補：「**命名規則**：`tcache[0x90]` 指的是『**chunk 大小**＝0x90 的那條鏈』；`malloc(0x80)` 的 0x80 是你要的**資料長度**。因為標頭佔 0x10 bytes 且要 16-byte 對齊，`chunk_size = 對齊16(malloc 參數 + 0x10)`（所以 `malloc(0x80)`→`0x90`、`calloc(1,0x30)`→`0x40`）。查表用 `tc_idx = (chunk_size - 0x20)/0x10`。」

**P4-5｜`key` 為什麼「清成 0」就能繞過**
> 引文（§7.2，L1113）：「`+0x08 key (= tcache_key)  ← ★ 用 Deposit() 把它寫成 0`」

缺什麼：§5.1 說 `key` 是「每次執行隨機的 64-bit 值」，但沒說「我們不可能猜到它，所以只能靠 UAF 把它覆蓋掉」。
建議補：「`key` 唯一用途是讓 `free()` 偵測 double free（`if (e->key == tcache_key) abort`）。我們不需要知道 `tcache_key` 是什麼，只要用 UAF 把 `key` 覆寫成**任何不等於它的值**（例如 0），第二次 `free()` 就會靜默通過。」

**P4-6｜heap 沒有像 pwn6 那樣的 20 行暖身**
> 對照：`pwn6/notes.md` §3.5「heap 最小語彙（讀 §4 之前先看這段）」——**pwn4 沒有等價段落**，直接從 §4 逐行組語接 §5 理論。

建議：把 `pwn6` §3.5 的作法搬到 `pwn4` §4 之前（或至少在 §5 開頭放 10 行「chunk / bin / UAF / double free / poisoning 各一句話」）。

### 1.6 `pwn5/notes.md`、`pwn6/notes.md`（僅標題層級）

**P56-1**：`pwn5` §6「從零開始 ROP」與 `wp/00` §10 大量重疊（gadget、16-byte 對齊、`movaps`），
好處是單題自足，但兩處**沒有互相引用**，兩份都讀的人會不確定哪個才是對的（其實一致）。
建議 `pwn5` §6.3 開頭加一行：「與 `wp/00` §10.4 講的是同一件事，這裡只是用本題的真實位址再驗一次。」

**P56-2**：`pwn5` §4.3 標題「（鑰匙卡魔數）——順便藏了 `pop rdi; ret`！」是很好的示範（教新手 gadget 可能藏在立即值裡）；
`pwn6` §3.5「讀 §4 之前先看這段」與 §5.5「SROP 是什麼（補充）」的**放置順序正確**。
建議把這兩個作法回饋到 `pwn4` 與 `pwn2`。

**P56-3**：`pwn5` 標題使用程式自訂名詞（`EJECT`、`ESC 訊框`、`opcode`、`capacity`），都在同檔 §2 定義，可接受；
但 `pwn5` §7.3「第二次 APPEND 的 payload（共 0x200 bytes）」與 `00` §6.3 的「offset 一律從 `buf` 起點往上數」需要一次顯式對照（`00` §6.3 有講等價，`pwn5` 沒提）。

---

## 2. 術語／魔術數字／順序問題

### 2.1 術語先用、後定義（或被指向外部文件）

| # | 術語 | 首次出現處 | 定義處 | 嚴重度 |
|---|---|---|---|---|
| 1 | `bin`（回收桶） | `wp/README.md` L127 | `pwn4` §5.3（**但 00 卻把新手導向 99 §8**） | ★★★ |
| 2 | `unsorted/small/large bin`、`fastbin` | `99` §8 | `pwn4` §5.5 | ★★★ |
| 3 | `FSOP` / `House of Apple` | `99` §8 L237 | **無** | ★★ |
| 4 | `aligned_OK(e)`、`tcache_get/put` | `99` §8 L225–226 | **無**（實作細節，不該出現在入門速查） | ★★ |
| 5 | `PREV_INUSE / IS_MMAPPED / NON_MAIN_ARENA` | `99` §8 L211 | `pwn4` §5.2 | ★★ |
| 6 | `hook` | `99` §8 L232、`README` L130 | `99` §8 L239（同節內、但排在數字之後） | ★ |
| 7 | `rt_sigframe` / `ucontext` | `00` §11.1（L779） | `00` §11.4（L841） | ★★ |
| 8 | `%n` / `%hn` / `%hhn` | `00` §12（L928） | `pwn2` §3.4、`99` §7 | ★★ |
| 9 | `seccomp` / `stack pivot` | `README` L110、L20 | `00` §10.6（pivot）；`seccomp` 全篇無定義 | ★★ |
| 10 | `IFUNC` / `va_list` 別名 | `README` L16、`00` §1 名詞表 | `00` §4.3.1 註解、`pwn3` §4.1 | ★ |

### 2.2 出現但來源未交代的魔術數字

| 數字 | 出現處 | 缺什麼 |
|---|---|---|
| `(saved_rbp + 0x10) % 16 == 0` | `00` §10.8 L744 | 整個式子的推導（**最嚴重**） |
| `/bin/sh` offset `0x1cb42f` | `00` §4.3.1 L296 | 沒說用 `strings -tx` / `libc.search` 取得 |
| `chunk >> 12` 的 key | `99` §8、`pwn4` §5.4 | 沒說「為什麼是 12 bits」（＝4 KB 頁） |
| `0x203b20` / `0x203ac0` + `0x60` | `pwn4` §8.1 | 只寫「gdb 實測」，沒給指令 |
| libc 指紋表（9 個 `+0x…`） | `pwn4` §8.4 | 沒給產生指令 |
| `tcache 最多 7 個` | `99` §8、`pwn4` §5.3 | 有寫 `mp_.tcache_count = 7`（OK，正評）|
| `0x10 / 0x20 / 0x90` 的 chunk 對應 | `pwn4` §5.3 | 命名規則未寫（見 P4-4） |
| `pwn1` 的 `0x401069`、`pwn5` 的 `0x12aa/0x4a54/0x10c0/0x101a` | `99` §6、`00` §10.8 | 都有說明來源（正評） |

### 2.3 順序問題（概念太早／太晚）

1. **太早**：`README` 成果總表用 SROP / tcache / seccomp / stack pivot 當「核心技巧」欄位，而它同時是「第一次讀者看到的東西」。
2. **太早**：`00` §12 出現 format string API，但 `00` 沒有該章節（§9.2 只是指路）。
3. **太晚**：`00` §11.4 的 SROP 名詞表（應在 §11.1）。
4. **太晚**：`99` §8 的「hook 是什麼」擺在引用 hook 的那幾行**後面**（L232 用、L239 才定義）。
5. **順序錯誤（結構性）**：`00` §1 把 heap 新手導向 `99` §8，但真正的入門教材是 `pwn4` §5。
   建議動線改為：`pwn4 §5.1–5.4` → `99 §8`（當速查）→ `pwn4 §7`。
6. **正確示範（應推廣）**：`00` §4 開頭主動警告「本節會用到 §5/§6 的符號，不熟先跳過去」；
   `pwn6` §3.5 在 §4 之前放 20 行 heap 語彙。這兩處是全套文件裡對「閱讀順序」處理得最好的地方。

---

## 3. 五個自我檢查問題的答案

### 3.1 讀完 `wp/00` 之後

| # | 問題 | 能回答？ | 讀完後的實際理解／缺什麼 |
|---|---|---|---|
| a | 什麼是 syscall | **YES** | `rax`＝編號、`rdi/rsi/rdx/r10/r8/r9`＝參數、`syscall` 指令、回傳值在 `rax`；§7 有編號表（`read`=0、`rt_sigreturn`=15、`execve`=59）。**缺**：一句「syscall 是**唯一**能從使用者空間要求核心做事的入口，libc 的 `read()` 只是薄薄一層包裝」——§7 的「為什麼重要」已經很接近，可再一句。 |
| b | 堆疊框架長什麼樣 | **YES** | §6.3 的圖＋「由上往下讀是位址變低」＋「溢位會先撞 canary 再撞返回位址」＋ offset 一律從 `buf` 起點往上數；連「`char buf[0x30]` 其實落在 `rbp-0x40`，別用『陣列大小 + 8』猜」都講了。**缺**：無（唯一小遺憾：`canary` 表格假設 `-fstack-protector` 預設值，但已註明實測條件）。 |
| c | 為何蓋返回位址能劫持控制流 | **YES** | §6.2「`ret` = `pop rip`」＋ §10.8 的五步表（`leave` → 第一個 `ret` → `pop rdi` → 第二個 `ret` → `system`）。 |
| d | gadget 是什麼 | **YES** | §1 名詞表＋§10.2「以 `ret` 結尾的一小段指令」＋三行 trace 示範「堆疊變成指令序列」。§10.2 還先聲明「以下位址都是佔位符，照抄一定失敗」。 |
| e | SROP 為什麼存在 | **YES** | §11.1 動機（核心信任堆疊上的 `rt_sigframe`）＋ §11.6「沒有 `pop rdi`／需要一次設定很多暫存器時比 ROP 好用」。 |

> 小結：`wp/00` 對 (a)–(e) **全部合格**。唯一的理解斷點不是這五題，而是 §10.8 的對齊算式（W-1）與 `checksec` 的安裝（W-2）。

### 3.2 讀完 `pwn2/notes.md` 之後

| 問題 | 能回答？ | 說明 |
|---|---|---|
| 能在**全新 binary** 上自己找出 format string 的參數索引嗎？ | **YES** | §4 給了四招：標記法（`AAAABBBB` → 找 `0x4242424241414141`）、`FmtStr` 自動探測、分段掃描（並提醒 `%100$p` 很佔長度、注意 255 上限）、以及「換 libc 版本這個數字可能不同 → 永遠實測」。§3.2 也給了「為什麼第 6 個之後在堆疊上」與「`buf[8k]` = 參數 `8+k`」的通則。 |
| 能用 `%n` 寫出任意位址寫入嗎？ | **YES** | §3.4 給了完整的四件事：① `%n` 的參數是**指標**；② 指標從哪來（`buf` 就是參數）；③ 寫入值＝「已印出的字元數」，以及**哪些東西會計數、哪些不會**（有實測驗證 `%64c%17$hhn` 計數是 64 不是 75）；④ 排版順序（格式指令在前、`\x00` 位址在後、8-byte 對齊、`badbytes=b'\n'`）。§9 的坑 2–5 幾乎把新手會踩的雷都列完了。 |
| 缺什麼 | — | ① 「我控制 `buf` 就等於控制參數」缺一句直白解釋（P2-1）；② `p64(system)[:6]` 為何只寫 6 bytes 沒說（P2-2）；③ 沒有現成的「**寫入→讀回驗證**」最小實驗腳本（§5 那個 `/proc/<pid>/mem` 自檢腳本很好，但被寫成「驗證 GOT 被改」，新手不會想到可以改成「驗證我寫對了 byte」）。建議在 §3.4 末補一個 10 行版本。 |

### 3.3 讀完 `pwn4/notes.md` 之後

| 問題 | 能回答？ | 說明 |
|---|---|---|
| 能解釋 tcache 嗎？ | **YES** | §5.3 有：每執行緒一份、依大小分 64 條鏈、LIFO、每鏈最多 7、`tcache_perthread_struct` 自己在 heap 開頭、`tc_idx = (chunk_size-0x20)/0x10`、以及 `free`/`malloc` 兩段虛擬碼。 |
| 能解釋 safe-linking 為什麼存在嗎？ | **NO（部分）** | §5.4 把「**怎麼繞**」講得非常清楚（key 怎麼洩漏、`entries[]` 是明文、`PROTECT_PTR` 公式），但**從頭到尾沒說它防的是什麼攻擊**。我讀完只知道「它把 `next` 加密了」，不知道「為什麼 glibc 要這樣做」。建議補一句：「**safe-linking 防的是『拿到 UAF/溢寫但不知道 heap 位址的人』**：因為存進去的值是 `位址 ^ (自己的位址>>12)`，不知道 chunk 位址就無法偽造出可用的 `fd`，`malloc` 拿到的就會是垃圾位址而 abort。」 |
| 能解釋 poison write（tcache poisoning）怎麼運作嗎？ | **YES** | §7.3 的 (2a)(2b)(2c) 三段狀態圖＋§8.3 的每一步對應程式碼＋「為什麼 double free 是必要條件」（§5.3 末）＋「為什麼毒化目標選 slot 表而不是 GOT」（`memset_chk` 會把 GOT 清 0）都很清楚。`POISON_SLOT = 6` 的推導表（§8.3）是很好的示範。 |
| 缺什麼 | — | ① safe-linking 的**動機**（上列）；② 「chunk 位址 vs user 位址」矛盾（P4-1，這條會直接讓人算錯）；③ chunk 大小／請求大小的命名規則（P4-4）；④ 指紋表與 `0x203b20` 無法重製（P4-2、P4-3）。 |

---

## 4. 術語一致性問題表

| 概念 | 各文件寫法 | 是否為問題 |
|---|---|---|
| safe-linking 的基準位址 | `pwn4` §5.1/§5.4：**chunk 位址**；`99` §8：**user 位址（`&next` 的位址）**；`pwn6` §3.5/§4.3：**user 位址** | ★★ **不一致（pwn4 是少數）**，且 pwn4 §5.1 自己把「chunk 位址」定義成標頭位址 → 差 0x10 |
| 返回位址 | `00`／`99`／`pwn4`：**回傳位址**；`pwn2`：**返回位址**（也混用 `return address`） | ★ 同義異名，建議統一為「返回位址（return address）」 |
| 鏈別標記 | `tcache[0x90]`（chunk 大小） vs `malloc(0x80)`（請求大小） vs `calloc(1,0x30)`→`0x40` | ★★ 規則未寫出（P4-4） |
| 格式字串參數位置 | 「第 N 個參數」(`00`/`pwn2`/`99`) ／「offset」(`fmtstr_payload` 的參數名、`99` §7) ／「參數編號」 | ★ 建議在 `99` §7 開頭統一宣告：「本文用『第 N 個參數（1-based）』，pwntools 的參數名叫 `offset`」 |
| GOT 的稱呼 | `xxx@got` ／ `GOT` ／ `.got.plt` ／ 「GOT 表」 | ★ `.got` 與 `.got.plt` 在 `00` §4.4 有區分，實務上都寫 `@got`；可在 `00` §8 加一句「口語上的『改 GOT』在本系列一律指 `.got.plt`」 |
| 對齊用的 `ret` | 「對齊用 `ret`」／「16-byte 對齊」／「`movaps` 崩潰」 | ✅ 一致（`00` §10.4 與 `99` §5.1 措辭幾乎相同） |
| canary | 「canary」／「金絲雀」／「Stack Guard」 | ✅ 一致（`pwn5` §1.3 三詞並列） |
| leak | 「leak」／「洩漏」 | ✅ 一致 |
| `next` vs `fd` | tcache 用 `next`/`key`，unsorted 用 `fd`/`bk` | ✅ **已明確說明**（`99` §8 L227–228：「同一格欄位在不同 bin 有不同名字」） |
| `P` 代表什麼 | `pwn6` §3.5 明文宣告「`P` 一律指 `malloc` 回傳的 user 位址」；`pwn4` 用 `chunk` 指同一東西 | ★ 建議 pwn4 也加同樣一句宣告 |
| PIE base 變數名 | `pie`（`00` §10.8、`pwn5`）／`pie_base`（`pwn2`）／`PIE_base`／`$base`（`99`，見 C-1） | ★ 變數名不統一雖無害，但 `$base` 是**未定義變數**，必須修 |
| `heap` 指令集 | `heap` / `bins` / `vis_heap_chunks`；`99` §10 已註明原版 gdb 要用 `x/40gx <heap 位址>` 代替 | ✅ 已處理 |

---

## 5. 結論

### 分數：**7 / 10**（「一個完全新手能不能靠這套文件學會」）

**加分**：
- `wp/00` §5–§11 是我讀過對「從零到第一條 ROP 鏈」最完整的繁中教學：暫存器→組語→堆疊框架→offset 計算（還警告不要用「陣列大小 +8」猜）→ROP 五步表→SROP→`checksec` 對策，**每一段都有實測輸出**。
- `99` §12「常見失敗症狀 → 原因對照表」對新手價值極高（`stack smashing detected`、`movaps` SIGSEGV、`b *main+42` 對 stripped 無效…）。
- `pwn2` §3–§5 + §9（16 條坑）足以讓人**獨立**完成一題 format string，並用 `/proc/<pid>/mem` 自己證明 GOT 真的被改。
- 兩條「假線索」的說明（`00` 附錄：pwn3/pwn5 的題目提示是餌）展現了正確的方法論。

**扣分**：
- heap 動線是斷的（`00` 把新手導向為老手寫的 `99` §8）；safe-linking 缺「動機」；pwn4 對基準位址自我矛盾。
- 一條**照抄會報錯**的 gdb 指令（`b *$base+…`），而且它正好出現在「症狀排除表」裡。
- `00` §10.8 的唯一算式沒有推導。

### 前三名「必須補」（依投資報酬率排序）

1. **修好 heap 的入門動線**（`99` §8 開頭加真正的「入門三句話」，並把 `00`/`README` 的指路改成「先讀 `pwn4` §5.1–5.4，再回來看 `99` §8」）。
   同時在 `pwn4` §5.4 補上 **safe-linking 到底防什麼**的一句話——這是目前唯一「能照做、卻講不出為什麼」的核心觀念。
2. **修掉 `$base`**：`99` §10 與 §12 症狀表改成 `starti` → `info proc mappings`（或 `vmmap`）→ `set $base = <實際位址>`，
   並在 `00` §13 同步加註「`$base` 不是 gdb 內建變數」。（我已用原生 gdb 實測：`p $base` → `void`，`b *$base+0x1234` → `Argument to arithmetic operation not a number or boolean.`）
3. **統一 safe-linking 的基準位址與 chunk 大小命名規則**：`pwn4` §5.4 的「chunk 位址」改成「user 位址（`&e->next` ＝ chunk 標頭 + 0x10）」，
   並在 §5.1/§5.3 明文寫出 `chunk_size = 對齊16(malloc 參數 + 0x10)`、`tcache[...]` 括號內是 chunk 大小。
   順手把 `pwn4` §8.1/§8.4 的常數附上產生指令（`readelf -sW libc.so.6 | grep`、gdb 印 `&main_arena`）。

**第四、五名（強烈建議）**：
4. `00` §10.8 補上 `(saved_rbp + 0x10) % 16 == 0` 的推導（或改成「用 gdb 在 `system` 第一道指令看 `$rsp & 0xf`」這種不必推導的做法）。
5. `00` §4 補上 `checksec` 的三種取得方式（獨立指令／apt／pwntools 一行），避免 `command not found` 卡住第一步。
6. `99` §7 補「怎麼從 `%N$p` 輸出裡認出自己」（`AAAABBBB` 標記法），並把 `write_size_max` 預設 `'long'` 的說明從 `00` §12 同步過來。
