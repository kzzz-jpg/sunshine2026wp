# Review Round 3（最終）— Part C：回歸事實查核

> **審查對象**：第 2 輪修正後的現況檔（`pwn1..pwn7/notes.md`、`pwn*/exploit.py`、
> `wp/00_基礎知識_從零開始.md`、`wp/99_速查表.md`、`wp/README.md`）
> **查核依據**：五份 changelog（`wp/fixes_round2_stack.md`、`fixes_round2_fmtstr.md`、
> `fixes_round2_heap.md`、`fixes_round2_rop_foundations.md`、`fixes_round2_wp00.md`）。
> **方法**：逐條讀 changelog → 到現況檔確認修改是否落實 → **再用 `objdump -d -M intel` /
> `readelf -S/-r/-s/-x` / `gdb -q -batch`（含單步、`/proc/<pid>/mem`） / pwntools / 實際跑 exploit
> 獨立重驗**。凡是 changelog 有列出驗證指令的，我都在本機重跑一次。
>
> 環境：Arch Linux、glibc 2.44（題目另有附 glibc 2.39 的 `libc.so.6` / `ld-linux-x86-64.so.2`）、
> pwntools 4.15.0。**本 repo 沒有 git 歷史**，所以「程式邏輯沒動」這類宣稱無法用 diff 驗證，
> 只能用行為驗證（重跑 exploit + 觀察輸出）——這一點在第 1 節的「限制」中註明。
>
> **結論：changelog 宣稱的修改全部有落實（0 條未落實）；但複驗過程中找到 1 條真正的技術錯誤
> （pwn1「唯一 `syscall; ret`」，第 1 輪修出來的句子本身是錯的，第 2 輪審查還把它標成「已正確修好」）
> 與 5 條低風險的位址／措辭問題。7 題 local + REMOTE 共 14 次實測全部 PASS。**

---

## 1. 修改未落實 / 與 changelog 不符（清單）

**統計：0 條「宣稱改了但沒改」、0 條「改錯方向」。**以下是我實際逐條確認過的清單（全部落實）：

| changelog | 宣稱 | 現況檔 | 我的確認方式 | 結果 |
|---|---|---|---|---|
| stack E1 | `pwn7/notes.md` §4.1：迴圈再開 3 次 `/dev/null`、槽表補成 4 個 `state=2` | `pwn7/notes.md:429-467` | `objdump` + gdb（`follow-fork-mode child`，`b *0x40180c`、`b *0x401819`） | ✅ 落實 |
| stack E1 | `pwn7/exploit.py` 檔頭註解同步 | `pwn7/exploit.py:23-29` | 讀檔 | ✅ 落實 |
| stack E2 | pwn1「3 次 read、**3 次** send」 | `pwn1/notes.md:559-563` | `grep -n "p\.send" pwn1/exploit.py` → 86/122/130 三筆 | ✅ 落實 |
| stack E3 | pwn1 §3.3 表格拆成兩列、補 ⚠️、重現腳本 7 個中斷點 | `pwn1/notes.md:230-300`、`:334-347` | **逐字抽出腳本跑**（`gdb -q -batch -x`） | ✅ 落實且可跑 |
| stack E4 | pwn7 §9 #3 改成尾呼叫（`jmp write@plt`） | `pwn7/notes.md:1019+` | `objdump --start-address=0x401f38` | ✅ 落實 |
| stack E5 | pwn1 §5.3 `csgsfs` = `33 00 …`（無 `0x2b`） | `pwn1/notes.md:470 附近` | `bytes(SigreturnFrame())[0xb8:0xc0].hex()` → `3300000000000000` | ✅ 落實 |
| stack E6 | pwn7 §2.2 組語範圍 0x401339~**0x40146f** | `pwn7/notes.md:139` | `objdump` 0x401339=`movabs`、0x40146f=`mov [rsp+0x28],rbp`、0x401474=`call prctl` | ✅ 落實 |
| stack E7 | pwn7 §6「我挑的**三個**片段」 | `pwn7/notes.md:600-615` | 表內 3 列（0x401f07 / 0x401fda / 0x401c32）與 `exploit.py` 常數逐項比對 | ✅ 落實 |
| stack §5 | pwn1/pwn7 的 ``` 圍籬數 66 / 96 | 兩份 notes | `grep -c '^```'` → **66 / 96** | ✅ 完全相符 |
| fmtstr E1 | pwn2 §9-5 `%17$hhn` 不貢獻計數、`%64c%17$hhn` = 64 | `pwn2/notes.md:970-972` | 自寫實驗寫進 `.bss` 再用 `/proc/<pid>/mem` 讀回 → **0x40** | ✅ 落實且正確 |
| fmtstr E3 | `write_size_max` 預設 `'long'`、會合併 | `pwn2/notes.md:478-488`、`pwn2/exploit.py:84-88` | `inspect.signature(fmtstr_payload)` → `write_size_max='long'`；實跑 → `%1097c%19$hn`、96 bytes | ✅ 落實 |
| fmtstr E4 | 格式指令區 72 bytes → 第一個位址在 `buf[72]` → 參數 17 | `pwn2/notes.md:514-519` | 探針 `%17$p` + 72 bytes padding + 標記 → 印出標記 ⇒ arg17 == buf[72] | ✅ 落實且正確 |
| fmtstr F1 | pwn3 `rbx` 保存格在 `buf-0x38` | `pwn3/notes.md:735-753` | gdb `x/1gx $rsp+0xe8` → `0x7fffffffdbe0` == `buf` | ✅ 落實且正確 |
| fmtstr F2 | §4.1 gdb 步驟「可直接貼上」 | `pwn3/notes.md:315-347` | 逐字複製執行，輸出與筆記**逐行相同** | ✅ 落實且可跑 |
| fmtstr F3 | `.init_array`=`[0x4012b0,0x401190]`、`.fini_array`=`[0x401280]` | `pwn3/notes.md:700-706` | `objdump -s -j .init_array/.fini_array` | ✅ 落實且正確 |
| fmtstr N1/N2 | §5 marker 法、IFUNC、`_IONBF` | `pwn3/notes.md:69-71,176-193,589-625` | 逐字跑 marker 腳本 → 輸出與筆記相同 | ✅ 落實 |
| heap E1~E15 | pwn4/pwn6 共 15 條 | 見第 3 節 | 逐條 objdump/gdb 重跑 | ✅ 全部落實 |
| heap E15 | `pwn6/exploit.py` 本地不再覆蓋 `FLAG.txt` | `pwn6/exploit.py:262-273` | 跑 local 後看訊息 + 檔案內容 | ✅ 落實 |
| heap B2 | `P` = malloc user 指標（標籤正名） | `pwn6/notes.md:712,1144-1145,1200`、`exploit.py:221` | 跑 exploit 訊息 `victim P (malloc user ptr)` | ✅ 落實 |
| rop P0-1 | pwn5 §7.1 ROP 鏈圖位移修正 | `pwn5/notes.md:991-1040` | **gdb 單步**（見第 3 節 pwn5） | ✅ 落實且正確 |
| rop P0-5 | `wp/README.md` 檔案樹（含 `00_recon.md`、`FLAG_REMOTE.txt`、`gdb_evidence.sh`、`libc-2.39…`、`review_round2_*.md`） | `wp/README.md` | 逐項 `ls` 對照 | ✅ 落實 |
| rop P1-1 | `process()` 預設 stdin PIPE、stdout PTY raw | `pwn5/notes.md:1319-1329` | `process('./homemaker')` 後讀 `/proc/<pid>/fd/{0,1,2}` → `pipe:[…]`、`/dev/pts/0`、`/dev/pts/0` | ✅ 落實且正確 |
| rop P2-1 | `checksum` 起點 0x11e9、0x11ff 是 `mov rax,fs:0x28` | `pwn5/notes.md` §1.3 | `objdump --start-address=0x11e9` | ✅ 落實 |
| rop P2-6/P2-7 | `wp/99` SROP 欄位註解、`rax=15 = __NR_rt_sigreturn` | `wp/99_速查表.md:138-144` | 讀檔 + pwn1 實測（`rax=15` 才進 `rt_sigreturn`） | ✅ 落實 |
| rop P2-8 | `wp/99` §1 補 Partial RELRO 一列 | `wp/99_速查表.md:19` | 讀檔（pwn2/3/4/6 = Partial） | ✅ 落實 |
| wp00 §1~§17 | 11 條已修 + 11 條已補 | `wp/00`（1197 行） | 逐條抽驗（見第 3 節 wp/00） | ✅ 全部落實 |
| fmtstr W1 / rop P0-2~P0-4 等「略過」項 | 轉入 3 份 `pending_wp00_*.md`，由 wp00 agent 套用 | `wp/00` §2、§9、§11.4、§12 | grep + 實測（pacman 套件、DEBUG 參數） | ✅ 已由 wp00 agent 套用 |

### 1.1 三點必須註明的「查核限制」（不是不符，是無法驗證）

1. **沒有 git**：`fixes_round2_*.md` 中「`pwnN/exploit.py` 只改註解、程式邏輯沒動」這類宣稱
   無法用 diff 證明。我只能做行為驗證：14 次實測（7 題 × local/REMOTE）全部 PASS，
   且輸出的 payload 內容與 notes 描述一致 → 邏輯沒被改壞。
2. **`fixes_round2_heap.md` 說「340 條引用中 0 條位址／運算元錯誤」**：
   我寫了比對腳本把 notes 裡每一行「以 16 進位位址開頭」的組語抓出來跟 `objdump` 逐字比。
   結果是 **333 行逐字相同 + 7 行差異**，而那 7 行差異全部是**格式差異**，不是錯誤：
   `call fgets@plt`（notes 用符號名）vs `call 401170`（objdump 印數字）、
   `[rbp+rax*8]` vs `[rbp+rax*8+0x0]`、以及 2 行是中文敘述（`(建構子起點) setvbuf(…)`、
   `(同一支) setvbuf(…)`——這兩行下方已各自標了「呼叫在 0x4012c8 / 0x4012e1」，我實測
   `0x4012c8: call setvbuf@plt`、`0x4012e1: jmp setvbuf@plt` 都正確）。
   ⇒ **「0 條真錯」成立**，只是行數統計口徑與我不同。
3. **「重現性」有環境相依**：`pwn7/exploit_input.bin` 這類固定輸入流**沒有**被本次審查改動，
   但我在 pwn5 發現它的「金絲雀」已過期（見第 3 節 pwn5），**幸好筆記自己已經寫明這件事**。

---

## 2. 修改後新增的錯誤（清單，每條附驗證指令）

> 我把「本輪新增」與「沿襲、本輪未抓到」分開標，因為責任歸屬不同。
> 嚴重度：高＝會直接讓人做錯事；低＝位址/措辭不精確。

### 2.1 【高】pwn1：「唯一『syscall 後面接 ret』的位置」是錯的

* **位置**：`pwn1/notes.md:380-382` 的組語註解 + `pwn1/notes.md:387-389` 的正文 +
  `pwn1/exploit.py:58-59` 的常數註解。
  原文：「`0x401069: syscall; ret   ← 唯一「syscall 後面接 ret」的位置（其他 3 條 syscall 後面都不是 ret）`」
  「所以只有 `0x401069` 有用」。
* **為什麼錯**：`0x40104c: syscall` 的下一條就是 `0x40104e: ret`（`0f 05 c3`），
  所以「`syscall; ret`」有**兩個**位置。SROP 的 frame 可以直接把 `rip` 設成 `0x40104c`
  （不需要執行前面的 `mov rax,0`），它是完全可用的 gadget。
* **驗證指令**（我在本機跑過）：
  ```bash
  cd pwn1
  objdump -d -M intel challenge | grep -A1 syscall     # → 會看到 2 個 syscall 後面接 ret
  objdump -d -M intel challenge | grep -c syscall      # → 4（「全檔 4 條 syscall」這句是對的）
  ```
  輸出（節錄）：
  ```
  40104c: 0f 05      syscall
  40104e: c3         ret          ← 這裡也是 syscall; ret
  ...
  401069: 0f 05      syscall
  40106b: c3         ret
  ```
* **責任歸屬**：**不是本輪新增**。這句是第 1 輪 `review_round1.md` E7 的「建議改法」原文，
  第 1 輪套用後，第 2 輪的 `review_round2_stack.md:252` 還把它標成「**已正確修好**」並被
  `fixes_round2_stack.md` 接受 ⇒ **本輪（第 3 輪）複驗判定為仍然錯誤**。
* **修正建議**：把「唯一」改成「**本題用的是 `0x401069`**（另一個 `syscall; ret` 在
  `0x40104c`/`0x40104e`，跳進去時 `rax` 由前一條 `mov rax,0` 決定，兩者都可用，
  但 `0x401069` 是 `vuln` 裡緊跟在 `mov rax,0` 之後、最直觀的那個）」；
  並且**不要**再寫「其他 3 條 syscall 後面都不是 ret」。

### 2.2 【低】wp/00 §11.4（本輪新增的表格）把 `rt_sigframe` 說成「約 `0xf8` bytes」

* **位置**：`wp/00_基礎知識_從零開始.md` §11.4 名詞表第 1 列
  （同一句話在 `pwn1/notes.md:406` 也有）。
* **為什麼是錯的**：`0xf8`（248）是 **pwntools `SigreturnFrame()` 的長度**，
  也就是「我們要寫上堆疊的那 `0xf8` bytes」；核心真正的 `struct rt_sigframe`
  還包含 `siginfo`（≥ 0x80 bytes）與 `pretcode`，實際大小約 `0x1a8` 以上。
* **驗證指令**：
  ```bash
  python3 -c "from pwn import *; context.clear(arch='amd64'); print(len(bytes(SigreturnFrame())))"
  # → 248 = 0xf8（pwntools 的 frame）
  ```
  ⇒ 表格第 1 列若寫「`rt_sigframe`（≈0xf8）」，會讓新手以為「核心放的整包只有 0xf8」；
  建議改成「`rt_sigframe`：核心在堆疊上放的整包（含 `siginfo`）；**我們只需要其中
  `0xf8` bytes 的 `ucontext`/`sigcontext` 部分，也就是 pwntools 的 `SigreturnFrame()`**」。
* **責任歸屬**：**本輪新增**（`fixes_round2_wp00.md` §8「已補：四名詞表」）。

### 2.3 【低】wp/00 §12 的 `python3 exploit.py DEBUG` 在本系列腳本上不會生效

* **位置**：`wp/00_基礎知識_從零開始.md` §12（`python3 exploit.py DEBUG  # pwntools 除錯模式（印出每一次 send/recv）`）。
* **機制本身是對的**（我實測 `args.DEBUG` 會把 `context.log_level` 設成 10），
  **但本系列 7 支 exploit 裡有 6 支在 `from pwn import *` 之後又寫死
  `context.log_level = 'info'`**，把 `DEBUG` 的效果蓋掉，所以照著跑看不到任何 debug 輸出。
* **驗證指令**：
  ```bash
  grep -n "context.log_level" pwn*/exploit.py
  # pwn1/exploit.py:51  pwn2:42  pwn3:50  pwn5:21  pwn6:26  pwn7:68 → 都是寫死 'info'
  # pwn4/exploit.py:35 → 'debug' if VERBOSE else 'info'（唯一吃命令列旗標的）
  DEBUG=1 python3 pwn1/exploit.py      # 沒有 debug 輸出（這句「沒用」是對的）
  python3 pwn1/exploit.py DEBUG        # 也沒有 debug 輸出（因為腳本自己覆蓋了 log_level）
  ```
  建議補一句「**本系列的腳本自己會設 `log_level='info'`；要看 debug 輸出請自己把那行
  改成 `'debug'`（或跑 pwn4 的 `VERBOSE`）**」。
* **責任歸屬**：**本輪新增**（`fixes_round2_wp00.md` §3）。

### 2.4 【低】pwn5 兩個組語清單的位址「差 2」

* **位置 1**：`pwn5/notes.md` §4（`;; epilogue @ 1a69` 那塊）
  ```
  1a74: 74 05                  je     1a7d          ← 實際位址是 0x1a76
  1a76: e8 33 f6 ff ff         call   10b0 <__stack_chk_fail@plt>   ← 實際位址是 0x1a78
  ```
* **位置 2**：`pwn5/notes.md` §4（`append()` 清單）
  ```
  176d: 48 89 45 f8            mov    [rbp-0x8],rax  ← 實際位址是 0x176f
  ```
* **原因**：那兩條 `mov rax,QWORD PTR fs:0x28` 是 8 bytes，objdump 會把最後 2 bytes
  印在「續行」上並標上 `1a74:` / `176d:`，作者抄到了續行的位址。
* **驗證指令**：
  ```bash
  cd pwn5
  objdump -d -M intel --start-address=0x1a69 --stop-address=0x1a80 homemaker
  #  1a6d: 64 48 2b 04 25 28 00  sub rax,QWORD PTR fs:0x28
  #  1a74: 00 00                       ← 續行
  #  1a76: 74 05                  je   1a7d        ★
  #  1a78: e8 33 f6 ff ff         call 10b0 <__stack_chk_fail@plt>   ★
  objdump -d -M intel --start-address=0x1766 --stop-address=0x1775 homemaker
  #  1766: 64 48 8b 04 25 28 00  mov rax,QWORD PTR fs:0x28
  #  176d: 00 00
  #  176f: 48 89 45 f8           mov QWORD PTR [rbp-0x8],rax   ★
  ```
  影響：讀者若照抄 `b *0x1a74` / `b *0x176d` 會停在指令中間（gdb 會顯示
  那個位址落在 `sub`/`mov` 的尾巴上），是「照著做卻對不上」的典型症狀。
* **責任歸屬**：**沿襲、本輪未抓到**（這兩塊清單不是本輪新增的內容，
  `fixes_round2_rop_foundations.md` 也沒宣稱改過它們）。

### 2.5 【低】pwn7 §4.1 組語清單 `40179c: call open@plt` 的位址

* **位置**：`pwn7/notes.md:429-433`
  ```
  40179c:  call open@plt     ; 開 /dev/null      ← 實際 0x40179c 是 mov rdi,rbp
  ```
* **驗證指令**：
  ```bash
  cd pwn7
  objdump -d -M intel --start-address=0x40178e --stop-address=0x4017b2 service
  #  401795: be 02 00 00 00   mov esi,0x2
  #  40179a: 31 c0            xor eax,eax
  #  40179c: 48 89 ef         mov rdi,rbp      ← 筆記寫成 call open@plt
  #  40179f: e8 …             call 401260 <open@plt>   ★ 這才是 call
  ```
  同區塊其它列（`40178e` lea、`4017a4` xor esi、`4017a8` mov edi,eax、`4017aa`/`4017bd` call dup2、
  `4017c2`/`4017c7` signal 參數）我逐條對過 objdump，**都正確**。
* **責任歸屬**：**沿襲、本輪未抓到**（第 2 輪只改了「迴圈那 3 個槽」的敘述）。

### 2.6 【低，純敘述】pwn3 兩處標籤與 §7.2 圖的一格

* `pwn3/notes.md:251`：`40114d: (fallthrough 回 0x40114f)`——`0x40114a` 的 `call write@plt`
  是 5 bytes，fallthrough 是 **`0x40114f`**，標成 `0x40114d` 會讓人以為 `0x40114d` 是執行點。
* `pwn3/notes.md:728`（§7.2 堆疊圖）：
  `buf-0x18 │ printf 保存的 r14 / r13 / r12 / rbp`——這四個其實各佔一格
  （`buf-0x18`=r14、`-0x20`=r13、`-0x28`=r12、`-0x30`=rbp）。**同一節下面的表（:742-750）是正確的**，
  所以只是圖上壓縮成一格、沒有標範圍。建議補成 `buf-0x18 ~ buf-0x30`。
* 驗證指令：`objdump -d -M intel --start-address=0x401148 --stop-address=0x401150 revolution`
  （`0x40114a` call 後下一條是 `0x40114f`）；其餘見第 3 節 pwn3 的 gdb 證據。
* **責任歸屬**：**沿襲、本輪未抓到**（`fixes_round2_fmtstr.md` F1 只改 §7.2 的 `rbx` 那一格，
  那一格**現在是對的**：`buf-0x38`）。

> **總結第 2 節：真正會讓人做錯事的只有 2.1 一條（高）。**
> 其餘 5 條是位址複製錯誤或措辭不精確，都不影響 exploit 能不能打。

---

## 3. 高風險項逐條複驗結果

### pwn1 `total_recall`（SROP）— **複驗通過（1 條高風險錯誤，見 2.1）**

| 待驗項 | 我怎麼驗 | 結果 |
|---|---|---|
| 「3 次 read、3 次 send」表 | `grep -n "p\.send" pwn1/exploit.py` → 86/122/130（第 1 次 `b"A"*0x18`、第 2 次 payload、第 3 次 15 bytes） | ✅ 與 §6 的表一致 |
| `0x40106b` 的 `[rsp]` | 用 notes 的 7 中斷點腳本，餵「完整 payload」與「只餵 24 bytes」各一次 | ✅ 分別是 `0x40104f` / `0x40100a`，與表格兩列完全相符 |
| SigreturnFrame 位移表 | pwntools `_regs` 索引 ×8 對照 | ✅ `rdi=0x68`、`rax=0x90`、`rsp=0xa0`、`rip=0xa8`、`err=0xc0`、總長 `0xf8`；`csgsfs` 在 `0xb8`、佔 8 bytes（`cs=0x33`、`gs=fs=0`，實測 `33 00 00 00 00 00 00 00`） |
| 「4 條 syscall」 | `objdump \| grep -c syscall` → 4；位址 0x401014/0x40102f/0x40104c/0x401069 全對 | ✅ 但同一段的「唯一 syscall;ret」**錯**（2.1） |
| `buf + 0x08`（第二次 read 的終點） | gdb：第二次進 `0x40104f` 時 `rsp=0x7fffffffdf20`、`rsi=0x7fffffffdea0`（= `rsp-0x80` = `buf+0x08`，`buf=0x7fffffffdf18`） | ✅ |
| SigreturnFrame 落點 `rsp = buf+0x90` | 單步：`0x401069` syscall 前 `rsp=0x7fffffffdf20+8=df28`，`buf=de98` ⇒ 差 `0x90` | ✅ |

### pwn2 `mad_libs`（Format String）— **複驗通過**

* **`%17$hhn` 不貢獻 `%n` 計數（E1）**：我**自己寫了一個獨立實驗**（不是照抄筆記的腳本）：
  洩漏 PIE base → 送 `b'%64c%17$hhn'.ljust(72,b'a') + p64(.bss 內可寫位址)`
  → 用 `/proc/<pid>/mem` 讀回 → **`0x40`（64）**，不是 `0x47`（71）。✅
  同一支腳本先送 `b'%17$p'.ljust(72)+p64(0xdeadbeefcafe)`，印出 `0xdeadbeefcafe`
  ⇒ 也順帶證明「第一個位址落在 `buf[72]` → 參數 17」的推導（E4）。✅
* **`write_size` / `write_size_max`（E3）**：`inspect.signature(fmtstr_payload)` 顯示
  `write_size_max='long'`（預設）；同一位址用預設 vs `write_size_max='byte'`
  → 96 bytes（`%1097c%19$hn` 合併）vs 112 bytes（6 個 `%hhn`）。✅ 與 notes §3.4/§7 及
  `exploit.py` docstring 的描述**完全一致**。
* **notes 與 `exploit.py` 實跑一致**：實跑 local → `write payload (112 bytes) … 6 個 %hhn`；
  remote → `write payload (96 bytes) … %2663c%19$hn`。兩者都落在 notes 列的變體集合內
  （notes 已明講「不固定、只是範例之一」）。✅
* **GOT 真的被改（鐵證）**：把 notes §5 的自檢腳本**逐字抽出**執行
  → `printf@GOT before = libc+0x600f0`、`after = libc+0x58740`、`match=True`、
  且 `echo SHELL_OK; id` 有回應。✅
* 附註（不算錯誤）：notes:509 說「最近跑的兩次都剛好是 112 bytes、6 個 `%hhn`」，
  我這次 remote 抽到 96 bytes 的 `%19$hn` 變體——該句是「某次實測」的敘述，且同節已強調不固定。

### pwn3 `revolution`（自製 printf）— **複驗通過（僅 2.6 的敘述小瑕）**

* **`rbx` 保存格 = `buf-0x38`（F1）**：`objdump` 顯示 6 個 `push`（r15/r14/r13/r12/rbp/rbx）
  共 `0x30`，rbx 最後 push ⇒ `[rbp-0x38]`；gdb 實測 `$rbp=0x7fffffffddd0`、
  `x/1gx $rsp+0xe8` = `0x7fffffffdba8` = `0x00007fffffffdbe0` = `buf`。✅
* **可執行 gdb recipe（F2）**：`printf '%%6$p\n' > /tmp/rev_in` + 那串 `-ex`
  **逐字複製**執行，輸出與 notes:321-327 完全一樣（`$1=0x7fffffffdac0`、
  `$2=0x7fffffffdbe0`、`rdi=r15=buf`、`[rsp+0xe8]=buf`、`[rsp+0x120]='%6$p\0\0\0\0'`）。✅
* **`.init_array` / `.fini_array`（F3）**：`objdump -s` →
  `403dc0: b0124000 00000000 90114000 00000000`（= 0x4012b0、0x401190）、
  `403dd0: 80124000`（= 0x401280）；反組譯確認 `0x401190` = `setvbuf(stdout/stderr, …, 2)`、
  `0x4012b0` = `frame_dummy`、`0x401280` = `__do_global_dtors_aux`。✅
* **`va_list.overflow_arg_area`（N2/§4.1）**：`0x4013ca: mov [rsp+0x20],rax`（rax = `rsp+0x120`）
  + gdb 證明 `rsp+0x120 == rdi == r15 == buf`，於是「第 N 個參數 = `*(u64*)(buf+8*(N-6))`」。✅
  另外獨立跑了 §5 的 marker 腳本，輸出與筆記逐字相同
  （`arg6 = 0x0000000070243625`、`scan = …|0x4242424241414141|0x4444444443434343`）。✅

### pwn4 `cache_money`（tcache poisoning）— **複驗通過**

* **`read_int` 的 EOF 語意（E3）**：`objdump` → `40155c: je 401590` / `401590: xor edi,edi` /
  `401592: call 4011e0 <exit@plt>` ⇒ **EOF → `exit(0)`**，不是回 -1。✅
* **`calloc` 參數順序（E5）**：`401620: mov esi,0x1` / `401625: mov edi,0x30` /
  `40162a: call calloc@plt` ⇒ `calloc(nmemb=0x30, size=1)` = 0x30 bytes。✅（notes 的敘述正確）
* **fastbin 深度（E1）**：把 notes 的 C 程式照抄編譯，用**題目附的 2.39 loader/libc** 跑：
  `glibc 2.39` / `freed 20 chunks of tcache-size 0x20: fastbin length=13` ✅（與 notes 逐字相同）
* **`entries[7] = 0x406970`（E2）**：用 notes B5 的輸入檔 + `gdb -ex 'b *0x401b21' ./cm_dbg`：
  `0x4050a0: 0x406930`（entries[2]）、`0x4050c8: 0x406970`（entries[7]）；
  chunk walk `0x406920 size=0x41`、`0x406960 size=0x91` ⇒ entries[7] 的標頭在 `0x406960`。✅
* **small bin 範圍（E9）**：`in_smallbin_range` 的定義（`MIN_LARGE_SIZE = 0x400`）實算：
  `0x3f0 → True`、`0x400 → False` ⇒ notes 的「`0x90 ~ 0x3f0`（< 0x400）」成立。✅
* **新貼的 objdump 原文（E6）**：自動比對 340 行 → **0 條真正的位址／運算元錯誤**
  （7 行是格式差異，已於 1.1 說明）。✅

### pwn5 `homemaker`（off-by-one → ROP）— **複驗通過（含 2 條位址小瑕，見 2.4）**

* **§7.1 ROP 鏈圖（P0-1）**：以 `exploit_input.bin` 重播（ASLR 關閉 → PIE = `0x555555554000`），
  在 `0x1a76` 印出堆疊：
  ```
  0x7fffffffddc8: 0xe4fbd8d3ee76a900   0x00007fffffffde60   ← canary / saved rbp
  0x7fffffffddd8: 0x000055555555501a   0x00005555555552aa   ← state[0x118]=ret / [0x120]=pop rdi;ret
  0x7fffffffdde8: 0x0000555555558a54   0x00005555555550c0   ← [0x128]="/bin/sh" / [0x130]=system@plt
  0x7fffffffddf8: 0x0000000000000000   0x0000000000000000   ← [0x138]=0
  ```
  ⇒ **與 §7.1 的圖逐格相符**（`PIE+0x101a` / `+0x12aa` / `+0x4a54` / `+0x10c0` / 0）。✅
  另外 `x/s 0x555555558a54` → `"/bin/sh"`，證明 `binsh = PIE+0x4a54` 不是抄錯。✅
* **`system` 入口 `rsp & 0xf == 8`**：單步追蹤（因輸入檔金絲雀已過期，先 `set $rip` 跳到 `0x1a7d`）：
  ```
  after leave : rsp=0x7fffffffddd8
  after ret   : rip=PIE+0x101a rsp=0x7fffffffdde0   ← chain[0] 對齊用 ret
  after ret2  : rip=PIE+0x12aa rsp=0x7fffffffdde8   ← chain[1] pop rdi; ret
  after pop   : rdi=0x555555558a54 rsp=0x7fffffffddf0
  after ret3  : rip=PIE+0x10c0 rsp=0x7fffffffddf8   ← system@plt，rsp&0xf = 8 ✅
  ```
  ⇒ 與 §6.3.1 的步驟表與 §5.3 的 `rsp&0xf=8` **完全一致**。✅
* **`rbp_main = rbp_service_loop + 0x20`（§4.11、§6.3 💡 塊）**：gdb 在 `0x1a9a`
  讀 `rbp_main=0x7fffffffddf0`，在 `0x1a76` 讀 `rbp=0x7fffffffddd0` ⇒ 差 **0x20** ✅
  （靜態推導也對：`sub rsp,0x10` + call 壓 8 + `push rbp` = 0x20）。
* **§5.3 的 gdb 證據**：把 `gdb_evidence.sh` 的 gdb 命令**逐字重跑**（只把輸出留在 stdout、
  不改寫 repo 檔）→ 四行 `@0x1797/@0x1810/@0x1a76` 與 8 個 qword **與 notes:836-843 完全相同**。✅
* **一個環境事實（筆記已自行揭露，不是錯誤）**：`exploit_input.bin` 內的金絲雀是舊的
  （本次 `fs:0x28=0x50e9e0e211e5e200`，檔案內是 `0xe4fbd8d3ee76a900`），
  所以「重播 + 繼續單步」會 `*** stack smashing detected ***`。**notes:850 已經寫明
  「`set $pc = base+0x1a7d` 強制跳過金絲雀比較，因為輸入檔的金絲雀是舊的」**，
  且 §5.3 只印到中斷點為止 ⇒ 讀者照做不會踩雷，**判定為已充分揭露**。

### pwn6 `code_breaker`（heap refcount → tcache poisoning）— **複驗通過**

* **§3.5 新補的 heap 最小語彙**：`tc_idx=(size-0x20)/0x10` ⇒ `0x90→7`、
  tcache 64 條（0x20~0x410、每條 7 塊）、fastbin ≤ 0x80 且**沒有 7 塊上限**、
  `PROTECT_PTR(pos,ptr)=pos>>12 ^ ptr` 且 `pos` 是 **user 位址**、`entries[]` 是**明文** —— 
  逐條與 glibc 2.39/2.44 行為一致，且與 `pwn4/notes.md` §5、`wp/99` §8 用語一致。✅
* **`P` = malloc user pointer**：`pwn6/notes.md:712` 定義、`:1144-1145` 再強調「標頭是 `P-0x10`，
  別拿去 XOR」、`:1200` 指路；`exploit.py:221` 的輸出字串是
  `victim P (malloc user ptr) = 0x…`（實跑訊息一致）。✅
* **`system` 的 stub 是 `0x1080`（E11）**：`readelf -rW` → `system@GLIBC_2.2.5` 在 `0x4028`
  = 第 6 個 JUMP_SLOT（index 5）⇒ stub = `0x1030+5*0x10 = 0x1080`；
  `objdump -d --section=.plt` 確認 `0x1080: push 0x5`；而 `0x1030` 是 `free`（index 0，`0x4000`）。✅
* **payload 長度 `00 47`（E10）**：`len(b'cat flag.txt … echo DONE')` = 70，`70+1 = 71 = 0x47`
  ⇒ big-endian 前綴 `00 47`，與 notes §6.4 的圖一致；實跑 log 也顯示同一條指令。✅
* **safe-linking gdb 實測（B8）**：把 §4.3 的 C 程式與 gdb 命令照抄重跑 →
  `P=0x55555555b2a0`、`P>>12=0x55555555b`、free#1 後 `next=0x000000055555555b`、
  double free 後 `next=0x000055500000e7fb`（= `P ^ (P>>12)`，我自行驗算相符）；
  `key` 每次不同（本次 `0x6c83d638a23db0a6` vs 筆記 `0x8885eebd61c58fb7`）
  ——**筆記已明講 key 是隨機的**。✅
* **`FLAG.txt` 保護（E15）**：跑 local →
  `[*] local test flag -> FLAG.txt left untouched`；
  跑完 remote 後 `pwn6/FLAG.txt` = `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}`。✅
  （順帶確認 pwn4 也有同樣的保護：`pwn4/exploit.py:220` 的 `if flag != 'sun{LOCAL_TEST_FLAG}'`。）

### pwn7 `service`（負 fd / seccomp）— **複驗通過（僅 2.5 的位址小瑕）**

* **§7「照抄就能跑」的完整片段（B1）**：我用腳本**逐字抽出** notes 中 §7 的第一個 ```python
  區塊（第 771~838 行，67 行）存成檔案直接跑：
  ```
  b'OK\nSUNSHINE{local_test_flag}\n\n'
  ```
  ⇒ **可跑、且直接印出 flag**（最後的 SIGSEGV 是設計上必然，§8 已說明）。✅
* **§4.1 四個 `state=2` 槽（E1）**：
  `objdump` → `4017f8: xor esi,esi / mov rdi,rbp / add rbx,0x40c / mov [rbx],0x2 / call open /
  mov [rbx+4],eax / cmp rbx,r12 / jne 4017f8`（**先寫槽、後比較**）；
  gdb（`follow-fork-mode child`）→
  ```
  @4017cc rbx=0x405080 r12=0x405ca4
  [loop open] rdi=0x40306f "/dev/null"  writing slot=0x40548c / 0x405898 / 0x405ca4
  slot0 0x405080 state=2 fd=5 | 0x40548c state=2 | 0x405898 state=2 | 0x405ca4 state=2 | 0x4060b0 state=0
  ```
  ⇒ 3 次 `/dev/null`、共 4 個 `state=2`、只有 `0x405080` 是 flag fd、槽表基底 `0x4060b0` 仍是 0。✅
  字串位址亦確認：`.rodata` `0x40306f`=`"/dev/null"`、`0x403079`=`"flag.txt"`。✅
* **`rax = 3` 的洩漏大小解釋**：`objdump --start-address=0x401f07`：
  ```
  401f07: xor edi,edi ; 401f09: movzx edx,bl ; 401f0c: mov rsi,rsp ; 401f0f: call read
  401f14: test rax,rax ; 401f17: jle 401f2f
  401f19: mov edx,0x3 ; lea rsi,[rip+0x110b]("OK\n") ; mov edi,0x1 ; call write   ← rax = 3
  401f2f: add rsp,0x40 ; 401f33: pop rbx ; 401f34: ret
  ```
  ⇒ `write(1,"OK\n",3)` 之後**沒有任何指令動 `rax`**，所以鏈的第一個 `WRITE_RDX_RAX`
  執行時 `rax = 3` ⇒ `rdx = 3` ⇒ 兩次 `write` 各 3 bytes = 6 bytes 的 key 洩漏
  （與 `exploit.py` 的 `recvn(6)` 一致）。✅
  同時驗證 B8「read 目標 `+0x40` = 下一個 `rbx`、`+0x48` = 鏈的第 0 個 qword」：`add rsp,0x40; pop rbx; ret` ✅
* **§9 #3 的尾呼叫（E4）**：`0x401f38: add rsp,0x40 ; mov edx,0xd ; mov edi,0x1 ;
  lea rsi,[rip+0x10d1]("ERR bad size\n") ; pop rbx ; jmp 401190 <write@plt>` ⇒ 是 `jmp` 不是 `ret`。✅
* **§6「三個片段」**：表內 0x401f07 / 0x401fda / 0x401c32；
  0x401c32 = `mov rdx,rax ; jmp 401190 <write@plt>` ✅；三個常數與 `exploit.py` 完全一致。✅

### wp/00 從零教學 — **複驗通過（含 2 條低風險項，見 2.2 / 2.3）**

* **§6.3 堆疊圖 + canary offset 規則**：我寫了 4 個函式（`char buf[0x10/0x20/0x30/0x40]`）
  用 `gcc -O0 -fstack-protector` 編譯再看 `objdump`：
  `sub rsp,0x20/0x30/0x40/0x50`、`buf` 落在 `rbp-0x20/-0x30/-0x40/-0x50`
  ⇒ 表格四列**全部相符**；`buf[0x30]` 的 canary offset `0x38`、返回位址 `0x48` 也對。✅
  圖的順序（canary 在 `rbp-0x8`、buf 在 `rbp-0x40`）正確。✅
* **§4.3.1 libc base + offset**：`readelf -sW pwn2/libc.so.6` → `system@@ = 0x58740`、
  `printf@@ = 0x600f0`；`next(libc.search(b'/bin/sh')) = 0x1cb42f`；本機 Arch libc 2.44
  → `0x54580` / `0x5b6f0` ⇒ 表格兩個版本**全部正確**。✅
* **pwn6 三處修正**：§9 表已新增 `Reference count bug` 列並把 pwn6 從
  `Missing bounds check`、`Uninitialised memory` 移除（`Missing bounds check` 列改註明「本系列沒有直接例子」）；
  `Stack Buffer Overflow` 列已補 pwn5；附錄 pwn6 核心技巧 = heap refcount → double free + UAF
  → tcache poisoning → 覆寫 `.bss` 函式指標 → `system()`（不需 ROP）。✅
* **pwn3 `va_list` 修正**：§9/§9.2/附錄都改成「`va_list.overflow_arg_area` 指向輸入緩衝區 →
  `%N$s`/`%N$w` 任意讀寫 → `strcspn@got` 覆寫成 `system`」，並加上「`.bss`/`memcpy` 是假線索」註記。✅
* **安裝指令**：`pacman -Ss` 實查 → `extra/python-pwntools 4.15.0-2`、`extra/ropgadget 7.7-1`、
  `extra/ropper 1.13.13-2`、`extra/python-pipx 1.15.0-1` 全部存在，與文件寫的套件名一致。✅
* **`python3 exploit.py DEBUG`**：機制驗證 `args.DEBUG → log_level=10`、
  `DEBUG=1` 環境變數無效（`log_level=20`）⇒ 「`DEBUG=1` 沒用」這句是對的；
  但本系列腳本會覆蓋 `log_level`（見 2.3）。⚠️

---

## 4. 7 題最終實測（local + REMOTE 各一次）

執行方式：各題目錄下 `python3 exploit.py` 與 `python3 exploit.py REMOTE PORT=<port>`，
`wp/run_all.sh` 的 port 對照。

| 題目 | local | REMOTE | 拿到的 flag | PASS/FAIL |
|---|---|---|---|---|
| pwn1 `total_recall` | ✅ | ✅ | local: `sun{LOCAL_DUMMY_FLAG}` / remote: `sun{r3caLl_ev3Ry_reGist3r_sR0p}` | **PASS** |
| pwn2 `mad_libs` | ✅ | ✅ | local: `sun{LOCAL_DUMMY_FLAG}` / remote: `sun{f1ll_iN_th3_g0T_eNtry}` | **PASS** |
| pwn3 `revolution` | ✅ | ✅ | local: `sun{LOCAL_TEST_FLAG}` / remote: `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}` | **PASS** |
| pwn4 `cache_money` | ✅ | ✅ | local: `sun{LOCAL_TEST_FLAG}` / remote: `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` | **PASS** |
| pwn5 `homemaker` | ✅ | ✅ | local: `sun{LOCAL_DUMMY_FLAG}` / remote: `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}` | **PASS** |
| pwn6 `code_breaker` | ✅ | ✅ | local: `sun{local_test_flag}` / remote: `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` | **PASS** |
| pwn7 `service` | ✅ | ✅ | local: `SUNSHINE{local_test_flag}` / remote: `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` | **PASS** |

* **14/14 PASS**（7 題 × 2 模式）。local 的「假 flag」與各題 `flag.txt` 內容一致，
  remote 的 flag 與各題 `FLAG.txt` 內容一致。
* 跑完後 `FLAG.txt` 仍是**真正的遠端 flag**（pwn6 會印 `FLAG.txt left untouched`，
  pwn4 有同款保護 `if flag != 'sun{LOCAL_TEST_FLAG}'`）⇒ **本輪回歸測試沒有污染任何 flag 檔**。
* pwn7 的 local 收尾是 `SIGSEGV`（`Process './service' stopped with exit code -11`），
  這是設計上必然（seccomp 只允許 read/write/exit，§8 有說明），**不是 FAIL**。

---

## 5. 最終判定

### 5.1 評分：**9 / 10**

理由：

* **正面**：我把 5 份 changelog 的每一條（約 60 條）都對到現況檔並獨立重驗，
  **0 條未落實、0 條改錯方向**；高風險的 8 個區塊（pwn1 表格/SigreturnFrame、
  pwn2 `%hhn` 計數與 `write_size_max`、pwn3 `buf-0x38` 與可跑 gdb recipe、
  pwn4 EOF/calloc/fastbin/entries[7]、pwn5 ROP 鏈與 16-byte 對齊、pwn6 heap 語彙與
  `FLAG.txt` 保護、pwn7 §7 可跑片段與 4 個 fd 槽、wp/00 §6.3 與 libc+offset）
  **全部通過**，其中 5 項是我用**自己寫的實驗**（`/proc/<pid>/mem` 直讀、gcc 編譯對照、
  gdb 單步）證明的，不是照抄筆記數字。7 題 14 次實測全 PASS。
* **扣 1 分**：仍有一條**會誤導新手的高風險錯誤**（2.1 pwn1「唯一 `syscall; ret`」）
  ——它剛好是第 2 輪審查明確標成「已正確修好」的項目，代表**這一類「用一句『唯一/只有』
  下結論的句子」是這份 write-up 的系統性弱點**；另外 5 條低風險位址/措辭問題
  （2.2~2.6）都是「照著做會對不上」的類型，累積起來讓它拿不到 10 分。

### 5.2 還剩哪些「會誤導新手」的內容

| 優先序 | 位置 | 症狀 | 建議一句話修法 |
|---|---|---|---|
| **1（必改）** | `pwn1/notes.md:381,387-389`、`pwn1/exploit.py:58-59` | 以為只有 `0x401069` 能當 `syscall; ret`；實際上 `0x40104c/0x40104e` 也是。用 `objdump -d -M intel challenge \| grep -A1 syscall` 一秒就被打臉 | 拿掉「唯一」與「其他 3 條後面都不是 ret」，改成「本題用 `0x401069`；`0x40104c` 也算 `syscall; ret`，只是它的 `rax` 由前面那條 `mov rax,0` 決定」 |
| 2 | `wp/00` §11.4、`pwn1/notes.md:406` | 以為核心放的整包就是 `0xf8`；實際 `0xf8` 是 pwntools frame（=我們要寫上堆疊的部分） | 註明「`0xf8` 是 `SigreturnFrame()` 的長度；核心的 `rt_sigframe` 還含 `siginfo`」 |
| 3 | `wp/00` §12 | 照著跑 `python3 exploit.py DEBUG` 卻沒有 debug 輸出（因為本系列腳本自己覆蓋 `log_level`） | 補一句「本系列腳本寫死 `log_level='info'`，要看 debug 請自己改成 `'debug'`」 |
| 4 | `pwn5/notes.md` §4（epilogue 與 append 兩塊） | `b *0x1a74` / `b *0x176d` 會停在指令中間 | 位址改成 `0x1a76` / `0x1a78` / `0x176f` |
| 5 | `pwn7/notes.md:433` | `b *0x40179c` 想斷在 `call open@plt`，實際 `0x40179c` 是 `mov rdi,rbp` | 改成 `0x40179f`（或直接 `b *0x40179f`） |
| 6 | `pwn3/notes.md:251,728` | `40114d` 不是 fallthrough 點（應為 `40114f`）；§7.2 圖把 r14/r13/r12/rbp 壓成一格 | 修標籤與圖上的範圍（表本身是對的） |

> 以上 6 條都不影響任何一題的 exploit（14 次實測全 PASS），
> 但第 1 條建議在最終交付前務必修掉——它正好落在「新手會照著學 gadget 觀念」的位置。
