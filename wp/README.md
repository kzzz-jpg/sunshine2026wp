# Sunshine CTF — pwn 全 7 題 Write-up（從零開始版）

> 這份 write-up 是為**沒學過 pwn、沒寫過 exploit、沒聽過 ROP/SROP** 的人寫的。
> 每一題都會從「這行組語在幹嘛」開始講，一路講到完整的 exploit。
>
> 遠端：`chal.sunshinectf.games`

---

## 🏁 成果總表（全部已取得真實 flag）

| # | 題目 | 檔案 | port | 保護機制 | 核心技巧 | Flag |
|---|---|---|---|---|---|---|
| 1 | **total_recall** | `pwn1/challenge` | 26003 | 靜態、non-PIE、**NX off**、無 canary、stripped、純組語 (108 bytes) | Stack Overflow → **SROP** | `sun{r3caLl_ev3Ry_reGist3r_sR0p}` |
| 2 | **mad_libs** | `pwn2/mad_libs` | 26001 | PIE、canary、NX、Partial RELRO | **Format String** → `printf@GOT` 覆寫成 `system` | `sun{f1ll_iN_th3_g0T_eNtry}` |
| 3 | **revolution** | `pwn3/revolution` | 26002 | non-PIE、無 canary、NX、Partial RELRO | 自製 printf 的 `va_list` 別名問題 → 任意讀 + 任意 8-byte 寫 → `strcspn@GOT` 覆寫 | `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}` |
| 4 | **cache_money** | `pwn4/cache_money` | 26004 | non-PIE、canary、NX、Partial RELRO | **Heap UAF + Double Free** → tcache poisoning（繞 safe-linking）→ `strtol@GOT` 覆寫 | `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` |
| 5 | **homemaker** | `pwn5/homemaker` | 26008 | PIE、canary、NX、**Full RELRO** | Off-by-one 改大容量 → 洩漏堆疊 → **ROP**（`pop rdi; ret` + `system@plt`） | `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}` |
| 6 | **code_breaker** | `pwn6/code_breaker` | 26005 | PIE、canary、NX、Partial RELRO | **Heap Double Free + UAF** → tcache poisoning → 覆寫全域函式指標 | `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` |
| 7 | **SafeHouse** | `pwn7/service` | 26007 | non-PIE、無 canary、NX、Full RELRO、**seccomp** | Stack pivot + 偽造 IPC 封包 + **負索引越界** | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` |

> 上表的 **port** 與各題 `exploit.py`、`run_all.sh` 的設定一致；
> **保護機制**是逐題用 `checksec --file=./pwnN/<binary>`（或
> `python3 -c "from pwn import *; print(ELF('./pwnN/<binary>',checksec=False).checksec())"`）實跑出來的；
> **Flag** 與 `pwnN/FLAG.txt` 逐字相同（7 題全部都是遠端實打到的真 flag），
> 每一題也都能用 `wp/run_all.sh pwnN` 重跑一次拿到同樣的結果。

---

## 📚 閱讀順序（強烈建議照這個順序）

```
1. wp/00_基礎知識_從零開始.md      ← 先讀這個。暫存器、組語、堆疊、PLT/GOT、ROP、SROP 全部從零教
2. pwn1/notes.md                   ← 最完整的單題教學（SROP）。所有後續題目都引用這裡的觀念
3. pwn2/notes.md                   ← Format String 從零教（%p / %N$p / %n / %hn）
4. pwn3/notes.md                   ← 更難的 format string（自製 printf、va_list 佈局）
5. pwn4/notes.md                   ← glibc heap 從零教（chunk / tcache / safe-linking / UAF / double free）
6. pwn5/notes.md                   ← PIE + canary + Full RELRO 下的完整 ROP
7. pwn6/notes.md                   ← heap + 自製 RPC 協定 + 覆寫函式指標
8. pwn7/notes.md                   ← seccomp、stack pivot、偽造二進位封包、有號數邊界檢查
9. wp/99_速查表.md                 ← 解題時放旁邊查
```

---

## 📁 檔案結構

```
sunshine/
├── wp/                                    ← 教學與審查文件全部在這裡
│   ├── README.md                          ← 你現在看的這份（索引）
│   ├── 00_基礎知識_從零開始.md              ← 從零教學（暫存器/組語/堆疊/ROP/SROP/pwntools/gdb）
│   ├── 99_速查表.md                        ← 速查表
│   ├── 00_recon.md                        ← 7 題清單／port／保護機制速查
│   ├── run_all.sh                         ← 一鍵重跑全部 7 題（打遠端）
│   ├── review_round1.md                   ← 第 1 輪審查報告
│   ├── review_round2_*.md                 ← 第 2 輪審查報告（依主題拆檔）
│   ├── review_round3_*.md                 ← 第 3 輪審查報告（依主題拆檔）
│   ├── fixes_round1_applied.md            ← 第 1 輪修正紀錄
│   ├── fixes_round2_*.md                  ← 第 2 輪修正紀錄（依主題拆檔）
│   └── pending_wp00_fixes_*.md            ← 第 2 輪回報、待套用到 `wp/00` 的項目（已套用完畢）
│
├── pwn1/  challenge  exploit.py  notes.md  FLAG.txt  flag.txt  web_migurimental.tar.gz
├── pwn2/  mad_libs  exploit.py  selfcheck.py  notes.md  FLAG.txt  flag.txt  NOTES_SUMMARY.txt
│          ld-linux-x86-64.so.2  libc.so.6
├── pwn3/  revolution  exploit.py  notes.md  FLAG.txt  flag.txt  NOTES_SUMMARY.txt
│          rev.asm  local_run.log  remote_run.log  libc-2.39-0ubuntu8.3.so.6
├── pwn4/  cache_money  exploit.py  notes.md  FLAG.txt  flag.txt  NOTES_SUMMARY.txt
│          dis.txt  cm_dbg  ld-linux-x86-64.so.2  libc.so.6  work/
├── pwn5/  homemaker  exploit.py  notes.md  FLAG.txt  flag.txt  NOTES_SUMMARY.txt
│          disasm.txt  gdb_evidence.sh  gdb_evidence.py  gdb_evidence_raw.txt
│          exploit_input.bin  remote_run.txt  scratch_leak.py
├── pwn6/  code_breaker  exploit.py  notes.md  FLAG.txt  flag.txt  NOTES_SUMMARY.txt
│          proto.py  cb.asm  cb_new.asm  ld-linux-x86-64.so.2  libc.so.6
└── pwn7/  service  exploit.py  notes.md  FLAG.txt  FLAG_REMOTE.txt  flag.txt  dis.txt
```

> 📌 **`*` 代表「一組同前綴的檔案」**，不是真的檔名。實際檔名請 `ls wp/`：
> 第 2 輪報告是 `review_round2_{stack,fmtstr,heap,rop_foundations}.md`，
> 第 3 輪報告是 `review_round3_{verification,cold_read,regression}.md`，
> 修正紀錄則是 `fixes_round2_{stack,fmtstr,heap,rop_foundations,wp00}.md`。
>
> 📌 各題目錄裡還有一些**解題過程的佐證檔**（`dis.txt` / `rev.asm` / `*.log` /
> `gdb_evidence*` / `cm_dbg` / `proto.py` / `NOTES_SUMMARY.txt` 等），
> 是筆記引用到的原始資料，新手可以完全不管它們。
>
> 📌 **兩種 flag 檔不要搞混**：
> * `flag.txt` = 題目附的假 flag（本機 `cat flag.txt` 測試用）
> * `FLAG.txt` = **遠端實打到的真 flag** —— 7 題**全部**都有，內容與上面成果總表的 Flag 欄逐字一致
>   （pwn7 另外留了第一次遠端連線的 `FLAG_REMOTE.txt`）

> 📌 **每一支 `exploit.py` 都支援兩種模式，而且不需要 TTY：**
> ```bash
> cd pwnN
> python3 exploit.py            # 打本地
> python3 exploit.py REMOTE     # 打 chal.sunshinectf.games:<port>
> ```

---

## ▶️ 一鍵驗證

`run_all.sh` 放在 `wp/` 底下，所以**要在 `wp/` 目錄裡**跑（或從專案根目錄用 `wp/run_all.sh`）：

```bash
cd wp                     # ← 一定要先進來（或改用 ./wp/run_all.sh）
./run_all.sh              # 跑全部 7 題
./run_all.sh pwn1 pwn4    # 只跑指定題目
```

每一題都會印出 `[+] FLAG: sun{...}`（`pwn6` 的輸出含二進位，若用 grep 請加 `-a`）。

---

## 🧭 三種主要技巧速覽

### A. 堆疊類（pwn1、pwn5、pwn7）

| 步驟 | 說明 |
|---|---|
| 1. 找漏洞 | `read(0, buf, 太大)` / 迴圈 off-by-one |
| 2. 處理 canary | 沒有 → 直接蓋返回位址；有 → 先 leak 或不碰它 |
| 3. 處理 PIE | 沒有 → gadget 位址寫死；有 → 先 leak 程式碼位址 |
| 4. 組鏈 | `pop rdi; ret` + 字串位址 + `system@plt` 或 `syscall` |
| 5. 特別情況 | 沒有 `pop rdi` → **SROP**；鏈太短 → **stack pivot**；有 seccomp → 不能用 `execve`，改「借別人的手」讀 flag |

### B. Format String 類（pwn2、pwn3）

| 步驟 | 說明 |
|---|---|
| 1. 找漏洞 | `printf(buf)` —— 把使用者輸入當格式字串 |
| 2. 定位參數 | 用 `%1$p %2$p ...` 掃描，找出自己的輸入是第幾個參數 |
| 3. 洩漏 | `%N$s`（任意位址讀）或直接 `%N$p`（堆疊上的 libc / canary / PIE） |
| 4. 寫入 | `%n` / `%hn` / `%hhn` + 把目標位址擺進 payload |
| 5. 劫持 | 把 `xxx@got` 改成 `system`，之後那個函式就變成執行 shell 指令 |

### C. Heap 類（pwn4、pwn6）

| 步驟 | 說明 |
|---|---|
| 1. 找漏洞 | `free` 之後沒清指標（UAF）、重複 `free`、size 檢查不一致 |
| 2. 看懂 tcache | glibc ≥ 2.26 的 per-size 單向 bin，LIFO，每 size 最多 7 個 |
| 3. 處理 safe-linking | glibc ≥ 2.32 的 `fd` 是 `stored = ptr ^ ((u64)&e->next >> 12)`（XOR key 用的是 **user 位址**，不是 chunk 標頭），要先 leak 才能反推 |
| 4. 投毒 | 用 UAF write 把 `fd` 改成目標位址，下一次 `malloc` 就回傳那個位址 |
| 5. 劫持 | 覆寫 GOT / 全域函式指標 / `__free_hook`（2.34 以後沒有 hook 了） |

---

## 📖 一次讀完整份（單一檔案版）

不想在目錄之間跳來跳去的話，這裡有一份把 `README` + `00_基礎知識` + 7 題筆記 + 速查表
合併起來的單一檔案（約 10,700 行）：

```
wp/SunshineCTF2025_pwn_完整writeup.md
```

---

## 🔍 三輪新手適用性審查

全部寫完之後，另外跑了 **3 輪獨立審查**，每一輪都由不同的審查者重新對 binary 驗證，
並由另一組人套用修正：

| 輪次 | 範圍 | 發現 | 修正紀錄 |
|---|---|---|---|
| 第 1 輪 | `wp/00`、`wp/99`、pwn1、pwn7 | 16 條錯誤（含 1 條會直接誤導新手的 `rax` 說明）＋ 18 個新手卡點 | `fixes_round1_applied.md`（16/16 已修） |
| 第 2 輪 | 全部 7 題筆記 + `wp/00` + `wp/99` + `README` | 約 51 條錯誤 ＋ 33 個新手卡點（依堆疊／format string／heap／ROP+基礎四份報告） | `fixes_round2_*.md`（全部套用） |
| 第 3 輪 | 端到端重現、冷讀模擬、回歸查核 | 21/21 遠端重現 PASS；1 條高風險殘留錯誤 ＋ 5 條小瑕疵；冷讀 7/10、回歸 9/10 | `fixes_round3_*.md`（全部套用） |

審查報告原文都保留在 `wp/review_round*.md`，修正紀錄在 `wp/fixes_round*.md`，
另外 `wp/pending_wp00_fixes_*.md` 是第 2 輪跨檔案的待辦清單（已套用完畢）。

> 💡 **為什麼要留著這些報告？**
> 因為它們同時也是很好的教材：裡面記錄了「哪些看起來很合理、其實是錯的」的推論
> （例如「glibc 的 `read`/`write` wrapper 會弄髒 `rdx`」是假的；
> 「`%17$hhn` 這幾個字元本身會增加 `%n` 的計數」也是假的）。
> 這些正是新手最容易自己騙自己的地方。

---

## ✅ 可重現性

每一支 exploit 都經過：
- 本地測試（含本地假 flag）
- 遠端實測（真實 flag）：`./wp/run_all.sh` → **7/7 全部印出真 flag**
- 多次重跑確認穩定（每一題至少 3 次）
- 7 個 `pwnN/FLAG.txt` 與文件中的 Flag 欄**逐字元比對一致**

所有記憶體位址、offset、gadget 位址**都是用 gdb / objdump 實際驗證過的**，
筆記裡附有可重跑的 gdb 腳本，不是憑空寫出來的數字。
