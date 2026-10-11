# Sunshine CTF 2025 — pwn 全 7 題（已完賽，全部取得真實 flag）

這份 repo 是一套**從零開始的 pwn 教學 write-up**：7 題全部打到遠端真實 flag，
並且把每一題「組語每一行在幹嘛、漏洞在哪、exploit 怎麼寫」都用繁體中文詳細寫出來，
目標讀者是**沒學過 ROP / SROP、沒寫過 exploit** 的人。

## 🏁 成果

| # | 題目 | port | 技巧 | Flag |
|---|---|---|---|---|
| 1 | total_recall | 26003 | Stack Overflow → **SROP** | `sun{r3caLl_ev3Ry_reGist3r_sR0p}` |
| 2 | mad_libs | 26001 | **Format String** → `printf@GOT` → `system` | `sun{f1ll_iN_th3_g0T_eNtry}` |
| 3 | revolution | 26002 | 自製 printf 的 `va_list` 別名 → 任意寫 | `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}` |
| 4 | cache_money | 26004 | **Heap UAF + Double Free** → tcache poisoning | `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` |
| 5 | homemaker | 26008 | Off-by-one → **ROP**（`pop rdi; ret` + `system@plt`） | `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}` |
| 6 | code_breaker | 26005 | Heap Double Free + UAF → 覆寫全域函式指標 | `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` |
| 7 | SafeHouse | 26007 | Stack pivot + 偽造 IPC ＋ **負索引越界**（seccomp 環境） | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` |

## 📖 從這裡開始

```
wp/README.md          ← 索引：閱讀順序、檔案結構、三種技巧速覽
wp/00_基礎知識_從零開始.md  ← 第一次接觸 pwn 就先讀這份（暫存器/組語/堆疊/PLT-GOT/ROP/SROP）
pwnN/notes.md         ← 每一題的完整教學（含逐行組語解說與 ASCII 記憶體圖）
wp/99_速查表.md        ← 解題時放旁邊查
wp/SunshineCTF2025_pwn_完整writeup.md  ← 上述全部合併成一個檔案（約 10,600 行）
SunshineCTF2025_pwn_writeup.pdf        ← 上面那份排好版的 PDF（A4、166 頁、可列印）
```

## 📄 PDF 版

`SunshineCTF2025_pwn_writeup.pdf`（1.3 MB、A4、166 頁）是整份 write-up 的排版版本，
含可點擊目錄、10 個章節書籤，以及全部 ASCII 記憶體圖（方框都對齊）。

要重新產生（需要 `xelatex`、`xeCJK`、`Noto Sans CJK`、`JetBrains Mono`）：

```bash
python3 .pdfbuild/build_master.py                     # 由各小檔重新合併出完整 md
cd .pdfbuild && ./venv/bin/python build_pdf.py        # 產生 PDF 到 repo 根目錄
./venv/bin/python verify_pdf.py                       # 品質檢查（缺字／爆版／方框對齊）
```

## ▶️ 重現

```bash
./wp/run_all.sh              # 打遠端，7 題全部重跑（會印出真 flag）
./wp/run_all.sh pwn1 pwn4    # 只跑指定題目

cd pwn4 && python3 exploit.py            # 本地
cd pwn4 && python3 exploit.py REMOTE     # 遠端 chal.sunshinectf.games:26004
```

每一支 `exploit.py` 都支援 local / `REMOTE` 兩種模式，且**不需要 TTY**。

## 🔍 品質保證

全部寫完之後做了 **3 輪獨立審查**（每一輪都重新對 binary 驗證，共發現並修正
約 70 條技術錯誤與 50 個新手閱讀障礙）：

| 輪次 | 報告 | 修正紀錄 |
|---|---|---|
| 第 1 輪 | `wp/review_round1.md` | `wp/fixes_round1_applied.md` |
| 第 2 輪 | `wp/review_round2_{stack,fmtstr,heap,rop_foundations}.md` | `wp/fixes_round2_*.md` |
| 第 3 輪 | `wp/review_round3_{verification,cold_read,regression}.md` | `wp/fixes_round3_*.md` |

最終驗證：`./wp/run_all.sh` → **7/7 全部取得真實 flag**。
