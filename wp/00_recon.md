# 環境與題目對照（解題時的第一手紀錄）

remote：`chal.sunshinectf.games`

| 目錄 | 題名（檔案） | port | 保護機制 |
|---|---|---|---|
| pwn1 | total_recall (`challenge`) | 26003 | 靜態連結、stripped、non-PIE、**NX off**、無 canary、手寫組語（`.text` 只有 0x6c bytes） |
| pwn2 | mad_libs (`mad_libs`) | 26001 | PIE、canary、NX、Partial RELRO |
| pwn3 | revolution (`revolution`) | 26002 | non-PIE、無 canary、NX、Partial RELRO、自製 printf |
| pwn4 | cache_money (`cache_money`) | 26004 | non-PIE、canary、NX、Partial RELRO、heap |
| pwn5 | homemaker (`homemaker`) | 26008 | PIE、canary、NX、**Full RELRO** |
| pwn6 | code_breaker (`code_breaker`) | 26005 | PIE、canary、NX、Partial RELRO、heap |
| pwn7 | SafeHouse (`service`) | 26007 | non-PIE、無 canary、NX、Full RELRO、**seccomp** |

## 真實 flag（全部已取得）

```
pwn1  sun{r3caLl_ev3Ry_reGist3r_sR0p}
pwn2  sun{f1ll_iN_th3_g0T_eNtry}
pwn3  sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
pwn4  sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
pwn5  sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
pwn6  sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
pwn7  sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
```

## 每個 port 的辨識方式

第一次連上去（送一個換行）看到什麼，就能對應到哪一題：

| port | 連上去看到的 |
|---|---|
| 26001 | `=== Mad Libs ===` / `Fill in the blanks!` |
| 26002 | `=== PRINT PRINT REVOLUTION ===` / `Enter your score card template:` |
| 26003 | 8 bytes 的原始二進位（堆疊位址洩漏） |
| 26004 | `$$$ CACHE MONEY Crypto Wallet Manager $$$` |
| 26005 | 約 21 bytes 的二進位（`\x00\x11\x01` 開頭，每次不同） |
| 26007 | `SafeHouse v1.0` / `Type HELP.` / `sh> ` |
| 26008 | `MODEL 7 "HOMEMAKER" DOMESTIC AUTOMATON` |

（26006 沒有開；7 題分別對應上面 7 個 port。）

## 執行環境備註

* `pwn2`、`pwn6` 附了 `libc.so.6` 與 `ld-linux-x86-64.so.2`（RUNPATH = `$ORIGIN`）。
  直接用系統的 ld 跑會出現
  `undefined symbol: __nptl_change_stack_perm, version GLIBC_PRIVATE`，
  必須用：
  ```bash
  ./ld-linux-x86-64.so.2 --library-path . ./<binary>
  ```
  exploit 裡面也是用 `process(['./ld-linux-x86-64.so.2','--library-path','.','./<binary>'])`。
* `pwn4` 另外準備了對應遠端的 glibc 2.39。
* 7 題的 exploit 都不需要 TTY，`< /dev/null` 也能跑完並印出 flag。
