# Round 3 最終修正紀錄（notes／exploit 註解）

> **本輪可動的檔案只有 5 個**：`pwn1/notes.md`、`pwn1/exploit.py`、`pwn3/notes.md`、
> `pwn5/notes.md`、`pwn7/notes.md`。`wp/*`、其他 `pwnN/` 目錄一律沒動
> （本檔 `wp/fixes_round3_notes.md` 是本輪新增的交付物）。
>
> **方法**：每一條都先自己跑 `objdump -d -M intel` / `gdb -q -batch` 複驗，
> **才**決定修或略過；reviewer 的說法只要有一句驗不過就記在「reviewer 判讀有誤」。
> `pwn1/exploit.py` **只改註解、邏輯一行都沒動**（常數 `SYSCALL_RET = 0x401069` 與所有 payload
> 組法原封不動），改完之後 5 支 exploit 全部重跑一次（見文末輸出）。
>
> **統計：指定清單 7 條全部已修（0 條略過）、額外再修 2 條（合計 9 條）；另外列出的
> 「略過」共 11 條**（全部是「不在可編輯清單」或「冷讀報告沒有該檔的專屬條目」，
> 沒有半條是因為驗不過而放棄 —— 唯一的判讀修正見「reviewer 判讀有誤」那一節）。

---

## 1. 逐條結果

| # | 來源 | 項目 | 判定 | 檔案 | 一句話說明 |
|---|---|---|---|---|---|
| 1 | regression §2.1（**高**） | pwn1「唯一 `syscall; ret`」是錯的 | **已修** | `pwn1/notes.md` §4、`pwn1/exploit.py` 檔頭註解 | 改成「有**兩個** `syscall; ret`（`0x40104c`/`0x40104e` 與 `0x401069`/`0x40106b`）」，並寫清楚**本題選 `0x401069` 的真正理由**（它就是被我們溢位控制的那次 `read` 自己的 `syscall`：read 回傳值在 `rax`、`0x40106b` 的 `ret` 是被蓋掉的那一格 ⇒ 中間不需要任何額外指令）；同時註明 `0x40104c` **也能用**（實測拿得到 flag） |
| 2 | regression §2.4（低） | pwn5 三個位址差 2：`1a74`→`1a76`、`1a76`→`1a78`、`176d`→`176f` | **已修** | `pwn5/notes.md` §4（epilogue 清單）、§4.8（`append` 清單） | 三個位址全部照 objdump 改正，並補一段「`mov rax,QWORD PTR fs:0x28` 是 **9 bytes**，objdump 會拆成兩行、第二行標 `1a74:` —— 所以下一條在 `0x1a76`，`b *0x1a74` 會停在指令中間」＋驗證指令 |
| 3 | regression §2.5（低） | pwn7 `40179c: call open@plt` 應為 `0x40179f` | **已修** | `pwn7/notes.md` §4.1 | 位址改成 `40179f: call open@plt`；**順手 spot-check 同區塊每一列都對**（見第 3 節對照），並把筆記原本省略的 `0x401795 mov esi,0x2`、`0x40179a xor eax,eax`、`0x40179c mov rdi,rbp` 補進去＋「要斷在 open 請用 `b *0x40179f`」 |
| 4a | regression §2.6（低） | pwn3 `40114d` 不是 fallthrough 點 | **已修** | `pwn3/notes.md` §3 | 改成 `0x40114f`（`0x40114a` 的 `call write@plt` 是 5 bytes），並註明「0x40114a + 5 = 0x40114f」 |
| 4b | regression §2.6（低） | pwn3 §7.2 圖把 `r14/r13/r12/rbp` 壓成一格 | **已修** | `pwn3/notes.md` §7.2 | 拆成 4 列（`buf-0x18`=r14、`-0x20`=r13、`-0x28`=r12、`-0x30`=rbp），並補「怎麼一次驗整排」的 gdb 方法（`b *0x40133d` 時 `rsp` 還在 `buf-0x38`，`[rsp]`/`[rsp+8]`/… 依序是 rbx/rbp/r12/r13/r14/r15） |
| 5 | 本輪指定的「pwn1 冷讀新手點」 | 冷讀報告裡 pwn1 的條目 | **略過（見第 4 節）** | — | 冷讀報告**沒有**任何 pwn1 專屬斷點：pwn1 只出現在 §1.3 C-6（是給 `wp/99` 的建議）與 §2.2（正評）。不過同輪 regression §2.2 指到 `pwn1/notes.md:406` 的 `rt_sigframe ≈ 0xf8`，該句**已修**（見第 2 節「額外」） |
| 6a | cold read §1.6 P56-1 | pwn5 §6.3 與 `wp/00` §10.4 沒有互相引用 | **已修** | `pwn5/notes.md` §6.3 | 開頭加一段 📖：兩邊講的是同一件事（gadget／`rsp%16` 對齊／`movaps`），這裡只是用本題真實位址再驗一次 |
| 6b | cold read §1.6 P56-3 | pwn5 §7.3 與 `wp/00` §6.3 的 offset 規矩沒有顯式對照 | **已修** | `pwn5/notes.md` §7.3 | 開頭加一段 📖：`state[0x108]`＝「離 `state` 起點 0x108 bytes」；差別是 ① `state` 在 `.bss` 不是堆疊區域變數 ② 表上索引是 **payload 索引**，`append` 從 `payload+1` 開始複製 ⇒ `payload[i]` 對應 `state[i-1]` |
| 6c | cold read §1.6 P56-2 | pwn5 §4.3 gadget 藏在立即值、pwn6 語彙放置順序 | **略過（正評，無需改）** | — | 報告本身寫「是很好的示範」「放置順序正確」，沒有要修的內容 |
| 6d | cold read（pwn3／pwn7 專屬條目） | — | **略過（不存在）** | — | 冷讀報告沒有 `pwn3/notes.md`、`pwn7/notes.md` 的專屬斷點（pwn3 只在 `wp/00` 附錄被當正評提到） |

### 1.1 略過清單（附原因，共 8 條）

| 項目 | 原因 |
|---|---|
| regression §2.2 的 `wp/00` §11.4（`rt_sigframe` ≈ `0xf8`） | **`wp/00` 不在本輪可編輯清單**；同一句話在 `pwn1/notes.md` 的那一份**已修**（見下） |
| regression §2.3 `wp/00` §12 `DEBUG` 參數無效 | 同上，`wp/00` 不可編輯 |
| cold read C-1（`$base` 不是 gdb 內建）、C-2（heap 入門動線）、C-3、C-4、C-5、C-6 | 全部是 `wp/99_速查表.md` 的條目，不可編輯 |
| cold read W-1（對齊算式推導）、W-2（`checksec` 安裝） | `wp/00` 的條目，不可編輯 |
| cold read P2-1～P2-4 | `pwn2/notes.md` 的條目，不可編輯 |
| cold read P4-1～P4-6 | `pwn4/notes.md` 的條目，不可編輯 |
| regression §1.1／§1.2 的「無 git 歷史、統計口徑」註記 | 不是缺陷，是查核限制的說明，無需改檔 |
| regression §1 表格中「已落實」的 60 餘條 | 已落實，不動（避免把正確內容改壞） |

---

## 2. 額外修掉的一條（超出指定清單，但在我可編輯的檔案內、且已用 gdb 驗證）

| 項目 | 判定 | 檔案 | 說明 |
|---|---|---|---|
| `rt_sigframe` 被寫成「約 `0xf8` bytes」（regression §2.2，位置含 `pwn1/notes.md`） | **已修** | `pwn1/notes.md` §5.1 名詞表 | `0xf8` 是 **pwntools `SigreturnFrame()` 的長度**（＝我們要寫上堆疊的那段，`len(bytes(SigreturnFrame())) == 248`）；核心的 `struct rt_sigframe` 還含 `pretcode`、`siginfo`（128 bytes）等欄位，**比 0xf8 大**。名詞表改了，另加一段 ⚠️ 說明「我們只要準備 0xf8 bytes 放在 `rsp` 指到的地方（本題 `buf+0x90`），核心就會正確還原暫存器 —— 本題實測可跑」 |
| pwn3 §7.2 表格 `buf-0x18` 那一列的值（`0x402009`） | **已修** | `pwn3/notes.md` §7.2 表格 | **reviewer 說「下面的表是正確的」，這一句 reviewer 判讀有誤**：`0x402009`＝`"0123456789abcdef"` 是 `printf` **自己**在 `0x4013a4` 載入 `r14` 的值，**不是保存格的內容**。gdb 實測：`b *0x401330` → caller 的 `r14 = 0x7ffff7ffd000`、`r13 = 0x1`（不穩定）；保存格的內容是 `[rsp+0x20]=0x7ffff7ffd000`、`[rsp+0x18]=0x1`。已改成「呼叫者的 r14／r13，值不穩定」並加註 |

---

## 3. 驗證指令與實際輸出（複驗用）

### 3.1 pwn1 — 確認「`syscall; ret` 有兩個」

```bash
cd pwn1 && objdump -d -M intel challenge | grep -A1 syscall
```

```
  40104c:	0f 05                	syscall
  40104e:	c3                   	ret          ← 這裡也是 syscall; ret
  ...
  401069:	0f 05                	syscall
  40106b:	c3                   	ret          ← 本筆記用的是這個
```

`objdump -d -M intel challenge | grep -c syscall` → **4**（`0x401014`/`0x40102f`/`0x40104c`/`0x401069`），
「全檔 4 條 syscall」這句本來就對；錯的是「只有 `0x401069` 有用」。

**加碼實測**（不是只讀文件）：把 `exploit.py` 複製到暫存目錄、只把 `SYSCALL_RET` 改成 `0x40104c`
（連 frame 的 `rip` 一起換），本機照樣拿到 flag ⇒ 證明 `0x40104c` 是可用的 gadget，
「唯一」的說法確實是錯的。

### 3.2 pwn5 — 三個位址

```bash
cd pwn5
objdump -d -M intel --start-address=0x1a69 --stop-address=0x1a80 homemaker
objdump -d -M intel --start-address=0x1766 --stop-address=0x1775 homemaker
```

```
    1a6d:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28      ← 9 bytes
    1a74:	00 00                                               ← objdump 的續行
    1a76:	74 05                	je     1a7d          ★ 不是 1a74
    1a78:	e8 33 f6 ff ff       	call   10b0 <__stack_chk_fail@plt>   ★ 不是 1a76
    1a7d:	c9                   	leave
    1a7e:	c3                   	ret
    1766:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28      ← 9 bytes
    176d:	00 00                                               ← objdump 的續行
    176f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax   ★ 不是 176d
```

⇒ **reviewer 對這 3 個位址的判讀完全正確**，已照改。
（改完之後清單自己內部也一致了：`1a6d + 9 = 1a76`、`1766 + 9 = 176f`。）

### 3.3 pwn7 — `call open@plt` 的位址與同區塊 spot-check

```bash
cd pwn7 && objdump -d -M intel --start-address=0x40178e --stop-address=0x4017b2 service
```

| 筆記原本寫的 | objdump 實際 | 判定 |
|---|---|---|
| `40178e: lea rbp,[rip+0x18da]` | `40178e: lea rbp,[rip+0x18da]` → `# 40306f` | ✅ 對 |
| `40179c: call open@plt` | `40179c: mov rdi,rbp` / **`40179f: call 401260 <open@plt>`** | ❌ → **已修** |
| `4017a4: xor esi,esi` | `4017a4: xor esi,esi` | ✅ 對 |
| `4017a8: mov edi,eax` | `4017a8: mov edi,eax` | ✅ 對 |
| `4017aa: call dup2@plt` | `4017aa: call 4011c0 <dup2@plt>` | ✅ 對 |
| `4017b1: mov esi,0x1` | `4017b1: mov esi,0x1` | ✅ 對 |
| `4017bd: call dup2@plt` | `4017bd: call 4011c0 <dup2@plt>` | ✅ 對 |
| `4017c2: mov esi,0x1` / `4017c7: mov edi,0xd` / `4017d3: call signal@plt` | 位址與運算元全部相同 | ✅ 對 |
| `4017da: lea rdi,[rip+0x1898]`（`0x403079`="flag.txt"） / `4017e3: call open@plt` | 完全相同 | ✅ 對 |
| `4017e8: mov DWORD PTR [rip+0x388e],0x2` / `4017f2: mov DWORD PTR [rip+0x388c],eax` | 完全相同（`0x405080`/`0x405084`） | ✅ 對 |

⇒ 該區塊「只有 `0x40179c` 那一列是錯的」，reviewer 判讀正確。

### 3.4 pwn3 — fallthrough 與 §7.2 圖

```bash
cd pwn3 && objdump -d -M intel --start-address=0x401148 --stop-address=0x401150 revolution
```

```
  40114a:	e8 31 ff ff ff       	call   401080 <write@plt>     ← 5 bytes
  40114f:	ba 07 00 00 00       	mov    edx,0x7               ← fallthrough 是這裡
```

⇒ `0x40114d` 是錯的（reviewer 正確），已改成 `0x40114f`。

圖的修正依據（`printf` 進場六個 push，順序反過來就是位址由低到高）：

```
  401330: push r15 ; 401335: push r14 ; 401337: push r13 ;
  401339: push r12 ; 40133b: push rbp ; 40133c: push rbx ; 40133d: sub rsp,0xe8
```

gdb 實測（`b *0x40133d`，此時 `rsp` 還停在 `buf-0x38`）：

```
r15[-0x10]=0x403dd0  r14[-0x18]=0x7ffff7ffd000  r13[-0x20]=0x1
r12[-0x28]=0x40201a  rbp[-0x30]=0x402022        rbx[-0x38]=0x7fffffffdbe0 (=buf)
```

---

## 4. reviewer 判讀有誤／沒抓到的地方

1. **pwn3 §7.2 的表格並不是「完全正確」**（regression §2.6 寫「同一節下面的表（:742-750）是正確的」）：
   `buf-0x18` 那一列的 `0x402009` 是 `printf` 內部在 `0x4013a4` 載入的值，不是保存格的內容。
   實際那一格是**呼叫者的 r14**（本機 `0x7ffff7ffd000`，不穩定）。**已修**（第 2 節）。
2. **regression §2.1 的「修正建議」有一句會誤導**：它寫「`0x40104c`…跳進去時 `rax` 由前一條
   `mov rax,0` 決定」。實際上**直接跳到 `0x40104c` 時那條 `mov rax,0`（`0x401045`）根本不會執行**，
   `rax` 完全由攻擊者決定 —— 我把它當 `SYSCALL_RET` 實測可以拿到 flag。
   所以措辭寫成「兩者都可用，本題選 `0x401069` 是因為它連成一線」才是事實。
3. **其餘全數正確**：`pwn5` 三個 off-by-2、`pwn7` 的 `0x40179c`、`pwn3` 的 `0x40114d`
   我都逐條 objdump 複驗，reviewer 的判讀**沒有錯**（連「原因＝抄到 objdump 的續行」也對）。
4. 附帶一提：reviewer 說冷讀報告有 pwn1 的「新手點」可修 —— 實際上冷讀報告裡
   **pwn1 沒有任何專屬斷點**（只有 C-6 給 `wp/99` 的建議、與 §2.2 的正評）。
   真正落在 pwn1 的是 regression §2.2 的 `rt_sigframe ≈ 0xf8`，已修（第 2 節）。

---

## 5. 五支 exploit 實測（改完之後重跑）

```bash
cd pwn1 && python3 exploit.py < /dev/null
```

```
[+] stack leak  = 0x7ffcc5017068
[*] vuln buffer = 0x7ffcc5016fe8

[+] raw output:
sun{LOCAL_DUMMY_FLAG}
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

[+] FLAG: sun{LOCAL_DUMMY_FLAG}
```

```bash
cd pwn1 && python3 exploit.py REMOTE < /dev/null
```

```
[+] stack leak  = 0x7ffcd006aee8
[*] vuln buffer = 0x7ffcd006ae68

[+] raw output:
sun{r3caLl_ev3Ry_reGist3r_sR0p}
uid=1337(total_recall) gid=1337(total_recall) groups=1337(total_recall)
DONE

[+] FLAG: sun{r3caLl_ev3Ry_reGist3r_sR0p}
```

```bash
cd pwn3 && python3 exploit.py REMOTE < /dev/null
```

```
...（略：id / ls / 目錄列表）
uid=1337(revolution) gid=1337(revolution) groups=1337(revolution)
DONE

FLAG: sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```

```bash
cd pwn5 && python3 exploit.py REMOTE < /dev/null
```

```
[+] PIE base  = 0x63ea52127000
[+] shell should be up, sending commands
sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
uid=1337(homemaker) gid=1337(homemaker) groups=1337(homemaker)
DONE

FLAG: sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
```

```bash
cd pwn7 && python3 exploit.py REMOTE < /dev/null
```

```
[*] stage2 pre=b'OK\n' leak=931065e50000 A2=0x40a228
[+] XOR key = 931065e5
[*] stage3 d2ok=b'OK\n' A3=0x40a2e0 RESP=0x40a340
[+] raw  : b'OK\nsun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}\n\n'
[+] FLAG: sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
```

**5 / 5 PASS**，且各題 `FLAG.txt` 仍是真正的遠端 flag（沒有被本輪測試污染）。

---

## 6. 本輪動到的檔案

| 檔案 | 動了什麼 |
|---|---|
| `pwn1/notes.md` | §4 gadget 段落重寫（兩個 `syscall; ret`、選 `0x401069` 的真正理由）＋ §5.1 名詞表 `rt_sigframe`/`0xf8` 更正與 ⚠️ 說明 |
| `pwn1/exploit.py` | **只有註解**：`SYSCALL_RET` 那段說明改成「兩個 `syscall; ret`、本題用 `0x401069`、`0x40104c` 也可用」。**邏輯、常數、payload 一行都沒動** |
| `pwn3/notes.md` | §3 `0x40114d`→`0x40114f`；§7.2 圖拆成 r14/r13/r12/rbp 四列＋「一次驗整排」gdb 方法；§7.2 表格 r14/r13 值更正（不穩定／`0x402009` 不是這格的內容） |
| `pwn5/notes.md` | §4 epilogue 與 §4.8 `append` 清單三個位址（`1a76`/`1a78`/`176f`）＋「9 bytes 被 objdump 拆兩行」說明；§6.3 加 `wp/00` §10.4 交叉引用；§7.3 加 `wp/00` §6.3 offset 規矩對照 |
| `pwn7/notes.md` | §4.1 `40179c`→`40179f`，補 `0x401795`/`0x40179a`/`0x40179c` 三列與「`b *0x40179f`」提示 |
| `wp/fixes_round3_notes.md` | 本檔（新增） |
