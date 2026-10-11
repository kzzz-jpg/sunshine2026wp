# `wp/00_基礎知識_從零開始.md` 待修清單（來自 heap round 2 審查）

> 本檔由 heap 修正作業（`pwn4`/`pwn6`）產生，**只列出必須在 `wp/00` 做的修改**。
> 我**沒有**、也不能改 `wp/00`（它由另一位 agent 擁有），所以列在這裡交接。
> 來源：`wp/review_round2_heap.md` §3（S1、S2），以及我在驗證過程中確認的實況。
> 每一項都附「行號 / 原文 / 建議替換文字」，可直接照改。

---

## A. 必改（與 pwn6 筆記直接矛盾，3 處）

### A1. `wp/00:886`（§附錄：本系列 7 題對照表）— pwn6 被寫成「→ ROP」

**原文**

```
| code_breaker | `pwn6/code_breaker` | 26005 | PIE + canary → ROP | `../pwn6/notes.md` |
```

**為什麼錯**：`pwn6/notes.md:24` 明寫「**完全不需要 ROP chain**」；§4 的核心是
`clone` 的 refcount 算錯 ⇒ double free / UAF ⇒ tcache poisoning ⇒
把 `system@plt` 寫進 `.bss` 的函式指標 `[PIE+0x40c0]` ⇒ `cmd 0x15` 的
`call qword ptr [0x40c0]` 直接變成 `system(我們送的字串)`。
實跑（local + REMOTE 都 PASS）完全沒用到任何 gadget。
（PIE + canary 只是「保護機制」，不是「技巧」；`wp/00` 這一欄的欄名是「核心技巧」。）

**建議替換文字**

```
| code_breaker | `pwn6/code_breaker` | 26005 | **Heap**（UAF / double free → tcache poisoning）→ 覆寫函式指標 → `system()`（不需 ROP） | `../pwn6/notes.md` |
```

### A2. `wp/00:439`（§9 常見漏洞類型）— UAF 只列 pwn4

**原文**

```
| **Heap Overflow / UAF** | `malloc` 系列操作錯誤 | pwn4（heap 題） |
```

**為什麼要改**：`pwn6` 也是 heap 題（`pwn6/notes.md:17-19`：refcount 算錯 ⇒ double free +
UAF ⇒ tcache poisoning），而且它才是「UAF 寫入 tcache metadata」的完整示範。
只列 pwn4 會讓讀者以為 pwn6 不是 heap 題（正好與 A1 的錯誤互相強化）。

**建議替換文字**

```
| **Heap Overflow / UAF** | `malloc` 系列操作錯誤（free 後指標仍可用 / 同一塊 free 兩次） | pwn4（UAF + tcache poisoning）、pwn6（refcount 算錯 → double free + UAF） |
```

### A3. `wp/00:442`（§9 常見漏洞類型）— pwn6 被列在「Uninitialised memory」

**原文**

```
| **Uninitialised memory** | 沒初始化就讀 → 洩漏堆疊 | pwn6 |
```

**為什麼錯**：`pwn6/notes.md`（§9 坑 5）明確寫著 `/dev/urandom` 的 `fread`
**有** `cmp rax,0x10; jne 失敗` 的檢查，所以「nonce 沒讀到 ⇒ 用殘留 stack」是
**檢查過但不存在**的候選漏洞。把它列成本題的漏洞類型是錯的。
pwn6 真正的類型是 heap UAF / double free（見 A2），以及 §9:441 已經列的
「Logic bug」（refcount 邏輯）。

**建議替換文字（二選一）**

```
| **Uninitialised memory** | 沒初始化就讀 → 洩漏堆疊 | （本系列沒有；pwn6 是候選但已排除） |
```

或直接刪掉這一列（若不想留空欄）。

---

## B. 建議改（S1：`wp/00` 沒有任何 heap 內容／指路）

### B1. `wp/00` 目錄（`:13-29`）與 §9 都沒有 heap；§9:439 只是一個名詞

**問題**：`wp/00` 的章節只有 ELF/保護/組語/stack/syscall/PLT-GOT/ROP/SROP/pwntools/gdb/SOP，
**沒有 chunk / bin / tcache / safe-linking**。但檔頭（`:6` 附近）要求讀者
「讀完 00 就能看懂每一題的 notes」，而 `pwn4`/`pwn6` 需要的 heap 知識
只在 `wp/99_速查表.md` §8（迷你版）與 `pwn4/notes.md` §5（完整版）。
（`grep -n "wp/99\|速查表" pwn4/notes.md pwn6/notes.md` 原本是 **0 筆**；
本次已在兩份 notes 的檔頭補上指路，見 `wp/fixes_round2_heap.md` §3。）

**建議**：在 `wp/00` §9 的表格後（或 §9 開頭）加一段「heap 題的入門路徑」，
並在目錄加一個指標列：

```
> 💡 **heap 題（pwn4 `cache_money`、pwn6 `code_breaker`）**：本檔不含 heap 章節。
> 請先讀 `wp/99_速查表.md` §8（chunk / bin / tcache / safe-linking 的迷你版），
> 再讀 `pwn4/notes.md` §5（完整版，含 gdb 實測的 heap 佈局表）；
> `pwn6/notes.md` §3.5 也有一份 20 行的最小語彙整理。
```

---

## C. 確認「不需要改」的兩項（避免另一位 agent 白改）

* **S5（RELRO）**：`wp/00` §4.4 說「Partial RELRO → `.got` 唯讀、`.got.plt` 可寫」
  —— 這是**正確的**（`readelf` 實測 RELRO 覆蓋 `0x403dc0~0x404000`，
  含 `.got`（`0x403fd8`）；`.got.plt` 只有前 0x18 bytes 被保護，
  函式 GOT 從 `0x404000` 起仍可寫）。錯誤的是 `pwn4/notes.md`，已在本次修好。
  **`wp/00` 不用動。**
* **S6（暫存器術語）**：`wp/00` §6.1 寫「`r8`、`r9` 是第 5、6 個參數」——**正確**。
  錯誤的是 `pwn4/notes.md`（原本寫 `r8~r11`），已在本次修好。**`wp/00` 不用動。**

---

## D. 附註：屬於 `wp/99_速查表.md` §8（不是 `wp/00`，給負責 wp/99 的 agent）

以下三項也是 round 2 審查的一致性問題，但**不在 `wp/00`**，本檔僅代為列出以免漏掉：

1. **S3【中】** `wp/99:184-185` 說「偽造 `fd` 前**要先知道 chunk 位址**」——與事實相反。
   safe-linking 只用 `chunk >> 12`，所以「洩漏 `chunk>>12`（例如 free 到空鏈時讀 `next`）」
   就足以偽造 `fd`；這正是 pwn4 flag `s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che` 的意義。
   建議改成：「…存的是 `target ^ (chunk_addr >> 12)`；因為只用到 `chunk>>12`，
   只要洩漏 `chunk>>12` 就能偽造 `fd`（見 `pwn4/notes.md` §5.4、`pwn4/notes.md` §5.3 的 `entries[]` 明文註記）。」
2. **S4【中】** `wp/99` §8 補三個現代 glibc 細節（各一行）：
   (a) `tcache->entries[]` 是**明文** user 位址，只有 chunk 內的 `next` 才編碼；
   (b) `tcache_get()` 有 `aligned_OK(e)` 檢查 → 毒化目標必須 16-byte 對齊；
   (c) `tcache_put` 的寫入順序是 `key → next → entries → counts`（影響「先清 key 才能 double free」）。
   註：`pwn4` §5.3/§5.4/§10 與 `pwn6` §3.5/§4.3 現在都已經寫到這三點。
3. **S7【低】** `wp/99` §8 補一句欄位命名說明：
   「`+0x10`/`+0x18` 這兩格：在 tcache 叫 `next`/`key`，在 unsorted/small/large bin 叫 `fd`/`bk`；
   fastbin 只用到 `+0x10` 的 `fd`。」（`pwn6` §3.5 (2) 已有同樣說明。）
