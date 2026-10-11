#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修正 Markdown 裡 ASCII 方框圖「右邊框沒有對齊」的問題。

判定方式：一行「最右邊那條直線邊框字元」所在的格數欄位（絕對欄位，
不是寬度）就是這個方框的右邊界；同一個 fence 內連續的方框行應該一致。

只改動填充用的空白或 ─ 的數量，不動任何文字內容。
"""
import unicodedata, glob, sys, os, re

BOX = (0x2500, 0x257F)
VERT = set('│┃║┤┫┐┑┘┙╗╝╣╡╢╕╖╛╜')
MAXSPREAD = 20


def cells(s):
    n = 0
    for c in s:
        o = ord(c)
        if o in (0x2605, 0x2736):
            n += 1
        elif BOX[0] <= o <= BOX[1]:
            n += 1
        elif unicodedata.east_asian_width(c) in ('W', 'F'):
            n += 2
        else:
            n += 1
    return n


def vpos(l):
    return [i for i, c in enumerate(l) if c in VERT]


def metric(l):
    p = vpos(l)
    return cells(l[:p[-1] + 1]) if p else None


def adjust(l, delta):
    p = vpos(l)
    if not p:
        return None
    lb = p[-1]
    before, mark, after = l[:lb], l[lb], l[lb + 1:]

    if delta > 0:
        if before.endswith('─'):
            i = len(before)
            while i > 0 and before[i - 1] == '─':
                i -= 1
            return before[:i] + '─' * (len(before) - i + delta) + mark + after
        return before + ' ' * delta + mark + after

    n = -delta
    if before.endswith('─'):
        i = len(before)
        while i > 0 and before[i - 1] == '─':
            i -= 1
        run = len(before) - i
        if run - n >= 1:
            return before[:i] + '─' * (run - n) + mark + after
    start = p[-2] + 1 if len(p) >= 2 else 0
    cell = before[start:]
    for m in reversed(list(re.finditer(r' +', cell))):
        if len(m.group(0)) >= n:
            k = start + m.start()
            return before[:k] + ' ' * (len(m.group(0)) - n) + before[start + m.end():] + mark + after
    return None


def fix_group(g):
    if len(g) < 3:
        return []
    M = [metric(t) for _, t in g]
    if any(m is None for m in M):
        return []
    if max(M) - min(M) > MAXSPREAD:
        return []
    if len(set(M)) == 1:
        return []

    mode = max(set(M), key=M.count)
    out, bad = [], []
    for (ln, t), m in zip(g, M):
        d = mode - m
        if d == 0:
            continue
        new = adjust(t, d)
        if new is None:
            bad.append((ln, d))
        else:
            out.append((ln, new))
    if not bad:
        return out

    target = max(M)
    out = []
    for (ln, t), m in zip(g, M):
        d = target - m
        if d == 0:
            continue
        new = adjust(t, d)
        if new is not None:
            out.append((ln, new))
    return out


def fix_file(f):
    lines = open(f, encoding='utf-8').read().split('\n')
    changes = []
    infence, i = False, 0
    while i < len(lines):
        if lines[i].startswith('```'):
            infence = not infence
            i += 1
            continue
        if not infence:
            i += 1
            continue
        items, j = [], i
        while j < len(lines) and not lines[j].startswith('```'):
            items.append((j + 1, lines[j]))
            j += 1
        i = j + 1
        g = []
        for ln, t in items + [(None, '')]:
            if t and vpos(t):
                g.append((ln, t))
            else:
                if g:
                    changes += fix_group(g)
                    g = []
    return lines, changes


def main():
    fs = sorted(glob.glob('pwn*/notes.md')) + \
         ['wp/README.md', 'wp/00_基礎知識_從零開始.md', 'wp/99_速查表.md']
    fs = [f for f in fs if os.path.exists(f)]
    grand = 0
    for f in fs:
        lines, changes = fix_file(f)
        if not changes:
            continue
        seen = {}
        for ln, new in changes:
            seen[ln] = new
        for ln, new in seen.items():
            lines[ln - 1] = new
        open(f, 'w', encoding='utf-8').write('\n'.join(lines))
        grand += len(seen)
        print('%-32s 修正 %2d 行' % (f, len(seen)))
    print('\n合計修正 %d 行' % grand)
    return 0


if __name__ == '__main__':
    sys.exit(main())
