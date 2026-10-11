#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 wp/ 底下的教學文件合併成單一檔案 wp/SunshineCTF2025_pwn_完整writeup.md"""
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

PARTS = [
    ('# Part 0 — 索引與成果總表',        'wp/README.md'),
    ('# Part 1 — 基礎知識：從零開始',     'wp/00_基礎知識_從零開始.md'),
    ('# Part 2 — pwn1 total_recall（SROP）', 'pwn1/notes.md'),
    ('# Part 3 — pwn2 mad_libs（Format String）', 'pwn2/notes.md'),
    ('# Part 4 — pwn3 revolution（自製 printf）', 'pwn3/notes.md'),
    ('# Part 5 — pwn4 cache_money（Heap UAF）', 'pwn4/notes.md'),
    ('# Part 6 — pwn5 homemaker（ROP）', 'pwn5/notes.md'),
    ('# Part 7 — pwn6 code_breaker（Heap + RPC）', 'pwn6/notes.md'),
    ('# Part 8 — pwn7 SafeHouse（Seccomp + Pivot）', 'pwn7/notes.md'),
    ('# Part 9 — 速查表',                'wp/99_速查表.md'),
]
OUT = 'wp/SunshineCTF2025_pwn_完整writeup.md'


def demote(text):
    """把所有 Markdown 標題降一級（程式碼區塊內不動）"""
    out, fence = [], False
    for l in text.split('\n'):
        if l.startswith('```'):
            fence = not fence
            out.append(l)
            continue
        if not fence and l.startswith('#') and not l.startswith('#######'):
            out.append('#' + l)
        else:
            out.append(l)
    return '\n'.join(out)


def main():
    old = open(OUT, encoding='utf-8').read().split('\n')
    idx = next(i for i, l in enumerate(old) if l.startswith('# Part 0 — 索引與成果總表'))
    header = '\n'.join(old[:idx])          # 標題 + 導言 + 手寫目錄

    buf = [header]
    for i, (title, path) in enumerate(PARTS):
        body = demote(open(path, encoding='utf-8').read()).rstrip('\n')
        if i:
            buf.append('\n\n\n\n---\n\n')
        buf.append('%s\n\n> 原始檔案：`%s`\n\n%s\n' % (title, path, body))
    open(OUT, 'w', encoding='utf-8').write(''.join(buf))
    print('已重建 %s（%d 行）' % (OUT, len(''.join(buf).split('\n'))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
