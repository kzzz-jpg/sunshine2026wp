#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDF 產出品質總檢查"""
import subprocess, re, collections, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
PDF = 'build.pdf'
VERT = set('│┃║┤┫┐┑┘┙╗╝╣╡╢╕╖╛╜')


def log_stats():
    log = open('build.log', encoding='utf-8', errors='replace').read()
    print('【LaTeX 編譯】')
    for k, label in [('Missing character', '缺字警告'), ('Overfull \\hbox', '爆版行'),
                     ('Underfull', '鬆散行'), ('^!', '錯誤')]:
        n = log.count(k)
        print('  %-10s %d' % (label, n))


def pdf_info():
    out = subprocess.run(['pdfinfo', PDF], capture_output=True, text=True).stdout
    d = dict(re.findall(r'^(Pages|Page size|Title):\s+(.*)$', out, re.M))
    print('\n【PDF】')
    for k, v in d.items():
        print('  %-10s %s' % (k, v))
    print('  檔案大小   %.2f MB' % (os.path.getsize(PDF) / 1e6))
    from pypdf import PdfReader
    r = PdfReader(PDF)
    print('  書籤        %d 個' % len(r.outline))


def align():
    def rows_of(p):
        out = subprocess.run(['pdftotext', '-bbox', '-f', str(p), '-l', str(p), PDF, '-'],
                             capture_output=True, text=True).stdout
        R = collections.defaultdict(list)
        for m in re.finditer(r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">(.*?)</word>', out):
            R[round(float(m.group(2)), 1)].append((float(m.group(1)), float(m.group(3)), m.group(5)))
        return R
    tot = ok = 0
    worst = []
    for p in range(1, 167):
        R = rows_of(p)
        m = {}
        for y in sorted(R):
            xs = [x1 for x0, x1, t in R[y] if any(c in VERT for c in t)]
            if xs:
                m[y] = max(xs)
        cur = []
        for y in sorted(m):
            if cur and y - cur[-1] > 11.0:
                if len(cur) >= 3:
                    W = [m[k] for k in cur]
                    sp = max(W) - min(W)
                    tot += 1
                    if sp < 0.6:
                        ok += 1
                    else:
                        worst.append((sp, p, cur[0], len(cur)))
                cur = []
            cur.append(y)
        if len(cur) >= 3:
            W = [m[k] for k in cur]
            sp = max(W) - min(W)
            tot += 1
            if sp < 0.6:
                ok += 1
            else:
                worst.append((sp, p, cur[0], len(cur)))
    print('\n【ASCII 方框圖對齊】')
    print('  量到方框區塊 %d 個，右邊框完全對齊 %d 個' % (tot, ok))
    for w in sorted(worst, reverse=True)[:8]:
        print('    未對齊：span=%.2fpt p%d y=%.1f rows=%d' % w)
    return tot, ok, worst


def headings():
    SUBS = [('⚠', '※注意'), ('🔴', '※重要'), ('🚨', '※警告'), ('💡', '※提示'), ('📖', '※閱讀'),
            ('📚', '※閱讀'), ('🔬', '※實測'), ('🧯', '※修正'), ('🎉', '※完成'), ('🏁', '※總結'),
            ('🧭', '※導引'), ('📁', '※檔案'), ('🔍', '※查'), ('🔎', '※查'), ('📌', '※'), ('📍', '※'),
            ('❌', '✗'), ('✅', '✓'), ('✔', '✓'), ('❓', '？'), ('😄', ':)'), ('\ufe0f', '')]

    def norm(s):
        for a, b in SUBS:
            s = s.replace(a, b)
        return s

    def heads(t):
        o, f = [], False
        for l in t.split('\n'):
            if l.startswith('```'):
                f = not f
                continue
            if f:
                continue
            if re.match(r'^#{1,4} ', l):
                o.append(l.strip())
        return o
    src = [norm(h) for h in heads(open('../wp/SunshineCTF2025_pwn_完整writeup.md', encoding='utf-8').read())]
    bld = set(heads(open('build.md', encoding='utf-8').read()))
    miss = [h for h in src if h not in bld]
    print('\n【內容完整性】')
    print('  來源標題 %d 個，build.md 少 %d 個（預期只有手寫標題與目錄那 2 個）' % (len(src), len(miss)))
    for h in miss:
        print('    - %s' % h[:80])


if __name__ == '__main__':
    log_stats()
    pdf_info()
    align()
    headings()
