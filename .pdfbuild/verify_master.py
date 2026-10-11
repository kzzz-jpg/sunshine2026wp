import os, re, sys
sys.path.insert(0,'.pdfbuild')
from build_master import PARTS, demote
from fix_diagrams import vpos, metric

combined = open('wp/SunshineCTF2025_pwn_完整writeup.md', encoding='utf-8').read()
print('合併檔：%d 行、%d 字元' % (len(combined.split('\n')), len(combined)))

# 1) 每個 Part 的內容是否完整出現
print('\n[1] 各 Part 內容完整性')
ok = True
for title, path in PARTS:
    assert title in combined, '缺少 %s' % title
    body = demote(open(path, encoding='utf-8').read()).rstrip('\n')
    if body in combined:
        print('  OK   %-46s (%s, %d 行)' % (title[:46], path, len(body.split('\n'))))
    else:
        ok = False
        print('  FAIL %-46s (%s)' % (title[:46], path))
print('  →', '全部完整' if ok else '有缺漏！')

# 2) 標題數量
hd = [l for l in combined.split('\n') if re.match(r'^#{1,2} ', l)]
print('\n[2] 標題：H1=%d  H1+H2=%d' % (sum(1 for l in hd if l.startswith('# ')), len(hd)))

# 3) 方框圖對齊
lines = combined.split('\n')
infence, i, bad, grp = False, 0, 0, 0
while i < len(lines):
    if lines[i].startswith('```'): infence = not infence; i += 1; continue
    if not infence: i += 1; continue
    items, j = [], i
    while j < len(lines) and not lines[j].startswith('```'):
        items.append(lines[j]); j += 1
    i = j + 1
    g = []
    for t in items + ['']:
        if t and vpos(t): g.append(t)
        else:
            if len(g) >= 3:
                M = [metric(t) for t in g]
                if max(M)-min(M) <= 20 and len(set(M)) > 1:
                    grp += 1; bad += sum(1 for m in M if m != max(set(M), key=M.count))
            g = []
print('\n[3] 合併檔方框圖：未對齊群組=%d，偏差行=%d' % (grp, bad))

# 4) 程式碼圍籬成對
print('\n[4] ``` 圍籬數量：%d（%s）' % (combined.count('```'), '成對' if combined.count('```') % 2 == 0 else '奇數！有問題'))
