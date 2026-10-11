#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 wp/SunshineCTF2025_pwn_完整writeup.md 轉成一份排版良好的 PDF。

流程：
  1. 前處理 markdown（emoji → 文字標記、保護 <placeholder>、移除手寫目錄）
  2. 由實際用到的字元自動產生 xeCJK 字元分類表（給 ASCII 圖表對齊用）
  3. 用 pandoc + XeLaTeX 產出 PDF
"""
import os, re, subprocess, sys, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC  = os.path.join(ROOT, 'wp', 'SunshineCTF2025_pwn_完整writeup.md')
MD   = os.path.join(HERE, 'build.md')
OUT  = os.path.join(ROOT, 'SunshineCTF2025_pwn_writeup.pdf')

# --------------------------------------------------------------------------
# 符號替換表
# --------------------------------------------------------------------------
# 程式碼區塊內：只能用單一字元替換（不能產生 LaTeX 指令），
# 且必須是 JetBrains Mono 有涵蓋的半寬字元。
CODE_SUBS = {
    '★': '✶',      # U+2736：JetBrains Mono 有，半寬
    '①': '(1)', '②': '(2)', '③': '(3)', '④': '(4)',
    '⑤': '(5)', '⑥': '(6)', '⑦': '(7)', '⑧': '(8)',
    '✔': '✓', '✅': '✓', '❌': '✗',
    '🔴': '!!', '⚠': '!!', '🚨': '!!', '🎉': '!!', '🏁': '!!',
    '💡': '!!', '🧯': '!!', '🔬': '!!',
    '📌': '*', '📍': '*', '📖': '*', '📚': '*', '📁': '*',
    '🔍': '*', '🔎': '*', '🧭': '*', '❓': '?', '😄': ':)',
}

# 內文：換成好讀的文字標記（Noto Sans CJK 沒有 emoji，且彩色 emoji 無法用於 XeLaTeX）
PROSE_SUBS = {
    '⚠': '※注意', '🔴': '※重要', '🚨': '※警告', '💡': '※提示',
    '📖': '※閱讀', '📚': '※閱讀', '🔬': '※實測', '🧯': '※修正',
    '🎉': '※完成', '🏁': '※總結', '🧭': '※導引', '📁': '※檔案',
    '🔍': '※查', '🔎': '※查', '📌': '※', '📍': '※',
    '❌': '✗', '✅': '✓', '✔': '✓',
    '❓': '？', '😄': ':)',
}

# 這兩者由 LaTeX 的 pifont 提供（見 template.latex）
PROSE_KEEP = set('✓✗')

ANGLE = re.compile(r'<([A-Za-z_][A-Za-z0-9_@./+-]*)>')


def preprocess() -> str:
    raw = open(SRC, encoding='utf-8').read()
    lines = raw.split('\n')

    # ---- 1) 移除開頭的 H1 與三行說明引言（標題頁已經有同樣資訊） ----
    while lines and (lines[0].startswith('# ') or lines[0].strip() == '' or
                     lines[0].startswith('> ') or lines[0].strip() == '---'):
        if lines[0].startswith('## '):
            break
        lines.pop(0)

    # ---- 2) 移除手寫的「## 目錄」區塊（改用 pandoc/LaTeX 產生的真目錄） ----
    out, i, n = [], 0, len(lines)
    while i < n:
        if lines[i].strip() == '## 目錄':
            i += 1
            while i < n and not (lines[i].strip() == '---' or
                                 (lines[i].startswith('#') and not lines[i].startswith('##'))):
                i += 1
            # 一併吃掉收尾的 --- 與空白行；否則檔案以 --- 開頭，
            # pandoc 會把它當成 YAML metadata 而解析失敗
            while i < n and lines[i].strip() in ('---', ''):
                i += 1
            continue
        out.append(lines[i]); i += 1
    lines = out

    # ---- 3) 逐行處理（fence 內外用不同替換表） ----
    res, in_fence = [], False
    for ln in lines:
        if ln.startswith('```'):
            in_fence = not in_fence
            res.append(ln); continue

        # 變體選擇符一律移除（XeLaTeX 無法顯示）
        ln = ln.replace('\ufe0f', '')

        if in_fence:
            for k, v in CODE_SUBS.items():
                if k in ln:
                    ln = ln.replace(k, v)
            # 程式碼區塊內若還有漏網的 emoji，換成 *
            ln = ''.join('*' if (0x1F000 <= ord(c) <= 0x1FAFF or ord(c) in (0x2705, 0x274C, 0x2714)) else c
                         for c in ln)
            res.append(ln); continue

        for k, v in PROSE_SUBS.items():
            if k in ln:
                ln = ln.replace(k, v)
        ln = ''.join('※' if 0x1F000 <= ord(c) <= 0x1FAFF else c for c in ln)

        # 保護 <placeholder>：pandoc 會把它當成 raw HTML 而整段吃掉
        def _esc(m):
            pre = ln[:m.start()]
            if pre.count('`') % 2 == 1:        # 已經在行內程式碼裡
                return m.group(0)
            return '`<%s>`' % m.group(1)
        ln = ANGLE.sub(_esc, ln)
        res.append(ln)

    return '\n'.join(res)


# --------------------------------------------------------------------------
# 由實際用到的字元產生 xeCJK 字元分類
# --------------------------------------------------------------------------
def mono_cmap():
    from fontTools.ttLib import TTFont
    p = subprocess.run(['fc-match', '-f', '%{file}', 'JetBrains Mono'],
                       capture_output=True, text=True).stdout.strip()
    return set(TTFont(p, lazy=True).getBestCmap().keys())


def gen_fontclasses(text: str):
    """凡是 JetBrains Mono 有涵蓋的字元，都歸到 Default class（= 半寬），
    其餘（CJK 表意文字、全形標點…）留給 CJK class（= 全寬，剛好 2 倍寬）。"""
    jb = mono_cmap()
    used = {ord(c) for c in text if ord(c) > 127}
    move = sorted(cp for cp in used if cp in jb)

    # 壓成連續區間
    ranges, s = [], None
    for cp in move:
        if s is None:
            s = p = cp; continue
        if cp == p + 1:
            p = cp; continue
        ranges.append((s, p)); s = p = cp
    if s is not None:
        ranges.append((s, p))

    def spec(a, b):
        return '"%04X' % a if a == b else '"%04X -> "%04X' % (a, b)

    lines = ['% 由 build_pdf.py 自動產生：以下字元交給 \\setmonofont（JetBrains Mono，半寬）渲染。',
             '% 其餘非 ASCII 字元留在 CJK class，由 \\setCJKmonofont 渲染（全寬 = 2 倍寬），',
             '% 這樣 ASCII 圖表中的「製表符號 1 格、CJK 2 格」才會精準對齊。']
    CH = 12
    for i in range(0, len(ranges), CH):
        chunk = ', '.join(spec(a, b) for a, b in ranges[i:i + CH])
        cmd = '\\xeCJKDeclareCharClass{Default}{%s}' % chunk
        if i == 0:
            lines.append(cmd)
        else:
            lines.append(cmd)
    return '\n'.join(lines) + '\n', len(move), len(ranges)


# --------------------------------------------------------------------------
# LaTeX 後處理
# --------------------------------------------------------------------------
VERBATIM_OLD = r'\DefineVerbatimEnvironment{Highlighting}{Verbatim}{commandchars=\\\{\}}'
VERBATIM_NEW = (r'\DefineVerbatimEnvironment{Highlighting}{Verbatim}'
                r'{breaklines,breakanywhere,commandchars=\\\{\}}')

# 在這些字元後面插入「斷行機會」（\allowbreak 不會多印任何字元，
# 所以 Flag、長識別字可以在這裡折行，而不會像連字號那樣改變內容）。
BREAK_AFTER = ('\\_', '/', ':', '.', ',', '-')


def add_breaks(body: str) -> str:
    out, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        # 轉義序列 \X：X 是可斷字的標點時，後面給一個斷行機會
        if c == '\\' and i + 1 < n:
            nxt = body[i + 1]
            out.append(body[i:i + 2]); i += 2
            if nxt in '_{}%$&#' or nxt in '.,;:!?' or nxt.isalpha() is False:
                out.append(r'\allowbreak{}')
            continue
        # 空的 {} 群組（例如 \textquotesingle{}、\textbackslash{}）之後
        if c == '{' and i + 1 < n and body[i + 1] == '}':
            out.append('{}'); i += 2
            out.append(r'\allowbreak{}')
            continue
        out.append(c); i += 1
        if c in '/:.,-' and i < n and (body[i].isalnum() or body[i] in '_\\'):
            out.append(r'\allowbreak{}')
    return ''.join(out)


VERBATIM_OPEN = (r'\begin{Verbatim}[breaklines=true,breakanywhere=true,'
                 r'breakautoindent=false,fontsize=\fontsize{7.0}{9.5}\selectfont]')


def postprocess_tex(tex: str) -> str:
    tex = tex.replace(VERBATIM_OLD, VERBATIM_NEW)
    # pandoc 對「沒有語言標記」的程式碼區塊用 plain verbatim，
    # 那個環境不吃 \fvset（所以字級是 10pt 而且不會斷行）→ 換成 fvextra 的 Verbatim。
    tex = tex.replace(r'\begin{verbatim}', VERBATIM_OPEN)
    tex = tex.replace(r'\end{verbatim}', r'\end{Verbatim}')

    out, i, marker = [], 0, r'\texttt{'
    while True:
        j = tex.find(marker, i)
        if j < 0:
            out.append(tex[i:]); break
        out.append(tex[i:j])
        k, depth = j + len(marker), 1
        while k < len(tex) and depth > 0:
            ch = tex[k]
            if ch == '{' and tex[k - 1] != '\\':
                depth += 1
            elif ch == '}' and tex[k - 1] != '\\':
                depth -= 1
                if depth == 0:
                    break
            k += 1
        out.append(marker + add_breaks(tex[j + len(marker):k]) + '}')
        i = k + 1
    return ''.join(out)


# --------------------------------------------------------------------------
def main():
    text = preprocess()
    open(MD, 'w', encoding='utf-8').write(text)

    fc, ncp, nrange = gen_fontclasses(text)
    open(os.path.join(HERE, 'fontclasses.tex'), 'w', encoding='utf-8').write(fc)
    print('前處理：%d 行 md；%d 個字元歸入半寬 class（%d 個區間）'
          % (len(text.splitlines()), ncp, nrange))

    os.environ['TEXINPUTS'] = HERE + ':' + os.environ.get('TEXINPUTS', '')

    import pypandoc
    tex = pypandoc.convert_file(MD, 'latex', extra_args=[
        '--standalone',
        '--template=' + os.path.join(HERE, 'template.latex'),
        '-f', 'markdown-tex_math_dollars+pipe_tables+footnotes+strikeout',
        '--syntax-highlighting=tango',
        '--toc', '--toc-depth=1',
        '--metadata', 'title=Sunshine CTF 2025 — pwn 全 7 題完整 Write-up',
    ])
    tex = postprocess_tex(tex)
    texp = os.path.join(HERE, 'build.tex')
    open(texp, 'w', encoding='utf-8').write(tex)
    print('LaTeX 產生完成：%d 行' % len(tex.splitlines()))

    # 跑 3 次：第 1 次排版、第 2/3 次收斂目錄與交互參照
    for n in (1, 2, 3):
        r = subprocess.run(['xelatex', '-interaction=nonstopmode', '-halt-on-error',
                            'build.tex'],
                           cwd=HERE, capture_output=True, text=True)
        if r.returncode != 0:
            tail = (r.stdout or '')[-4000:]
            print('xelatex pass %d FAILED\n%s' % (n, tail))
            return 1
    pdf = os.path.join(HERE, 'build.pdf')
    if not os.path.exists(pdf):
        print('FAIL: build.pdf 不存在')
        return 1
    import shutil
    shutil.copyfile(pdf, OUT)
    print('產出：%s  (%.2f MB)' % (OUT, os.path.getsize(OUT) / 1e6))
    return 0


if __name__ == '__main__':
    sys.exit(main())
