set -e
PANDOC=./venv/bin/python
$PANDOC - <<'PYEOF'
import pypandoc, sys
args = [
 '--pdf-engine=xelatex',
 '-V','CJKmainfont=Noto Sans CJK TC',
 '-V','CJKmonofont=Noto Sans Mono CJK TC',
 '-V','mainfont=Noto Sans CJK TC',
 '-V','monofont=Noto Sans Mono CJK TC',
 '-V','monofontoptions=Scale=0.72',
 '-V','geometry:margin=1.6cm',
 '-V','fontsize=10pt',
 '-V','breaklines',
 '-V','colorlinks',
 '--highlight-style=tango',
 '-V','linkcolor=blue!70!black',
]
try:
    pypandoc.convert_file('smoke.md','pdf',outputfile='smoke.pdf',extra_args=args)
    print('OK')
except Exception as e:
    print('FAIL:', str(e)[:3000])
PYEOF
