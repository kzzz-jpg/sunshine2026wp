import time
from pwn import *
context.log_level='error'; context.timeout=5
HERE='/home/kzzz/Documents/code/ctf/sunshine/pwn4'
io = process([HERE+'/ld-linux-x86-64.so.2','--library-path',HERE,HERE+'/cache_money'])
io.recvuntil(b'>>> ')
io.send(b'1\nX\n32\n')
time.sleep(0.4); print('A:', io.recvrepeat(0.5)[:200])
payload = b'B'*32
io.send(b'2\n0\n' + payload)
time.sleep(0.4); print('B:', io.recvrepeat(1.0)[:300])
io.send(b'3\n0\n')
time.sleep(0.4); print('C:', io.recvrepeat(1.0)[:300])
