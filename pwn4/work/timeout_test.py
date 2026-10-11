import time
from pwn import *
context.log_level='info'
io = remote('chal.sunshinectf.games',26004)
t0=time.time()
io.recvuntil(b'>>> ')
print('[%.1fs] banner ok' % (time.time()-t0))
for w in (10, 15, 20, 25, 28, 30, 33, 40):
    while time.time()-t0 < w: time.sleep(0.2)
    try:
        io.sendline(b'6')
        d = io.recvuntil(b'>>> ', timeout=5)
        print('[%.1fs] alive, got %d bytes' % (time.time()-t0, len(d)))
    except EOFError:
        print('[%.1fs] CONNECTION DEAD' % (time.time()-t0)); break
