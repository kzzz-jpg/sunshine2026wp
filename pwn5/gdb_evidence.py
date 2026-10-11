# builds a deterministic local input stream (ASLR off) and dumps it for gdb
import os, sys
from pwn import *
context.arch='amd64'; context.log_level='info'
sys.path.insert(0,'.')
import exploit as E

io = process('./homemaker', stdin=process.PIPE, stdout=process.PIPE)
log = []
orig_send = io.send
def send(d):
    log.append(d); return orig_send(d)
io.send = send
try:
    E.exploit(io)
except Exception as e:
    print("note:", e)
open('exploit_input.bin','wb').write(b''.join(log))
print("wrote exploit_input.bin", sum(len(x) for x in log), "bytes")
print("leaked:", repr(io.recvrepeat(0.5)[:200]))
io.close()
