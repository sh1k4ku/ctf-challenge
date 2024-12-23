from Crypto.Util.number import bytes_to_long, long_to_bytes
import ctypes
import hashlib
import os
import struct
import hashlib
from random import randint
from tqdm import trange
from kyber_util import *
import numpy as np  
from lwe_lattice import *
from sage.all import matrix, Zmod, vector
import time

is_term = True
for key,value in os.environ.items():
    if key == "TERM":
        is_term = False
if is_term:
    os.environ["TERM"] = "xterm"
from pwn import remote, process, context


q = 3329
k = 2


def u32(n):
    return n & 0xFFFFffff

#
# Ordering of the message words
#

# The permutation rho
rho = [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]

# The permutation pi(i) = 9i + 5  (mod 16)
pi = [(9*i + 5) & 15 for i in range(16)]

# Round permutation r (left line)
rl = [range(16)]                    # id
rl += [[rho[j] for j in rl[-1]]]    # rho
rl += [[rho[j] for j in rl[-1]]]    # rho^2
rl += [[rho[j] for j in rl[-1]]]    # rho^3
rl += [[rho[j] for j in rl[-1]]]    # rho^4

# r' (right line)
rr = [list(pi)]                     # pi
rr += [[rho[j] for j in rr[-1]]]    # rhopi
rr += [[rho[j] for j in rr[-1]]]    # rho^2 pi
rr += [[rho[j] for j in rr[-1]]]    # rho^3 pi
rr += [[rho[j] for j in rr[-1]]]    # rho^4 pi

#
# Boolean functions
#

# f (x, y, z) = x ^ y ^ z
f1 = lambda x, y, z: x ^ y ^ z

# f (x, y, z) = (x ^ y) v (!x ^ z)
f2 = lambda x, y, z: (x & y) | (~x & z)

# f (x, y, z) = (x v !y) ^ z
f3 = lambda x, y, z: (x | ~y) ^ z

# f (x, y, z) = (x ^ z) v (y ^ !z)
f4 = lambda x, y, z: (x & z) | (y & ~z)

# f (x, y, z) = x ^ (y v !z)
f5 = lambda x, y, z: x ^ (y | ~z)

# boolean functions (left line)
fl = [f1, f2, f3, f4, f5]

# boolean functions (right line)
fr = [f5, f4, f3, f2, f1]

#
# Shifts
#

# round   X0  X1  X2  X3 ...
_shift1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
_shift2 = [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7]
_shift3 = [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9]
_shift4 = [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6]
_shift5 = [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]

# shifts (left line)
sl = [[_shift1[rl[0][i]] for i in range(16)]]
sl.append([_shift2[rl[1][i]] for i in range(16)])
sl.append([_shift3[rl[2][i]] for i in range(16)])
sl.append([_shift4[rl[3][i]] for i in range(16)])
sl.append([_shift5[rl[4][i]] for i in range(16)])

# shifts (right line)
sr = [[_shift1[rr[0][i]] for i in range(16)]]
sr.append([_shift2[rr[1][i]] for i in range(16)])
sr.append([_shift3[rr[2][i]] for i in range(16)])
sr.append([_shift4[rr[3][i]] for i in range(16)])
sr.append([_shift5[rr[4][i]] for i in range(16)])

#
# Constants
#

_kg = lambda x, y: int(2**30 * (y ** (1.0 / x)))

# constants (left line)
KL = [
    0,          # Round 1: 0
    _kg(2, 2),  # Round 2: 2**30 * sqrt(2)
    _kg(2, 3),  # Round 3: 2**30 * sqrt(3)
    _kg(2, 5),  # Round 4: 2**30 * sqrt(5)
    _kg(2, 7),  # Round 5: 2**30 * sqrt(7)
]

# constants (right line)
KR = [
    _kg(3, 2),  # Round 1: 2**30 * cubert(2)
    _kg(3, 3),  # Round 2: 2**30 * cubert(3)
    _kg(3, 5),  # Round 3: 2**30 * cubert(5)
    _kg(3, 7),  # Round 4: 2**30 * cubert(7)
    0,          # Round 5: 0
]

# cyclic rotate
def rol(s, n):
    assert 0 <= s <= 31
    assert 0 <= n <= 0xFFFFffff
    return u32((n << s) | (n >> (32-s)))


def box(h, f, k, x, r, s):
    assert len(s) == 16
    assert len(x) == 16
    assert len(r) == 16
    (a, b, c, d, e) = h
    for word in range(16):
        T = u32(a + f(b, c, d) + x[r[word]] + k)
        T = u32(rol(s[word], T) + e)
        (b, c, d, e, a) = (T, b, rol(10, c), d, e)
    return (a, b, c, d, e)

def _compress(h, x):    # x is a list of 16 x 32-bit words
    hl = hr = h

    # Iterate through all 5 rounds of the compression function for each parallel pipeline
    for round in range(5):
        # left line
        hl = box(hl, fl[round], KL[round], x, rl[round], sl[round])
        # right line
        hr = box(hr, fr[round], KR[round], x, rr[round], sr[round])

    # Mix the two pipelines together
    h = (u32(h[1] + hl[2] + hr[3]),
         u32(h[2] + hl[3] + hr[4]),
         u32(h[3] + hl[4] + hr[0]),
         u32(h[4] + hl[0] + hr[1]),
         u32(h[0] + hl[1] + hr[2]))

    return h

def compress(h, s):
    """The RIPEMD-160 compression function"""
    assert len(s) % 64 == 0
    p = 0
    while p < len(s):
        h = _compress(h, struct.unpack("<16L", s[p:p+64]))
        p += 64
    assert p == len(s)
    return h

digest_size = 20

def update(data,ripe_h,ripe_bytes,ripe_buf):
    ripe_buf = ripe_buf.encode() if isinstance(ripe_buf, str) else ripe_buf
    data = data.encode() if isinstance(data, str) else data  # Convert data to bytes if it's str
    ripe_buf += data
    ripe_bytes += len(data)
    p = len(ripe_buf) & ~63     # p = floor(len(ripe_buf) / 64) * 64
    if p > 0:
        ripe_h = compress(ripe_h, ripe_buf[:p])
        ripe_buf = ripe_buf[p:]
    assert len(ripe_buf) < 64
    return (ripe_h,ripe_bytes,ripe_buf)

def digest(ripe_h,ripe_bytes,ripe_buf, initial_length=64):
    # Merkle-Damgard strengthening, per RFC 1320
    # We pad the input with a 1, followed by zeros, followed by the 64-bit
    # length of the message in bits, modulo 2**64.
    # ATTACK: WE ADD 64 the length of the first block which is now part of our message
    ripe_buf = ripe_buf.encode() if isinstance(ripe_buf, str) else ripe_buf
    length = ((ripe_bytes + initial_length) << 3) & (2**64-1) # The total length of the message in bits, modulo 2**64
    assert len(ripe_buf) < 64
    data = ripe_buf + b"\x80"
    if len(data) <= 56:
        # one final block
        assert len(data) <= 56
        data = struct.pack("<56sQ", data, length)
    else:
        assert len(data) <= 120
        data = struct.pack("<120sQ", data, length)
    h = compress(ripe_h, data)
    return struct.pack("<5L", *h)

def hexdigest(ripe_h,ripe_bytes,ripe_buf,initial_length):
    return digest(ripe_h,ripe_bytes,ripe_buf,initial_length).hex()


def make_padding(length):
    tmp = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    if length % 64 < 56:
        padding = tmp[0:(56-length % 64)]
    else:
        padding = tmp[0:(64+56-length % 64)]
    length = (length << 3)
    for i in range(8):
        padding.append((length >> (8*i)) % 256)

    return padding


def gen_initial_length(L):
    msg_length = L
    buf_length = msg_length % 64 + 1
    if buf_length <= 56:
        initial_length = msg_length - (msg_length % 64) + 64
    else:
        initial_length = msg_length - (msg_length % 64) + 128
    return initial_length


kyber_lib = ctypes.CDLL("./libpqcrystals_kyber512_ref.so")

class Kyber:
    def __init__(self, pk = None, sk = None):
        if pk and len(pk) == 800:
            self.pk_buf = ctypes.c_buffer(pk)
            if sk:
                self.sk_buf = ctypes.c_buffer(sk)
        else:
            self.pk_buf = ctypes.c_buffer(800)
            self.sk_buf = ctypes.c_buffer(1632)
            kyber_lib.pqcrystals_kyber512_ref_keypair(self.pk_buf, self.sk_buf)


    def parse_sk(self):
        s_bytes = bytes(self.sk_buf)[:768]
        s_buf = ctypes.c_buffer(s_bytes)
        s_veck = (ctypes.c_int16 * int(k * 256))()
        kyber_lib.pqcrystals_kyber512_ref_polyvec_frombytes(s_veck, s_buf)
        return list(s_veck), s_bytes


    # encrypt with public key
    def encrypt2(self, m):
        ct_buf = ctypes.c_buffer(768)
        m_buf = ctypes.c_buffer(m)
        r = ctypes.c_buffer(os.urandom(32))
        kyber_lib.pqcrystals_kyber512_ref_indcpa_enc(ct_buf, m_buf, self.pk_buf, r)
        return bytes(ct_buf)
    

    # decrypt with secret key
    def decrypt2(self, c):
        assert len(c) == 768
        ct_buf = ctypes.c_buffer(c)
        m_buf = ctypes.c_buffer(32)
        kyber_lib.pqcrystals_kyber512_ref_indcpa_dec(m_buf, ct_buf, self.sk_buf)
        return bytes(m_buf)


def pad_msg(guess):
    guess = long_to_bytes(guess)
    return b'\x00' * (32 - len(guess)) + guess


def commit_round(guess, conn, alice, bob):
    def parse_gift(gift):
        idx = 1
        while True:
            if gift[idx:idx+1] == b"\x00":
                return int(gift[:idx].decode())
            idx += 1
            
    conn.recvuntil(b"Give me ciphertext of your string in hex: \n")
    msg = pad_msg(guess)
    c = bob.encrypt2(msg)
    conn.sendline(c.hex().encode())

    tmp = conn.recvline()
    if b"water" not in tmp:
        return None
    Lc = bytes.fromhex(tmp.strip().decode().split(": ")[1])
    L = alice.decrypt2(Lc)
    return parse_gift(L)


def run(conn, alice, bob):
    CHALL_NUM = 137
    stream = ''
    resp = ''
    sli = 10
    passed = False
    for i in trange(CHALL_NUM):

        streamL = len(stream)
        respL = len(resp)
        if 160 - respL < CHALL_NUM - i:
            print("excessive chance")
            return False
        elif 160 - respL == CHALL_NUM - i and not passed:
            passed = True
            print("we can win")
            sli = 1

        guess = int(stream + "1"*sli, 2)
        if len(bin(guess)[2:]) > 160:
            print("excessive length")
            return False

        commitL = commit_round(guess, conn, alice, bob)

        if i == 0 and commitL == 0:
            print("coin[0] must be 1")
            return False
        
        if commitL == sli+streamL:
            stream += '1' * sli
        elif commitL > streamL:
            stream += '1' * (commitL - streamL)
            stream += '0'
        else:
            stream += '0'
        streamL = len(stream)
        
        chall = int(conn.recvline().strip().decode().split(" = ")[1])
        if chall:
            resp = stream[:respL+1]
        else:
            resp = stream
        conn.recvuntil(b'Your response: ')
        msg = pad_msg(int(resp, 2))
        respc = bob.encrypt2(msg)
        conn.sendline(respc.hex().encode())
    if len(resp) == 160 and passed:
        return resp
    else:
        return False



def lwe_with_hint(idxs, shats, pk):
    def rotMatrix(poly):
        n = len(poly)
        A = np.array( [[0]*n for _ in range(n)] )
        for i in range(n):
            for j in range(n):
                c = 1
                if j < i:
                    c = -1
                A[i][j] = c * poly[(j-i)%n]
        return A
    
    def format_A(A):
        return np.block([[rotMatrix(list(A[i][j])) for j in range(k)] for i in range(k)])
    
    def transpose(A):
        A[0][1], A[1][0] = A[1][0], A[0][1]
        return A

    def bit_reverse(i, N=256):
        return int('{:0{width}b}'.format(i, width=N.bit_length() - 1)[::-1], 2)

    def modq_hints():
        zeta = 17
        elems = []
        for i in range(N//2):
            idx = bit_reverse(i) + 1
            elems.append(pow(zeta, idx, q))

        Z = [[0]*N for _ in range(N)]
        for i in range(N):
            for j in range(N):
                if (i + j) % 2 == 1:
                    continue
                Z[i][j] = pow(elems[i//2], j//2, q)

        V = []
        l = []
        for i in range(len(idxs)//2):
            tmp = Z[idxs[i]][:]
            tmp.extend(Z[idxs[-i]][:])
            V.append(tmp)
            l.append(shats[i])

        # remove redundant equations
        Vm = matrix(Zmod(q), V)
        rank_V = Vm.rank()
        print(f"{Vm.rank() = }")
        V_rref = Vm.rref()
        V_prime = V_rref[0:rank_V, :] 

        assert V_prime.rank() == rank_V
        print(f"{V_prime.dimensions() = }")
        U = Vm.solve_left(V_prime)
        print(f"{U.dimensions() = }")
        l_prime = U * vector(Zmod(q), l)

        V = [[int(_) for _ in row] for row in V_prime]
        l = [int(_) for _ in l_prime]
        return V, l
    
    t, A_seed = unpack_pk(pk)
    A = gen_matrix(A_seed)
    t = polyvec_invntt(t)
    A = [polyvec_invntt(a) for a in A]

    t = np.array(list(t[0]) + list(t[1]))
    A = format_A(transpose(A))
    V, l = modq_hints()
    if len(V) < 475:
        return None

    lattice = LWELattice(A, t, q, verbose=True)
    for i in range(len(V)):
        lattice.integrateModularHint(V[i], l[i] % q, q)
    lattice.reduce(maxBlocksize=40)
    s = list(lattice.s)
    print(f"{s = }")
    return s


alice = Kyber()
# context.log_level = 'debug'
while True:
    t1 = time.time()
    # conn = process(['python3', 'ZKPQC2.py'])
    conn = remote("instance.penguin.0ops.sjtu.cn", 18435)
    conn.recvuntil(b'Please provide your public key in hex: \n')
    conn.sendline(alice.pk_buf.raw.hex().encode())
    conn.recvuntil(b"This is ")
    bob_pk = bytes.fromhex(conn.recvline().strip().decode().split(": ")[1])
    leaf = bytes.fromhex(conn.recvline().strip().decode().split(": ")[1])
    bob = Kyber(pk=bob_pk)

    coins = run(conn, alice, bob)
    if coins:
        coins = long_to_bytes(int(coins, 2))
        print("Success")
        print(f"{coins.hex() = }")
    else:
        conn.close()
        continue

    L = 32
    dst = coins
    msg = b''
    idxs = []
    for i in trange(70):
        conn.recvuntil(b"give me some rubbish: ")

        pad_ = make_padding(L)
        initial_length = gen_initial_length(L)
        pad_ = [hex(x)[2:] for x in pad_]
        rubbish = ""
        for x in pad_:
            if len(x) == 1:
                x = "0" + x
            rubbish += x
        rubbish = bytes.fromhex(rubbish)
        L += len(rubbish)
        conn.sendline(rubbish.hex().encode())

        initial_h = tuple(struct.unpack("<5L", dst))
        msg += dst
        ripe_h = initial_h
        ripe_bytes = 0
        ripe_buf = ""
        (ripe_h,ripe_bytes,ripe_buf) = update(msg,ripe_h,ripe_bytes,ripe_buf)
        dst = digest(ripe_h,ripe_bytes,ripe_buf,initial_length)

        # update the msg
        idxs.extend([_ for _ in dst])
        L += len(msg)

    shats = eval(conn.recvline().strip().decode().split(": ")[1])
    try:
        ss = lwe_with_hint(idxs, shats, bob_pk)
        if ss == None:
            conn.close()
            continue

        ss = [ss[i*256:(i+1)*256] for i in range(k)]
        shat = polyvec_ntt(ss)
        s_bytes = polyvec_to_bytes(shat)

        bob_new = Kyber(pk=bob_pk, sk=s_bytes)
        seed = bob_new.decrypt2(leaf)
        print(f"{seed = }")
        conn.recvuntil(b"give me your fruit: \n")
        conn.sendline(seed.hex().encode())
        res = conn.recvall()
        if b"flag" in res:
            print(res)

            t2 = time.time()
            print(f"Time: {t2-t1}")

            break
        else:
            t2 = time.time()
            print(f"Time: {t2-t1}")
            conn.close()
            continue
    except BrokenPipeError:
        conn.close()
        continue