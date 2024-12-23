import ctypes
import hashlib
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import randint
import signal
from secrets import FLAG


def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

timeout = 120
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)

q = 3329
k = 2


kyber_lib = ctypes.CDLL("./libpqcrystals_kyber512_ref.so")

def poly_ntt(p):
    t = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_ntt(t)
    t = list(t)
    return t


def polyvec_ntt(p):
    return list([poly_ntt(p) for p in p])


class Kyber:
    def __init__(self, pk = None, sk = None):
        if pk and len(pk) == 800:
            self.pk_buf = ctypes.c_buffer(pk)
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
    

    def encrypt2(self, m):
        ct_buf = ctypes.c_buffer(768)
        m_buf = ctypes.c_buffer(m)
        r = ctypes.c_buffer(os.urandom(32))
        kyber_lib.pqcrystals_kyber512_ref_indcpa_enc(ct_buf, m_buf, self.pk_buf, r)
        return bytes(ct_buf)
    

    def decrypt2(self, c):
        assert len(c) == 768
        ct_buf = ctypes.c_buffer(c)
        m_buf = ctypes.c_buffer(32)
        kyber_lib.pqcrystals_kyber512_ref_indcpa_dec(m_buf, ct_buf, self.sk_buf)
        return bytes(m_buf)
    

class my_shake:
    def __init__(self, seed = None):
        self.idx = 0
        self.state = b""
        self.HashOr4cle = hashlib.new("ripemd160") # hash_hash
        if seed:
            self._absorb(seed)
        else:
            self._absorb()
        self._squeeze()

    
    def _absorb(self, data):
        self.HashOr4cle.update(data)


    def _squeeze(self):
        self.state += self.HashOr4cle.digest()
    

    def next(self, L = 1, data = None):
        if data:
            self._absorb(data)
        while len(self.state) - self.idx < L:
            self._absorb(self.state)
            self._squeeze()
        stream = self.state[self.idx: self.idx+L]
        self.idx += L
        return stream
            

class ZKP:
    def __init__(self, inner: Kyber, outer: Kyber, shake = None):
        if shake:
            self.shake = shake
        else:
            seed = os.urandom(32)
            self.shake = my_shake(seed)
            
        self.inner = inner
        self.outer = outer
        self.CHALL_NUM = 137
        self.L = 0
        self.slice = 10
        self.coins = bin(bytes_to_long(self.shake.next(10)))[2:].zfill(8*self.slice)


    def _commit(self):
        print("Give me ciphertext of your string in hex: ")
        cipher = bytes.fromhex(input())
        assert len(cipher) == 768
        L = self.L
        self.commit = self.inner.decrypt2(cipher)
        pre = bin(bytes_to_long(self.commit))[2:]
        while len(self.coins) < len(pre):
            self.coins += bin(bytes_to_long(self.shake.next(10)))[2:].zfill(8*self.slice)
        for i in range(self.L, len(pre)):
            if pre[i] != self.coins[i]:
                break
            L = i+1
        Lc = self.outer.encrypt2(str(L).encode())
        print(f'Your water: {Lc.hex()}')


    def _challenge(self, c = None):
        if c is None:
            self.chall = randint(0,1)
        else:
            self.chall = c
        print(f'chall = {self.chall}')


    def _verify(self):
        print('Your response: ')
        resp = bytes.fromhex(input())
        pre_ = bin(bytes_to_long(self.inner.decrypt2(resp)))[2:]
        if len(self.coins) < len(pre_):
            self.coins += bin(bytes_to_long(self.shake.next(10)))[2:].zfill(8*self.slice)
        while self.chall and len(pre_) - self.L != 1:
            return False
        for i in range(self.L, len(pre_)):
            if pre_[i] != self.coins[i]:
                return False
        self.L = len(pre_)
        return True


    def run(self):
        self.chall_lst = [randint(0,1) for _ in range(self.CHALL_NUM)]
        while sum(self.chall_lst) == 0 or sum(self.chall_lst) == self.CHALL_NUM:
            self.chall_lst = [randint(0, 1) for _ in range(self.CHALL_NUM)]

        for _ in range(self.CHALL_NUM):
            print(f'Now, for the {_} round of zkp:')
            self._commit()
            self._challenge(self.chall_lst[_])
            if not self._verify():
                print('You failed!')
                return False

        tickets = []
        weight = (self.slice + 4) / (2**(self.slice//2))
        for _ in range(int(weight * self.L)):
            rubbish = bytes.fromhex(input("give me some rubbish: "))
            ticket = [_ for _ in self.shake.next(20, rubbish)]
            tickets.extend(ticket)
        svec, _ = self.inner.parse_sk()
        s = [svec[i*256:(i+1)*256] for i in range(k)]
        hats = []
        for i in range(len(tickets) // 2):
            hats.append(s[0][tickets[i]] + s[1][tickets[-i]])
        print(f"wow, there are too many hats: {hats}")
        print('give me your fruit: ')
        fruit = bytes.fromhex(input())
        return fruit


print("Welcome to the ZKPQC challenge!")
print("Please provide your public key in hex: ")
pk = bytes.fromhex(input())
print(f"{len(pk) = }")
alice = Kyber(pk)
bob = Kyber()
print("This is my public key:", bob.pk_buf.raw.hex())
seed = os.urandom(32)
leaf = bob.encrypt2(seed)
print("This is your leaf:", leaf.hex())
shake = my_shake(seed)
print("Now, can you prove me you know the coins?")
zkp = ZKP(bob, alice, shake)
fruit = zkp.run()
if fruit == seed:
    print("Congratulations! Here is your flag:", FLAG)
else:
    print("You failed!")