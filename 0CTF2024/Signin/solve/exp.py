import os
from sage.all import matrix, vector, Zmod, ZZ, sqrt, PolynomialRing, inverse_mod, Sequence, identity_matrix, zero_matrix
from sympy import nextprime
from tqdm import trange
from time import time
import random
import numpy as np

is_term = True
for key,value in os.environ.items():
    if key == "TERM":
        is_term = False
if is_term:
    os.environ["TERM"] = "xterm"
from pwn import remote, process, context


n = 137
m = 220
h = 44
q = nextprime(1337)
samples = m - n


def balancemod(v):
    return int((v + q//2) % q) - q//2



def uniform_sample(n, bound, SecureRandom):
    return [SecureRandom.randrange(-bound, bound) for _ in range(n)]


def scale(A, b):
    inv = inverse_mod(731, q)
    A = A * inv
    b = b * inv
    return A, b


def rebuild(A, b):
    A = A.rows()
    A1 = []
    A2 = []
    b1 = []
    b2 = []
    for i, vec in enumerate(A):
        if i % 5 == 0:
            A1.append(vec)
            b1.append(b[i])
        else:
            A2.append(vec)
            b2.append(b[i])
    A1.extend(A2)
    A = matrix(Zmod(q), A1)
    b = vector(Zmod(q), b1 + b2)
    return A, b
    

def solve(A, b, e, samples):
    unknown = n - h
    P = PolynomialRing(Zmod(q), 'x', unknown)
    xs = P.gens()
    b_bar = b[:n] - vector(list(e) + list(xs))
    L = A[:n].solve_left(A[n:])
    L = L * b_bar
    F = []
    for i in range(samples):
        pol = (L[i] - b[n+i])
        F.append(pol)
    aa, _ = Sequence(F).coefficient_matrix()
    B = aa.T.change_ring(ZZ)
    print(f"{B.dimensions() = }")
    B = B.augment(-identity_matrix(unknown+1))
    B = B.stack((q * identity_matrix(samples, samples)).augment(zero_matrix(samples, unknown+1)))
    B_ = B.dense_matrix().BKZ(blocksize=20)
    ans = B_[0][samples:-1]
    if -1 in list(ans):
        ans = -ans
    if set(ans) != set([-1, 0, 1]):
        print("No solution found")
        return None
    s = A[:n].solve_right(b[:n] - vector(list(e) + list(ans)))
    return s


t1 = time()
conn = process(["python3", 'task.py'])
# conn = remote('instance.penguin.0ops.sjtu.cn', int(18447))
seed = bytes.fromhex(conn.recvline().strip().decode().replace("'", '').split(' = ')[1])
b = eval(conn.recvline().strip().decode().split(' = ')[1])

b = vector(Zmod(q), b)
R_A = random
R_A.seed(seed)
A = matrix(Zmod(q), [uniform_sample(n, q, R_A) for _ in range(m)])

A, b = scale(A, b)

A, b = rebuild(A, b)
b -= vector([1] * m)
s = solve(A, b, [1]*h, samples)
s = [balancemod(i) for i in s]
print(f"{s = }")
if s is None:
    exit()
conn.sendafter(b"Give me s: ", str(s).encode()+b'\n')
print(conn.recvall().decode())
t2 = time()
print(f"Time: {t2-t1}")
