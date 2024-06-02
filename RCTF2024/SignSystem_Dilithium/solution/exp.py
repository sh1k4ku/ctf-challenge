from dilithium import *
from pwn import process, context, remote
from os import urandom
from hashlib import shake_256
from sage.all import *
import time

K = 4
L = 3
eta = 2
D = 13
gamma1 = 1 << 17
gamma2 = (q-1) // 88
beta = 78
OMEGA = 80
tau = 39
N = 256

F = GF(q)
P = PolynomialRing(F, 'X')
X = P.gens()[0]
R = P.quotient_ring(X**N + 1, 'x')


def CenteredModulo(r, alpha):
    if type(r) == list:
        for i in range(len(r)):
            r[i] = CenteredModulo(int(r[i]), alpha)
    else:
        r = r % alpha
        if r > alpha/2:
            r -= alpha

    return r


def read_pk():
    io.recvuntil(b"This is your public key: ")
    pk = io.recvline().strip().decode()
    return pk


def convolution_matrix(vector):
    n = len(vector)
    conv_matrix = [[0] * n for _ in range(n)]

    for i in range(n):
        for j in range(n):
            conv_matrix[i][j] = vector[(i - j) % n]
            if (i - j) < 0:
                conv_matrix[i][j] = -conv_matrix[i][j]
    
    return conv_matrix


def sign_(m, bound = 26):
    io.sendline(b"1")
    io.recvline()
    io.sendline(m.encode())
    data = io.recvuntil(b"Please input the number you want to choose:\n").decode().strip().split("\n")
    sig = data[-2]
    c_, z, h = unpack_sig(bytes.fromhex(sig))
    cp = []
    c = poly_challenge(c_)
    for i in range(N):
        coeff = int(c[i])
        if coeff > q // 2:
            coeff -= q
        cp.append(coeff)

    conv_cp = convolution_matrix(cp)
    cp = R(cp)
    for i in range(L):
        for j in range(N):
            coeff = CenteredModulo(int(z[i][j]), q)
            if abs(coeff) <= bound:
                ssp_datas[i].append(conv_cp[j]+[coeff])

        # print()

def forge_signature(pk, s1):
    rho, t1 = unpack_pk(pk)
    target = b"yijiujiuqinian, woxuehuilekaiqiche, shangpoxiapoyasileyiqianduo."
    mu = shake_256(shake_256(pk).digest(int(48)) + target).digest(int(48))
    Ahat = matrix_expand(rho)
    while True:
        y = polyvecl_uniform_gamma1(urandom(64))
        y_range = False

        for i in range(L):
            for j in range(N):
                tmp = CenteredModulo(int(y[i][j]), q)
                if not -(gamma1-1) <= tmp <= gamma1:
                    y_range = True
                    break
        if y_range:
            continue
        

        w = compute_A_mul_v(Ahat, y)
        w1, _ = polyveck_decompose(w)
        w1_packed = polyveck_pack_w1(w1)
        c = shake_256(mu + w1_packed).digest(int(32))
        cp = poly_challenge(c)
        z = y + cp * s1
        verify_w1_ = compute_A_mul_v(Ahat, z) - cp * t1 * 2**D
        verify_w1, _ = polyveck_decompose(verify_w1_)

        h = verify_w1 - w1
        n = flatten([list(h__) for h__ in h]).count(1)
        if n > OMEGA:
            exit()

        w1_ = polyveck_use_hint(verify_w1_, h)
        print(f"w1 - w1_ = {w1 - w1_}")
        sig = pack_sig(c, z, h) + target
        # print(f"sig = {sig.hex()}")
        if verify(sig, pk) != False:
            return sig
        else:
            exit()

def flatter(M):
    from subprocess import check_output
    from re import findall
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def check_lll(v, m):
    if all(_ == 0 for _ in v[:m]):
        if all(abs(_) <= 2 for _ in v[m:-1]):
            if v[-1] == -1:
                return [int(_) for _ in v[m:-1]]
            elif v[-1] == 1:
                return [-int(_) for _ in v[m:-1]]
            else:
                return False
        else:
            return False
    else:
        return False


def ssp_solver(datas):
    weight = 2**300
    m = len(datas)
    print(f"m = {m}")
    if m < 165:
        return

    M = weight * matrix(ZZ, datas)
    M = M.T

    M = M.augment(identity_matrix(ZZ, N+1))
    print(f"starting lll")
    ML = flatter(M)
    for j in range(N+1):
        vec = ML[j]
        s = check_lll(vec, m)
        if s:
            print(f"vec_{j+1} find")
            return s
    for i in range(3):
        print(f"Round {i+1}")
        ML = ML.LLL()
        for j in range(N+1):
            vec = ML[j]
            s = check_lll(vec, m)
            if s:
                print(f"Round {i+1} in vec_{j+1} find")
                return s
    return None


# context(log_level='debug')
times = 0
while True:
    times += 1
    print(f"\n***********Times {times}***********\n")
    try:
        io = process('./task/task')
        # io = remote("1.94.13.174", 10089)
        ssp_datas = [[], [], []]
        chance = 18
        pk = read_pk()
        rho, t1 = unpack_pk(bytes.fromhex(pk))

        A = matrix_expand(rho)

        for i in range(chance):
            sign_(str(i))
        s1_ = []
    except AssertionError as e:
        print(e)
        continue

    t1 = time.time()
    ifrecover = True
    for i in range(L):
        s = ssp_solver(ssp_datas[i])
        if s:
            s1_.append(s)
            print(s)
        else:
            io.close()
            ifrecover = False
            break

    if not ifrecover:
        io.close()
        continue

    s1_recover = to_RL(s1_)

    sig = forge_signature(bytes.fromhex(pk), s1_recover)
    # print(sig)
    t2 = time.time()
    print(f"use time {t2 - t1}s.")
    io.sendline(b"2")
    print(io.recvline())
    io.sendline(sig.hex().encode())
    info = io.recvall()
    if b"Congratulations" in info:
        print(info)
        break
    
    io.close()
io.close()