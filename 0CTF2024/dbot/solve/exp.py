import os
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, isPrime
from sage.all import matrix, vector, Zmod, ZZ, sqrt, PolynomialRing
from tqdm import trange
from time import time

is_term = True
for key,value in os.environ.items():
    if key == "TERM":
        is_term = False
if is_term:
    os.environ["TERM"] = "xterm"
from pwn import remote, process, context

def flatter(M):
    from subprocess import check_output
    from re import findall
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


def ortho_attack(b_diff, mod, ROUND):
    M = matrix(ZZ, ROUND, ROUND)
    weight = 2**1024
    M[0, 0] = mod * weight
    for i in range(ROUND-1):
        M[i+1, 0] = b_diff[i] * weight
        M[i+1, i+1] = 1

    ML = flatter(M)
    Mortho = ML[:ROUND-3, 1:]
    bdv = vector(Zmod(mod), b_diff)
    print(f"{Mortho.dimensions() = }")
    assert Mortho * bdv == 0

    # print(f"{Mortho * adv = }")

    M_ = Mortho.right_kernel().basis_matrix()
    return M_[0]


def small_roots(self, X=None, beta=1.0, epsilon=None, **kwds):
    from sage.misc.verbose import verbose
    from sage.matrix.constructor import Matrix
    from sage.rings.real_mpfr import RR

    N = self.parent().characteristic()

    if not self.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    beta = RR(beta)
    if beta <= 0.0 or beta > 1.0:
        raise ValueError("0.0 < beta <= 1.0 not satisfied.")

    f = self.change_ring(ZZ)

    P,(x,) = f.parent().objgens()

    delta = f.degree()

    if epsilon is None:
        epsilon = beta/8
    verbose("epsilon = %f"%epsilon, level=2)

    m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    verbose("m = %d"%m, level=2)

    t = int( ( delta*m*(1/beta -1) ).floor() )
    verbose("t = %d"%t, level=2)

    if X is None:
        X = (0.5 * N**(beta**2/delta - epsilon)).ceil()
    verbose("X = %s"%X, level=2)

    # we could do this much faster, but this is a cheap step
    # compared to LLL
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta) ]
    g.extend([x**i * f**m for i in range(t)]) # h

    B = Matrix(ZZ, len(g), delta*m + max(delta,t) )
    for i in range(B.nrows()):
        for j in range( g[i].degree()+1 ):
            B[i,j] = g[i][j]*X**j

    B =  flatter(B)

    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    R = f.roots()

    ZmodN = self.base_ring()
    roots = set([ZmodN(r) for r,m in R if abs(r) <= X])
    Nbeta = N**beta
    return [root for root in roots if N.gcd(ZZ(self(root))) >= Nbeta]


def HNP(datas, p):
    L = len(datas) + 1
    M = matrix(ZZ, L, L)
    for i in range(L - 1):
        M[i, i] = p
        M[-1, i] = datas[i]
    M[-1, -1] = 1
    ML = M.LLL()
    vec = ML[0]
    if vec[-1] < 0:
        vec = -vec
    return vec


def level1(conn):
    conn.sendafter(b"Choose one prime you prefer: ", b"2\n")
    mod = int(conn.recvline().strip().decode().split(": ")[1])
    c = int(conn.recvline().strip().decode().split(" = ")[1])
    N = int(conn.recvline().strip().decode().split(" = ")[1])
    pq = N // mod
    # print(f"{c = }")
    # print(f"{N = }")
    # print(f"{mod = }")

    datas = []

    ROUND = 80

    for i in trange(ROUND):
        x0 = int(conn.recvline().strip().decode().split(" = ")[1])
        x1 = int(conn.recvline().strip().decode().split(" = ")[1])
        v = (x1 + x0) * inverse(2, mod) % mod
        conn.sendafter(b"Give me v: ", str(v).encode() + b"\n")
        # print(conn.recvline())
        m0 = int(conn.recvline().strip().decode().split(" = ")[1])
        m1 = int(conn.recvline().strip().decode().split(" = ")[1])
        datas.append((m0 + m1) % mod)
    
    B = [datas[i] * inverse(datas[0], mod) % mod for i in range(1, ROUND)]
    ks = HNP(B, mod)
    print(f"{ks[-1] = }\n")
    if ks[-1].bit_length() not in range(490, 498):
        print(f"{ks[-1].bit_length() = }")
        return False

    cons = datas[0] * inverse(ks[-1], mod) % mod
    for i in range(2):
        cons_ = cons + i * mod
        # qh = cons_ >> 248 << 248
        # brute_bits = 2
        # qh <<= brute_bits
        # for qh_l in trange(1 << brute_bits):
        print(f"{cons_ = }")
            # qh_ = qh + qh_l
        PR = PolynomialRing(Zmod(pq), "x")
        x = PR.gen()
        f = 2 * x - cons_ + 1
        fm = f.monic()
        try:
            roots = small_roots(fm, X = 2**247, beta=0.49, epsilon=0.01)
        except:
            continue
        if roots:
            res = roots[0]
            q = int(pq-f(res))
            print("find q")
            print(f"{q = }")
            p = pq // q
            d = inverse(0x10001, (p - 1) * (q - 1) * (mod - 1))
            m = pow(c, d, N)
            conn.sendafter(b"Give me m: ", str(m).encode() + b"\n")
            res = conn.recvline()
            print(res)
            if b"Good job!" in res:
                return True
            else:
                return False
    else:
        return False


def level2(conn):
    conn.sendafter(b"Choose one prime you prefer: ", b"3\n")
    mod = int(conn.recvline().strip().decode().split(": ")[1])
    c = int(conn.recvline().strip().decode().split(" = ")[1])
    N = int(conn.recvline().strip().decode().split(" = ")[1])
    pqr = N // mod
    # print(f"{c = }")
    # print(f"{N = }")
    # print(f"{mod = }")

    datas = []
    datas_ = []
    ROUND = 40

    for i in trange(2*ROUND):
        x0 = int(conn.recvline().strip().decode().split(" = ")[1])
        x1 = int(conn.recvline().strip().decode().split(" = ")[1])
        if i < ROUND:
            v = x0
            conn.sendafter(b"Give me v: ", str(v).encode() + b"\n")
            m0 = int(conn.recvline().strip().decode().split(" = ")[1])
            m1 = int(conn.recvline().strip().decode().split(" = ")[1])
            datas.append(m0)
        else:
            v = x1
            conn.sendafter(b"Give me v: ", str(v).encode() + b"\n")
            m0 = int(conn.recvline().strip().decode().split(" = ")[1])
            m1 = int(conn.recvline().strip().decode().split(" = ")[1])
            datas_.append(m1)

    b_diff = []
    for i in range(1, ROUND):
        b_diff.append((datas[i] - datas[0]) % mod)
        
    my_a_diff_vec = ortho_attack(b_diff, mod, ROUND)
    
    if not all([int(_).bit_length() in list(range(150, 161)) for _ in my_a_diff_vec]):
        print(set([int(_).bit_length() for _ in my_a_diff_vec]))
        return False

    offset = 162
    p_plus_q_hs = []
    for j in [-1, 1]:
        a_diff = list(j * my_a_diff_vec)
        p_plus_q_hs.extend([(b_diff[1] * inverse(a_diff[1], mod) % mod + i * mod) >> offset for i in range(4)])
            

    b_diff = []
    for i in range(1, ROUND):
        b_diff.append((datas_[i] - datas_[0]) % mod)

    my_a_diff_vec = ortho_attack(b_diff, mod, ROUND)
    if not all([int(_).bit_length() in list(range(150, 161)) for _ in my_a_diff_vec]):
        print(set([int(_).bit_length() for _ in my_a_diff_vec]))
        return False

    p_minus_q_hs = []
    for j in [-1, 1]:
        a_diff = list(j * my_a_diff_vec)
        p_minus_q_hs.extend([(b_diff[1] * inverse(a_diff[1], mod) % mod + i * mod) >> offset for i in range(4)])
    solved = False
    get_p = False

    for p_plus_q_h in p_plus_q_hs:
        for p_minus_q_h in p_minus_q_hs:
            ph = (p_plus_q_h + p_minus_q_h) >> 1
            brute_bits = 4
            ph <<= brute_bits
            if not get_p:
                for phl in trange(1 << brute_bits):
                    ph_ = ph + phl

                    pl = 1
                    hbits = ph_.bit_length()
                    lbits = pl.bit_length()
                    PR = PolynomialRing(Zmod(pqr), 'x')
                    x = PR.gen()
                    f = ph_ * 2**(512 - hbits) + x * 2**lbits + pl
                    fm = f.monic()
                    try:
                        roots = small_roots(fm, X=2**(512-hbits-lbits+1), beta = 0.32, epsilon = 0.012)
                    except Exception as e:
                        # print(f"an error in find roots: {e}")
                        continue
                    if roots:
                        res = roots[0]
                        p_ = int(f(res))
                        if isPrime(p_):
                            print(f"find p: {p_}")
                            get_p = True
                            break
                    # else:
                    #     print('not root')

                else:
                    print('not root')
                    continue

            if get_p:
                qr = pqr // p_
                qh = (p_plus_q_h - p_minus_q_h) >> 21
                PR = PolynomialRing(Zmod(qr), 'y')
                y = PR.gen()
                ql = 1
                hbits = qh.bit_length()
                lbits = ql.bit_length()
                g = qh * 2**(512 - hbits) + y * 2**lbits + ql
                gm = g.monic()
                try:
                    roots = small_roots(gm, X=2**(512-hbits-lbits+1), beta = 0.49, epsilon = 0.02)
                except Exception as e:
                    continue
                if roots:
                    res = roots[0]
                    q_ = int(g(res))
                    if isPrime(q_):
                        print(f"find q: {q_}")

                        r = qr // q_
                        phi = (p_ - 1) * (q_ - 1) * (r - 1) * (mod - 1)
                        d = inverse(65537, phi)
                        m = pow(c, d, N)
                        conn.sendafter(b"Give me m: ", str(m).encode() + b"\n")
                        assert b"Good job!" in conn.recvline()
                        solved = True
                        break

            if solved:
                break
                
        if solved:
            break
    
    if solved:
        return True
    else:
        return False



con_cnt = 0
while True:
    con_cnt += 1
    solved_level1 = False
    solved_level2 = False
    t1 = time()
    # context.log_level = 'debug'
    # conn = process(["python3", "task.py"])
    conn = remote("instance.penguin.0ops.sjtu.cn", 18444)
    solved_level1 = level1(conn)
    if not solved_level1:
        conn.close()
        continue
    print(f"************************level 1 pass **********************")
    solved_level2 = level2(conn)
    if solved_level2:
        print(conn.recvall())
        t2 = time()
        print(f"a round Takes {t2 - t1}s")
        print(f"we tried {con_cnt} times")
        break
    else:
        conn.close()
        continue