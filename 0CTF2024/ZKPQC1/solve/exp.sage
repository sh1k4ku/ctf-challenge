from hashlib import sha256
from Crypto.Util.number import long_to_bytes, bytes_to_long
import os
import time

is_term = True
for key,value in os.environ.items():
    if key == "TERM":
        is_term = False
if is_term:
    os.environ["TERM"] = "xterm"
from pwn import remote, process, context

from sage.all import (
    ZZ,
    cached_function,
    EllipticCurveIsogeny,
    factor,
    set_random_seed,
)
from sage.schemes.elliptic_curves.hom_velusqrt import EllipticCurveHom_velusqrt
from sage.schemes.elliptic_curves.hom_composite import EllipticCurveHom_composite

def EllipticCurveIsogenyFactored(E, P, order=None, velu_bound=400):
    """
    Works similarly to EllipticCurveHom_composite
    but with two main additions:

    Introduces a sparse strategy for prime power
    isogenies, taken from
    https://trac.sagemath.org/ticket/34239
    This should be default soon (9.8 maybe)

    For primes l > 400, we use velusqrt as
    the algorithm. This bound was found by testing
    in tests/test_isogenies.sage

    Additionally, we allow `order` as an optional parameter
    and `velu_bound` controls when sqrtvelu kicks in
    """

    def EllipticCurveHom_velusqrt_setorder(P):
        """
        To speed things up, we manually set the order
        assuming all curves have order (p^2 - 1)^2

        I think this is fixed for 9.8, but not everyone
        will be running the latest SageMath version.
        """
        E = P.curve()
        p = E.base().characteristic()
        E._order = ZZ((p**2 - 1) ** 2)
        return EllipticCurveHom_velusqrt(E, P)

    def evaluate_factored_isogeny(phi_list, P):
        """
        Given a list of isogenies, evaluates the
        point for each isogeny in the list
        """
        for phi in phi_list:
            P = phi(P)
        return P

    def sparse_isogeny_prime_power(P, l, e, split=0.8, velu_bound=2000):
        """
        Compute chain of isogenies quotienting
        out a point P of order l**e
        https://trac.sagemath.org/ticket/34239
        """
        if l > velu_bound:
            isogeny_algorithm = lambda Q, l: EllipticCurveHom_velusqrt_setorder(Q)
        else:
            isogeny_algorithm = lambda Q, l: EllipticCurveIsogeny(
                Q.curve(), Q, degree=l, check=False
            )

        def recursive_sparse_isogeny(Q, k):
            assert k
            if k == 1:  # base case
                return [isogeny_algorithm(Q, l)]

            k1 = int(k * split + 0.5)
            k1 = max(1, min(k - 1, k1))  # clamp to [1, k-1]

            Q1 = l**k1 * Q
            L = recursive_sparse_isogeny(Q1, k - k1)

            Q2 = evaluate_factored_isogeny(L, Q)
            R = recursive_sparse_isogeny(Q2, k1)

            return L + R

        return recursive_sparse_isogeny(P, e)

    # Ensure P is a point on E
    if P.curve() != E:
        raise ValueError(f"The supplied kernel must be a point on the curve E")

    if order:
        P._order = ZZ(order)
    cofactor = P.order()

    # Deal with isomorphisms
    if cofactor == 1:
        return EllipticCurveIsogeny(P.curve(), P)

    ϕ_list = []
    for l, e in cofactor.factor():
        # Compute point Q of order l^e
        D = ZZ(l**e)
        cofactor //= D
        Q = cofactor * P

        # Manually setting the order means
        # Sage won't try and do it for each
        # l-isogeny in the iteration
        Q._order = D

        # Use Q as kernel of degree l^e isogeny
        ψ_list = sparse_isogeny_prime_power(Q, l, e, velu_bound=velu_bound)

        # Map P through chain length e of l-isogenies
        P = evaluate_factored_isogeny(ψ_list, P)
        ϕ_list += ψ_list

    # return EllipticCurveHom_composite.from_factors(ϕ_list)
    return EllipticCurveHom_composite.from_factors(ϕ_list), ϕ_list


def find_isogeny_kernel(P, Q, l, e):
    sigma = 1
    while sigma < l ^ min(10, e):
        try:
            delta = discrete_log(-sigma * P, sigma * Q, l ^ e, operation='+')
            return sigma, sigma * delta % 2^a
        except:
            pass
        sigma *= l

    sigma = 1
    while sigma < l ^ min(10, e):
        try:
            delta = discrete_log(-sigma * P, Q, l ^ e, operation='+')
            return sigma, delta
        except:
            pass
        sigma *= l
    return None, None


def hash_function(J):
    return (bytes_to_long(sha256(str(J[0]).encode()).digest()) // 2 * 2 + 1)  % 2^a, \
        (bytes_to_long(sha256(str(J[1]).encode()).digest()) // 2 * 2 + 1) % 2^a



def send_Fp2(conn, ele):
    conn.sendline(str(ele[0]).encode())
    conn.sendline(str(ele[1]).encode())


a = 49
b = 36
p = 2**a * 3**b - 1

Fpx = PolynomialRing(GF(p), "x")
x = Fpx.gen()
Fp2.<i> = GF(p**2, modulus=[1,0,1])

E0 = EllipticCurve(Fp2, [0,6,0,1, 0])
E0.set_order((p+1)**2)
print(f"{E0.order() = }")
print(f"{2^a = }")


# context.log_level = "debug"
while True:

    i = Fp2.gen()
    conn = remote('instance.penguin.0ops.sjtu.cn', int(18432))
    # conn = process(["sage", "task.sage"])
    t0 = time.time()
    conn.recvuntil(b'Pa = ')
    Pa = E0(eval(conn.recvline()[:-1].decode().replace('(','').replace(')', '').replace(':',',')))
    conn.recvuntil(b'Qa = ')
    Qa = E0(eval(conn.recvline()[:-1].decode().replace('(','').replace(')', '').replace(':',',')))
    conn.recvuntil(b'Pb = ')
    Pb = E0(eval(conn.recvline()[:-1].decode().replace('(','').replace(')', '').replace(':',',')))
    conn.recvuntil(b'Qb = ')
    Qb = E0(eval(conn.recvline()[:-1].decode().replace('(','').replace(')', '').replace(':',',')))

    Sa = randint(0, 2^a-1)
    Ta = randint(0, 2^a-1)
    R = Sa*Pa + Ta * Qa
    phi = E0.isogeny(R, algorithm='factored')
    Ea, phiPb, phiQb = phi.codomain(), phi(Pb), phi(Qb)

    send_Fp2(conn, Ea.a4())
    send_Fp2(conn, Ea.a6())
    send_Fp2(conn, phiPb[0])
    send_Fp2(conn, phiPb[1])
    send_Fp2(conn, phiQb[0])
    send_Fp2(conn, phiQb[1])

    conn.recvuntil(b'Elliptic Curve defined by y^2 = x^3 + 6*x^2 + ')
    Eba4 = Fp2(conn.recvuntil(b'*x + ')[:-5].decode())
    Eba6 = Fp2(conn.recvuntil(b' over Finite Field')[:-len(b' over Finite Field')].decode())
    Eb = EllipticCurve(Fp2, [0, 6, 0, Eba4, Eba6])

    conn.recvuntil(b'psiPa = ')
    psiPa = Eb(eval(conn.recvline()[:-1].decode().replace('(','').replace(')', '').replace(':',',')))
    conn.recvuntil(b'psiQa = ')
    psiQa = Eb(eval(conn.recvline()[:-1].decode().replace('(','').replace(')', '').replace(':',',')))

    J = Eb.isogeny(Sa*psiPa + Ta*psiQa, algorithm='factored').codomain().j_invariant()


    Sa, Ta = hash_function(J)
    print(f"{Sa = }, {Ta = }")
    print(f"{Pa.order() = }, {Qa.order() = }")
    kernel = Sa*Pa + Ta*Qa
    print(f"{kernel.order() = }")
    phiaa = E0.isogeny(kernel, algorithm='factored')


    phia_, phi_lit = EllipticCurveIsogenyFactored(E0, kernel)
    assert phiaa == phia_
    j_lst = [E0.j_invariant()]
    for phi in phi_lit:
        j_lst.append(phi.codomain().j_invariant())

    spaths = [j_lst]
    # spaths.append([287496]+spaths[0])

    f_kernel = []
    Erec = []
    for num, path in enumerate(spaths):
        print()
        phiss = [[]]
        curEs = [E0]
        for ii in range(len(path) - 1):
            newEs = []
            newphiss = []
            for curE, phis in zip(curEs, phiss):
                Tss = curE(0).division_points(2)
                # print(len(Tss))
                for T in Tss:
                    phi = curE.isogeny(kernel=T, algorithm='factored',
                                       check=False)

                    if phi.codomain().j_invariant() == path[ii + 1]:
                        tmp_phis = phis.copy()
                        tmp_phis.append(phi)
                        newphiss.append(tmp_phis)
                        newEs.append(phi.codomain())
            curEs = newEs
            phiss = newphiss


        for j in range(len(curEs)):
            EEE = curEs[j].montgomery_model()
            if EEE.a2() not in Erec:

                print(f'spath: {num}')

                phia = reduce(lambda x, y: x * y, phiss[j][::-1])

                try:
                   print(phia.codomain().montgomery_model())
                except:
                    pass

                phiaPa = phia(Pa)
                phiaQa = phia(Qa)
                assert 2 ^ a * phiaPa == phia.codomain()(0)
                assert 2 ^ a * phiaQa == phia.codomain()(0)

                sigma, delta = find_isogeny_kernel(phiaPa, phiaQa, 2, a)
                print(sigma, delta)
                OphiaQa = phiaQa.order()

                for ii in range(2 ^ a // OphiaQa):
                    ker = sigma * Pa + (ii * OphiaQa + delta) * Qa
                    if E0.isogeny(ker, algorithm='factored').codomain().j_invariant() == phia.codomain().j_invariant():
                        print('-----------', sigma, ii * OphiaQa + delta)
                        if all(ker.weil_pairing(P, 2 ^ a) != 1 for P, _ in f_kernel) and \
                                2 ^ a * ker == E0(0) and 2 ^ (a - 2) * ker != E0(0):
                                # 2 ^ a * ker == E0(0) and 2 ^ (a//2) * ker != E0(0):
                            f_kernel.append((ker, (sigma, ii * OphiaQa + delta)))
                        break


                print(E0.isogeny(ker, algorithm="factored", check=False).codomain().j_invariant())
                print(phia.codomain().j_invariant())

    print(f"{len(f_kernel)} = ")

    if len(f_kernel) < 3:
        conn.close()
        continue
    else:
        break

CHALL_NUM = 16
for ker, (sigma, delta) in f_kernel:
    def gen_resp(psi, P2, Q2):
        dual_psi = psi.dual()

        delta = None
        sigma = 1
        while sigma < 3 ^ 10:
            try:
                # print(f'{sigma = }')
                delta = discrete_log(-dual_psi(sigma * P2), dual_psi(sigma * Q2), 3 ^ b, operation='+')
                print(f'{sigma = }, {delta = }')
                conn.sendline((str(sigma)+','+str(sigma*delta)).encode())
                return
            except:
                pass
            sigma *= 3

        delta = None
        sigma = 1
        while sigma < 3 ^ 10:
            try:
                # print(f'{sigma = }')
                delta = discrete_log(-dual_psi(sigma * P2), dual_psi(Q2), 3 ^ b, operation='+')
                print(f'{sigma = }, {delta = }')
                conn.sendline((str(sigma) + ',' + str(delta)).encode())
                return
            except:
                pass
            sigma *= 3


    def run(kernel):
        conn.recvuntil(b'P0 = ')
        P0 = E0(eval(conn.recvline()[:-1].decode().replace('(', '').replace(')', '').replace(':', ',')))
        conn.recvuntil(b'Q0 = ')
        Q0 = E0(eval(conn.recvline()[:-1].decode().replace('(', '').replace(')', '').replace(':', ',')))


        for __ in range(CHALL_NUM):
            Sb = randint(0, 3 ^ b - 1)
            Tb = randint(0, 3 ^ b - 1)
            Kpsi = Sb * P0 + Tb * Q0
            psi = E0.isogeny(Kpsi, algorithm='factored')
            E2 = psi.codomain()

            conn.recvuntil(b'Give me E2:\n')
            send_Fp2(conn, E2.a4())
            send_Fp2(conn, E2.a6())
            conn.recvuntil(b'P2 = ')
            P2 = E2(eval(conn.recvline()[:-1].decode().replace('(', '').replace(')', '').replace(':', ',')))
            conn.recvuntil(b'Q2 = ')
            Q2 = E2(eval(conn.recvline()[:-1].decode().replace('(', '').replace(')', '').replace(':', ',')))

            Kphi_ = psi(kernel)
            phi_ = E2.isogeny(Kphi_, algorithm='factored')
            E3 = phi_.codomain()
            P3, Q3 = phi_(P2), phi_(Q2)

            send_Fp2(conn, E3.a4())
            send_Fp2(conn, E3.a6())
            send_Fp2(conn, P3[0])
            send_Fp2(conn, P3[1])
            send_Fp2(conn, Q3[0])
            send_Fp2(conn, Q3[1])

            # challenge
            conn.recvuntil(b'chall = ')
            chall = int(conn.recvline())

            # verify
            conn.recvuntil(b"Your response:\n")
            if chall:
                send_Fp2(conn, Kphi_[0])
                send_Fp2(conn, Kphi_[1])
            else:
                gen_resp(psi, P2, Q2)

    t1 = time.time()

    conn.recvuntil(b"Give me your share: \n")
    print(f"{ker.order() = }")
    print(f"{ker.weil_pairing(kernel, 2^a) = }" )
    send_Fp2(conn, ker[0])
    send_Fp2(conn, ker[1])
    # conn.interactive()
    # conn.sendline((str(sigma)+','+str(delta)).encode())

    run(ker)

    t2 = time.time()

    print(conn.recvline())
    print(f"The {i}-th round spend {t2-t1} seconds")

# print(conn.recvline())
print(conn.recvline())
print(conn.recvline())
t3 = time.time()
print(f"Finished attack in {t3-t0} seconds")