from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from secrets import FLAG

FAKE_NUM = 3

# Base field
a = 49
b = 36
p = 2**a * 3**b - 1


def get_canonical_basis(E, l, e):
    assert (p+1) % l^e == 0
    P = E(0)
    while (l^(e-1))*P == 0:
        P = ((p+1) // l^e) * E.random_point()
    Q = P
    while P.weil_pairing(Q, l^e)^(l^(e-1)) == 1:
        Q = ((p+1) // l^e) * E.random_point()
    return P, Q


def gen_torsion_points(E):
    Pa, Qa = get_canonical_basis(E, 2, a)
    Pb, Qb = get_canonical_basis(E, 3, b)
    return Pa, Qa, Pb, Qb


def hash_function(J):
    return (bytes_to_long(sha256(str(J[0]).encode()).digest()) // 2 * 2 + 1)  % 2^a, \
        (bytes_to_long(sha256(str(J[1]).encode()).digest()) // 2 * 2 + 1) % 2^a


def get_Fp2(i):
    return int(input()) + int(input())*i


def get_ECC_and_points():
    Ea4 = get_Fp2(i)
    Ea6 = get_Fp2(i)
    Ea = EllipticCurve(Fp2, [0,6,0,Ea4, Ea6])
    P = Ea(get_Fp2(i), get_Fp2(i))
    Q = Ea(get_Fp2(i), get_Fp2(i))
    return Ea, P, Q


class ZKP:

    def __init__(self, E, kernel):
        self.P0, self.Q0 = get_canonical_basis(E, 3, b)
        self.E0 = E
        self.chall_lst = []
        self.CHALL_NUM = 16
        self.kernel = kernel
        self.ker_phi = self.E0.isogeny(self.kernel, algorithm="factored")
        print(f"{self.P0 = }")
        print(f"{self.Q0 = }")


    def _commit(self):
        print("Give me E2:")
        E2a4 = get_Fp2(i)
        E2a6 = get_Fp2(i)
        self.E2 = EllipticCurve(Fp2, [E2a4, E2a6])

        self.P2, self.Q2 = get_canonical_basis(self.E2, 3, b)
        print(f"{self.P2 = }")
        print(f"{self.Q2 = }")

        self.E3, self.P3, self.Q3 = get_ECC_and_points()
        assert self.E3.is_supersingular()


    def _challenge(self, c=None):
        if c is None:
            self.chall = randint(0,1)
        else:
            self.chall = c
        print(f"chall = {self.chall}")


    def _verify(self):
        print("Your response:")

        if self.chall:
            Kphi_ = self.E2(get_Fp2(i), get_Fp2(i))
            assert 2^a * self.E2(Kphi_) == self.E2(0)
            phi_ = self.E2.isogeny(Kphi_, algorithm="factored")
            assert self.E3.j_invariant() == phi_.codomain().j_invariant()
            assert phi_(self.P2) == self.P3 and phi_(self.Q2) == self.Q3
        else:
            resp = input()
            sigma, delta = [int(_) for _ in resp.split(",")]
            Kbar_psi = sigma * self.P2 + delta * self.Q2
            Kbar_psi_ = sigma * self.P3 + delta * self.Q3
            assert 3^b * Kbar_psi == self.E2(0) and 3^b * Kbar_psi_ == self.E3(0)
            E0_ = self.E2.isogeny(Kbar_psi, algorithm="factored").codomain()
            E1_ = self.E3.isogeny(Kbar_psi_, algorithm="factored").codomain()
            assert E0.j_invariant() == E0_.j_invariant() and EA.j_invariant() == E1_.j_invariant()
            assert self.ker_phi.codomain().j_invariant() == E1_.j_invariant()
        return True


    def run(self):
        self.chall_lst = [randint(0,1) for _ in range(self.CHALL_NUM)]
        while sum(self.chall_lst) == 0 or sum(self.chall_lst) == self.CHALL_NUM:
            self.chall_lst = [randint(0, 1) for _ in range(self.CHALL_NUM)]

        for _ in range(self.CHALL_NUM):
            print(f"Now, for the {_} round of PoK:")
            self._commit()
            self._challenge(self.chall_lst[_])
            if not self._verify():
                return False
        return True


Fpx = PolynomialRing(GF(p), "x")
x = Fpx.gen()
Fp2.<i> = GF(p**2, modulus=[1,0,1])

E0 = EllipticCurve(Fp2, [0, 6, 0, 1, 0])
E0.set_order((p+1)**2)

# Public parameters
Pa,Qa,Pb,Qb = gen_torsion_points(E0)
print(f"Pa = {Pa}")
print(f"Qa = {Qa}")
print(f"Pb = {Pb}")
print(f"Qb = {Qb}")

Ea, phiPb, phiQb = get_ECC_and_points()
assert Ea.is_supersingular()

Sb = randint(0, 3^b-1)
Tb = randint(0, 3^b-1)
R = Sb * Pb + Tb * Qb
psi = E0.isogeny(R, algorithm="factored")
Eb, psiPa, psiQa = psi.codomain(), psi(Pa), psi(Qa)
print(f"{Eb}")
print(f"psiPa = {psiPa}")
print(f"psiQa = {psiQa}")

J = Ea.isogeny(Sb*phiPb + Tb*phiQb, algorithm="factored").codomain().j_invariant()

Sa, Ta = hash_function(J)
EA = E0.isogeny(Sa*Pa + Ta*Qa, algorithm="factored").codomain()

s = set()
for _ in range(FAKE_NUM):
    print("Give me your share: ")

    kernel = E0(get_Fp2(i), get_Fp2(i))
    assert 2^a * kernel == E0(0) and 2^(a-2) * kernel != E0(0)
    zkp = ZKP(E0, kernel)

    if all(kernel.weil_pairing(PP, 2^a) != 1 for PP in s) and zkp.run():
        print("Good Job!")
        s.add(kernel)
    else:
        print("Out, you are cheating!")
        break

if len(s) == FAKE_NUM:
    print("You are a master of isogeny and ZKP.")
    print(FLAG)

