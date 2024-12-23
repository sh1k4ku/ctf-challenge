from Crypto.Util.number import getPrime, bytes_to_long, inverse
from Crypto.Random.random import randrange, getrandbits
from secrets import flag
from math import prod
import os
import signal


def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

timeout = 600
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)


def Level(level, primes, ROUND):
    print(f"This is level {level}!")
    N = prod(primes)
    phi = prod([(pp - 1) for pp in primes])
    d = inverse(0x10001, phi)
    m = bytes_to_long(os.urandom(N.bit_length() // 8 - 2))
    
    c = pow(m, 0x10001, N)

    idx = int(input("Choose one prime you prefer: "))
    assert idx in list(range(len(primes))), "No such prime"
    mod = primes.pop(idx)
    print(f"Here is your prime: {mod}")
    print(f"{c = }")
    print(f"{N = }")

    if level == 0:
        a = [getrandbits(496) for _ in range(ROUND)]
        b = getrandbits(248)
        c = [getrandbits(496) for _ in range(ROUND)]
        e = b
        ph1 = [prod([(primes[0] + a[i]), (primes[1] + b)]) for i in range(ROUND)]
        ph2 = [prod([(-primes[0] + c[i]), (primes[1] + e)]) for i in range(ROUND)]
    else:
        a = [getrandbits(160) for _ in range(ROUND)]
        b = a
        c = [ai + 1 for ai in a]
        e = c
        ph1 = [prod([(primes[0] + a[i]), (primes[1] + b[i])]) for i in range(ROUND)]
        ph2 = [prod([(primes[0] - c[i]), (primes[1] + e[i])]) for i in range(ROUND)]

    for i in range(ROUND):
        x0 = randrange(0, N)
        x1 = randrange(0, N)
        print(f"{x0 = }")
        print(f"{x1 = }")
        v = int(input("Give me v: "))
        m0 = (pow(v - x0, d, mod) + ph1[i]) % mod
        m1 = (pow(v - x1, d, mod) + ph2[i]) % mod
        print(f"{m0 = }")
        print(f"{m1 = }")
    m_ = int(input("Give me m: "))
    if m_ == m:
        print("Good job!")
        return True
    else:
        print("Try again!")
        return False


primes1 = [getPrime(512) for _ in range(3)]
primes2 = [getPrime(512) for _ in range(4)]
if Level(0, primes1, 80) and Level(1, primes2, 80):
    print("This is your flag:", flag)