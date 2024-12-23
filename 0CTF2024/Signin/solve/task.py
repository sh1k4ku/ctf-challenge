from Crypto.Util.number import bytes_to_long
from string import ascii_lowercase
from sympy import nextprime
import numpy as np
import random
import signal
import os


def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

timeout = 60
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)

flag = b'0ctf{7he_S3cur1ty_0f_LWE_Do5e_not_Re1y_on_the_Secret_Distribution, but_the_3rr0r_Distribu7ion~~~~~~}'

def uniform_sample(n, bound, SecureRandom):
    return [SecureRandom.randrange(-bound, bound) for _ in range(n)]


def ternary_sample(n, ternaryL, SecureRandom):
    return [ternaryL[int(_)] for __ in range(n // 5) for _ in np.base_repr(ord(SecureRandom.choice(ascii_lowercase)), 3)]

n = 137
m = 220
q = nextprime(1337)
e_L = [0, 101, 731]
R_s= random.SystemRandom()
s = np.array(uniform_sample(n, q//2, R_s))
R_e = random.SystemRandom()
e = np.array(ternary_sample(m, e_L, R_e))
seed = os.urandom(16)
R_A = random
R_A.seed(seed)
A = np.array([uniform_sample(n, q, R_A) for _ in range(m)])
b = (A.dot(s) + e) % q
print(f"{seed.hex() = }")
print(f"{b.tolist() = }")
s_ = input("Give me s: ")
if s_ == str(s.tolist()):
    print("Congratulations! You have signed in successfully.")
    print(flag)
else:
    print("Sorry, you cannot sign in.")