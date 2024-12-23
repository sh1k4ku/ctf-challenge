import ctypes
import hashlib
from Crypto.Util.number import inverse

q = 3329
k = 2
N = 256
KYBER_POLYVECCOMPRESSEDBYTES = k * 320
KYBER_POLYCOMPRESSEDBYTES = 128

kyber_lib = ctypes.CDLL('./libpqcrystals_kyber512_ref.so')


def balanced_mod(v):
    return int((v + q//2) % q) - q//2


def compressed_bytes_to_polyvec(b):
    polyvec = (ctypes.c_int16 * int(k * 256))()
    kyber_lib.pqcrystals_kyber512_ref_polyvec_decompress(polyvec, ctypes.c_buffer(b))
    return [list(polyvec)[:256], list(polyvec)[256:]]


def compressed_bytes_to_poly(b):
    poly = (ctypes.c_int16 * 256)()
    kyber_lib.pqcrystals_kyber512_ref_poly_decompress(poly, ctypes.c_buffer(b))
    return list(poly)


def bytes_to_polyvec(b):
    polyvec = (ctypes.c_int16 * int(k * 256))()
    kyber_lib.pqcrystals_kyber512_ref_polyvec_frombytes(polyvec, ctypes.c_buffer(b))
    return list([list(polyvec)[:256], list(polyvec)[256:]])

def polyvec_to_bytes(pv):
    buf = ctypes.c_buffer(int(k * 384))
    polyvec = (ctypes.c_int16 * int(k * 256))(*(list(pv[0]) + list(pv[1])))
    kyber_lib.pqcrystals_kyber512_ref_polyvec_tobytes(buf, polyvec)
    return bytes(buf)


def parse_cipher(c: bytes):
    u = c[:KYBER_POLYVECCOMPRESSEDBYTES]
    v = c[KYBER_POLYVECCOMPRESSEDBYTES:]
    u = compressed_bytes_to_polyvec(u)
    v = compressed_bytes_to_poly(v)
    return u, v


def poly_invntt(p):
    t = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_invntt(t)
    t = [balanced_mod(i * inverse(2**16, q) % q) for i in list(t)]
    return t


def polyvec_invntt(pv):
    return list([poly_invntt(p) for p in pv])


def poly_ntt(p):
    t = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_ntt(t)
    t = [_ % q for _ in list(t)]
    return t


def polyvec_ntt(p):
    return list([poly_ntt(p) for p in p])

    
def unpack_pk(pk_bytes):
    buf = pk_bytes[:k * 384]
    pv = bytes_to_polyvec(buf)
    seed = pk_bytes[k * 384:]
    return pv, seed


def gen_matrix(seed, transposed=0):
    out = ((ctypes.c_int16 * int(k * 256)) * int(k))()
    kyber_lib.pqcrystals_kyber512_ref_gen_matrix(out, ctypes.c_buffer(seed), transposed)
    o0 = list(out)[0]
    o1 = list(out)[1]
    r0 = [list(o0)[:256], list(o0)[256:]]
    r1 = [list(o1)[:256], list(o1)[256:]]
    return [r0, r1]