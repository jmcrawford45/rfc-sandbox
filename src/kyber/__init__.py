from typing import *
from rfc_4634.sha import *
from dataclasses import dataclass

# TODO: consider implementing shake and sha3
from hashlib import sha3_256, sha3_512, shake_256, shake_128


@dataclass
class KeyPair:
    public: bytes
    private: bytes


class Kyber:
    k: int
    eta_1: int
    eta_2: int
    d_u: int
    d_v: int

    @classmethod
    def inner_key_gen(cls, seed: bytes) -> KeyPair:
        rho, sigma = g(seed)
        a_hat = sample_matrix(rho)
        s = sample_noise(sigma, cls.eta_1, 0)
        e = sample_noise(sigma, cls.eta_1, cls.k)
        s_hat = ntt(s)
        t_hat = a_hat * s_hat + ntt(e)
        return KeyPair(encode(t_hat, 12) + rho, encode(s_hat, 12))

    @classmethod
    def inner_encrypt(
        cls, msg: bytes, public_key: bytes, seed: bytes
    ) -> bytes:
        t_hat, rho = public_key[:-32], public_key[-32:]
        t_hat = decode(t_hat, 12)
        a_hat = sample_matrix(rho)
        r = sample_noise(seed, cls.eta_1, 0)
        e_1 = sample_noise(seed, cls.eta_2, cls.k)
        e_2 = sample_noise(seed, cls.eta_2, 2 * cls.k)[0]
        r_hat = ntt(r)
        u = inv_ntt(transpose(a_hat) * r_hat) + e_1
        v = inv_ntt(t_hat * r_hat) + e_2 + decompress(decode(msg, 1), 1)
        c_1 = encode(compress(u, cls.d_u), cls.d_u)
        c_2 = encode(compress(v, cls.d_v), cls.d_vd_v)
        return c_1 + c_2

    @classmethod
    def inner_decrypt(cls, ciphertext: bytes, private_key: bytes) -> bytes:
        c_1, c_2 = ciphertext[: cls.d_u * cls.k], ciphertext[cls.d_u * cls.k :]
        u = decompress(decode(c_1, cls.d_u), cls.d_u)
        v = decompress(decode(c_2, cls.d_v), cls.d_v)
        s_hat = decode(private_key, 12)
        m = v - inv_ntt(s_hat * ntt(u))
        return encode(compress(m))

    @classmethod
    def key_gen(cls, seed: bytes) -> KeyPair:
        cpa_seed, z = seed[:32], seed[32:]
        cpa_key_pair = cls.inner_key_gen(cpa_seed)
        h = h(cpa_key_pair.public)
        return KeyPair(
            cpa_key_pair.public,
            cpa_key_pair.private + cpa_key_pair.public + h + z,
        )

    @classmethod
    def encapsulate(
        cls, public_key: bytes, seed: bytes
    ) -> Tuple[bytes, bytes]:
        m = h(seed)
        k_bar, cpa_seed = g(m + h(public_key))
        cpa_ciphertext = cls.inner_encrypt(m, public_key, cpa_seed)
        return (cpa_ciphertext, kdf(k_bar + h(cpa_ciphertext)))

    @classmethod
    def decapsulate(cls, private_key: bytes, ciphertext: bytes) -> bytes:
        cpa_private_key, cpa_public_key, h, z = (
            private_key[: cls.k * 12],
            private_key[cls.k * 12 : cls.k * 24 + 32],
            private_key[-64:-32],
            private_key[-32:],
        )
        m_2 = cls.inner_decrypt(ciphertext, cpa_private_key)
        k_bar_2, cpa_seed_2 = g(m_2, h)
        ciphertext_2 = cls.inner_encrypt(m_2, cpa_public_key, cpa_seed_2)
        k_1 = kdf(k_bar_2 + h(ciphertext))
        k_2 = kdf(z + k(ciphertext))
        # TODO: make this constant time
        return k_1 if ciphertext == ciphertext_2 else k_2


def ntt(s):
    pass


def inv_ntt(s):
    pass


def transpose(matrix: list[list[Any]]) -> list[list[Any]]:
    return [
        [matrix[col][row] for col in range(len(matrix[0]))]
        for row in range(len(matrix))
    ]


class Kyber512(Kyber):
    k = 2
    eta_1 = 3
    eta_2 = 2
    d_u = 10
    d_v = 4


class Kyber768(Kyber):
    k = 3
    eta_1 = 2
    eta_2 = 2
    d_u = 10
    d_v = 4


class Kyber1024(Kyber):
    k = 4
    eta_1 = 2
    eta_2 = 2
    d_u = 11
    d_v = 5


class Ring:
    pass


def compress(x: Union[int, list[int]], bit_len: int):
    if isinstance(x, list):
        return [compress(e, bit_len) for e in x]
    return umod(round(2**bit_len / FIELD_SIZE * x), 2**bit_len)


def decompress(x: Union[int, list[int]], bit_len: int):
    if isinstance(x, list):
        return [decompress(e, bit_len) for e in x]
    return round(FIELD_SIZE / (2**bit_len) * x)


def encrypt():
    pass


def decrypt():
    pass


FIELD_SIZE = 13 * 2**8 + 1

umod = lambda a, q: a % q


def smod(a, m):
    return (a % m) - (m // 2)


def norm(a: Union[int, list[int]]):
    if isinstance(a, list):
        return max(norm(e) for e in a)
    return abs(smod(a, FIELD_SIZE))


class Polynomial:
    n: int
    zeta: int

    def __init__(self, coefficients=None):
        self.coefficients = coefficients

    def __add__(self, other):
        coefficients = []
        for a, b in zip(self.coefficients, other.coefficients):
            coefficients.append(a + b)
        return Polynomial(coefficients)

    def __mul__(self, other):
        # TODO: NTT
        pass


class KyberPolynomial(Polynomial):
    n = 256
    zeta = 17


xof = lambda seed: shake_128(seed)
prf = lambda seed, counter: shake_256(seed, counter)
kdf = lambda msg: shake_256(msg)[:32]
h = lambda msg: sha3_256(msg)
g = lambda msg: (sha3_512(msg)[:32], sha3_512(msg)[:32])


def octets_to_bits(octets: list[int]) -> list[int]:
    out = []
    for i in range(len(octets) * 8):
        out.append(umod(octets[i >> 3] >> (umod(i, 8)), 2))
    return out


def encode(p: Union[int, Polynomial], w):
    # TODO
    if isinstance(p, Polynomial):
        return [encode(coefficient) for coefficient in p.coefficients]
    pass


def decode(p, w):
    pass


# adapted from draft-cfrg-schwabe-kyber-01
def sample_uniform(stream):
    cs = []
    while True:
        b = stream.read(3)
        d1 = b[0] + 256 * (b[1] % 16)
        d2 = (b[1] >> 4) + 16 * b[2]
        for d in [d1, d2]:
            if d >= FIELD_SIZE:
                continue
            cs.append(d)
            if len(cs) == KyberPolynomial.n:
                return KyberPolynomial(cs)


def sample_matrix(rho: bytes, k: int) -> list[list[Polynomial]]:
    out = [[None] * k for row in range(k)]
    for row in range(len(out)):
        for col in range(len(out)):
            out[row][col] = sample_uniform(
                xof(
                    rho + col.to_bytes(1, "little") + row.to_bytes(1, "little")
                )
            )
    return out


def cbd(a: list[int], eta: int) -> list[int]:
    b = octets_to_bits(a)
    pass


def sample_noise(sigma: bytes, offset: int, eta: int, k: int):
    out = []
    for i in range(k):
        out.append(cbd(prf(sigma, i + offset).digest, eta))
