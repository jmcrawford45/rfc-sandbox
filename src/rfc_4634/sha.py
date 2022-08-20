from fixedint import UInt32 as Int32
from fixedint import UInt64 as Int64

W_MAP = {
    32: Int32,
    64: Int64,
}


def shr(x: int, n: int) -> int:
    return x >> n


def shl(x: int, n: int, w: int) -> int:
    return W_MAP[w](x) << n


def rotr(x: int, n: int, w: int) -> int:
    return shr(x, n) | shl(x, w - n, w)


def rotl(x: int, n: int, w: int) -> int:
    return shl(x, n, w) | shlr(x, w - n)


class Sha:
    W: int
    K: list[int]
    INITIAL_VALUE: list[int]
    BLOCK_BYTE_LEN: int
    HASH_ROUNDS: int

    @classmethod
    def ch(cls, x: int, y: int, z: int) -> int:
        x = W_MAP[cls.W](x)
        y = W_MAP[cls.W](y)
        z = W_MAP[cls.W](z)
        return (x & y) ^ ((~x) & z)

    @classmethod
    def maj(cls, x: int, y: int, z: int) -> int:
        x = W_MAP[cls.W](x)
        y = W_MAP[cls.W](y)
        z = W_MAP[cls.W](z)
        return (x & y) ^ (x & z) ^ (y & z)

    @classmethod
    def process(cls, message: bytes) -> list[int]:
        message = cls.pad(message)
        H = cls.INITIAL_VALUE
        for block_num in range(len(message) // cls.BLOCK_BYTE_LEN):
            block = message[
                block_num
                * cls.BLOCK_BYTE_LEN : (block_num + 1)
                * cls.BLOCK_BYTE_LEN
            ]
            w = []
            for word in range(len(block) // (cls.W // 8)):
                w.append(
                    int.from_bytes(
                        block[word * (cls.W // 8) : (word + 1) * (cls.W // 8)],
                        "big",
                    )
                )
            while len(w) < cls.HASH_ROUNDS:
                w.append(cls.ssig1(w[-2]) + w[-7] + cls.ssig0(w[-15]) + w[-16])
            a, b, c, d, e, f, g, h = H
            for t in range(cls.HASH_ROUNDS):
                t1 = h + cls.bsig1(e) + cls.ch(e, f, g) + cls.K[t] + w[t]
                t2 = cls.bsig0(a) + cls.maj(a, b, c)
                h = g
                g = f
                f = e
                e = d + t1
                d = c
                c = b
                b = a
                a = t1 + t2
            for i, working_variable in enumerate([a, b, c, d, e, f, g, h]):
                H[i] += working_variable
        return H


class Sha224256(Sha):
    W = 32
    BLOCK_BYTE_LEN = 64
    HASH_ROUNDS = 64
    # SHA-224 and SHA-256 use the same sequence of sixty-four constant
    #    32-bit words, K0, K1, ..., K63.  These words represent the first
    #    thirty-two bits of the fractional parts of the cube roots of the
    #    first sixty-four prime numbers.  In hex, these constant words are as
    #    follows (from left to right):

    K = [
        W_MAP[32](i)
        for i in [
            0x428A2F98,
            0x71374491,
            0xB5C0FBCF,
            0xE9B5DBA5,
            0x3956C25B,
            0x59F111F1,
            0x923F82A4,
            0xAB1C5ED5,
            0xD807AA98,
            0x12835B01,
            0x243185BE,
            0x550C7DC3,
            0x72BE5D74,
            0x80DEB1FE,
            0x9BDC06A7,
            0xC19BF174,
            0xE49B69C1,
            0xEFBE4786,
            0x0FC19DC6,
            0x240CA1CC,
            0x2DE92C6F,
            0x4A7484AA,
            0x5CB0A9DC,
            0x76F988DA,
            0x983E5152,
            0xA831C66D,
            0xB00327C8,
            0xBF597FC7,
            0xC6E00BF3,
            0xD5A79147,
            0x06CA6351,
            0x14292967,
            0x27B70A85,
            0x2E1B2138,
            0x4D2C6DFC,
            0x53380D13,
            0x650A7354,
            0x766A0ABB,
            0x81C2C92E,
            0x92722C85,
            0xA2BFE8A1,
            0xA81A664B,
            0xC24B8B70,
            0xC76C51A3,
            0xD192E819,
            0xD6990624,
            0xF40E3585,
            0x106AA070,
            0x19A4C116,
            0x1E376C08,
            0x2748774C,
            0x34B0BCB5,
            0x391C0CB3,
            0x4ED8AA4A,
            0x5B9CCA4F,
            0x682E6FF3,
            0x748F82EE,
            0x78A5636F,
            0x84C87814,
            0x8CC70208,
            0x90BEFFFA,
            0xA4506CEB,
            0xBEF9A3F7,
            0xC67178F2,
        ]
    ]

    @classmethod
    def bsig0(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 2, cls.W) ^ rotr(x, 13, cls.W) ^ rotr(x, 22, cls.W)

    @classmethod
    def bsig1(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 6, cls.W) ^ rotr(x, 11, cls.W) ^ rotr(x, 25, cls.W)

    @classmethod
    def ssig0(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 7, cls.W) ^ rotr(x, 18, cls.W) ^ shr(x, 3)

    @classmethod
    def ssig1(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 17, cls.W) ^ rotr(x, 19, cls.W) ^ shr(x, 10)

    @classmethod
    def pad(cls, message: bytes) -> bytes:
        L = len(message) * 8
        K = 448 - L
        if K <= 0:
            K += 512
        # Since L is a multiple of 8, we know that the first padded byte will be 1 << 7
        # Similarly, we also must have K divisible by 8
        return (
            message
            + int.to_bytes(1 << 7, 1, "big")
            + bytes(K // 8 - 1)
            + int.to_bytes(L, 8, "big")
        )


class Sha384512(Sha):
    W = 64
    BLOCK_BYTE_LEN = 128
    HASH_ROUNDS = 80
    # SHA-384 and SHA-512 use the same sequence of eighty constant 64-bit
    # words, K0, K1, ... K79.  These words represent the first sixty-four
    # bits of the fractional parts of the cube roots of the first eighty
    # prime numbers.  In hex, these constant words are as follows (from
    # left to right):

    K = [
        W_MAP[64](i)
        for i in [
            0x428A2F98D728AE22,
            0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F,
            0xE9B5DBA58189DBBC,
            0x3956C25BF348B538,
            0x59F111F1B605D019,
            0x923F82A4AF194F9B,
            0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242,
            0x12835B0145706FBE,
            0x243185BE4EE4B28C,
            0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F,
            0x80DEB1FE3B1696B1,
            0x9BDC06A725C71235,
            0xC19BF174CF692694,
            0xE49B69C19EF14AD2,
            0xEFBE4786384F25E3,
            0x0FC19DC68B8CD5B5,
            0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275,
            0x4A7484AA6EA6E483,
            0x5CB0A9DCBD41FBD4,
            0x76F988DA831153B5,
            0x983E5152EE66DFAB,
            0xA831C66D2DB43210,
            0xB00327C898FB213F,
            0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2,
            0xD5A79147930AA725,
            0x06CA6351E003826F,
            0x142929670A0E6E70,
            0x27B70A8546D22FFC,
            0x2E1B21385C26C926,
            0x4D2C6DFC5AC42AED,
            0x53380D139D95B3DF,
            0x650A73548BAF63DE,
            0x766A0ABB3C77B2A8,
            0x81C2C92E47EDAEE6,
            0x92722C851482353B,
            0xA2BFE8A14CF10364,
            0xA81A664BBC423001,
            0xC24B8B70D0F89791,
            0xC76C51A30654BE30,
            0xD192E819D6EF5218,
            0xD69906245565A910,
            0xF40E35855771202A,
            0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8,
            0x1E376C085141AB53,
            0x2748774CDF8EEB99,
            0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63,
            0x4ED8AA4AE3418ACB,
            0x5B9CCA4F7763E373,
            0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC,
            0x78A5636F43172F60,
            0x84C87814A1F0AB72,
            0x8CC702081A6439EC,
            0x90BEFFFA23631E28,
            0xA4506CEBDE82BDE9,
            0xBEF9A3F7B2C67915,
            0xC67178F2E372532B,
            0xCA273ECEEA26619C,
            0xD186B8C721C0C207,
            0xEADA7DD6CDE0EB1E,
            0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA,
            0x0A637DC5A2C898A6,
            0x113F9804BEF90DAE,
            0x1B710B35131C471B,
            0x28DB77F523047D84,
            0x32CAAB7B40C72493,
            0x3C9EBE0A15C9BEBC,
            0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6,
            0x597F299CFC657E2A,
            0x5FCB6FAB3AD6FAEC,
            0x6C44198C4A475817,
        ]
    ]

    @classmethod
    def bsig0(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 28, cls.W) ^ rotr(x, 34, cls.W) ^ rotr(x, 39, cls.W)

    @classmethod
    def bsig1(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 14, cls.W) ^ rotr(x, 18, cls.W) ^ rotr(x, 41, cls.W)

    @classmethod
    def ssig0(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 1, cls.W) ^ rotr(x, 8, cls.W) ^ shr(x, 7)

    @classmethod
    def ssig1(cls, x: int) -> int:
        x = W_MAP[cls.W](x)
        return rotr(x, 19, cls.W) ^ rotr(x, 61, cls.W) ^ shr(x, 6)

    @classmethod
    def pad(cls, message: bytes) -> bytes:
        L = len(message) * 8
        K = 896 - L
        if K <= 0:
            K += 1024
        # Since L is a multiple of 8, we know that the first padded byte will be 1 << 7
        # Similarly, we also must have K divisible by 8
        return (
            message
            + int.to_bytes(1 << 7, 1, "big")
            + bytes(K // 8 - 1)
            + int.to_bytes(L, 16, "big")
        )


class Sha224(Sha224256):
    INITIAL_VALUE = [
        W_MAP[32](i)
        for i in [
            0xC1059ED8,
            0x367CD507,
            0x3070DD17,
            0xF70E5939,
            0xFFC00B31,
            0x68581511,
            0x64F98FA7,
            0xBEFA4FA4,
        ]
    ]

    @classmethod
    def digest(cls, message: bytes) -> bytes:
        return b"".join(
            [
                int.to_bytes(intermediate_hash, 4, "big")
                for intermediate_hash in cls.process(message)[:7]
            ]
        )


class Sha256(Sha224256):
    INITIAL_VALUE = [
        W_MAP[32](i)
        for i in [
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        ]
    ]

    @classmethod
    def digest(cls, message: bytes) -> bytes:
        return b"".join(
            [
                int.to_bytes(intermediate_hash, 4, "big")
                for intermediate_hash in cls.process(message)
            ]
        )


class Sha384(Sha384512):
    INITIAL_VALUE = [
        W_MAP[64](i)
        for i in [
            0xCBBB9D5DC1059ED8,
            0x629A292A367CD507,
            0x9159015A3070DD17,
            0x152FECD8F70E5939,
            0x67332667FFC00B31,
            0x8EB44A8768581511,
            0xDB0C2E0D64F98FA7,
            0x47B5481DBEFA4FA4,
        ]
    ]

    @classmethod
    def digest(cls, message: bytes) -> bytes:
        return b"".join(
            [
                int.to_bytes(intermediate_hash, 8, "big")
                for intermediate_hash in cls.process(message)[:6]
            ]
        )


class Sha512(Sha384512):
    INITIAL_VALUE = [
        W_MAP[64](i)
        for i in [
            0x6A09E667F3BCC908,
            0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B,
            0xA54FF53A5F1D36F1,
            0x510E527FADE682D1,
            0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B,
            0x5BE0CD19137E2179,
        ]
    ]

    @classmethod
    def digest(cls, message: bytes) -> bytes:
        return b"".join(
            [
                int.to_bytes(intermediate_hash, 8, "big")
                for intermediate_hash in cls.process(message)
            ]
        )
