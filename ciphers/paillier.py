from ciphers.base import BaseCipher
from math import lcm, gcd


class Paillier(BaseCipher):
    def __init__(self, p: int, q: int, g: int, **kwargs):
        super().__init__(**kwargs)
        while p is None or q is None:
            p, q = self._generate_pq()
        self.p = p
        self.q = q
        self.g = g if g is not None else p * q + 1

    def encrypt(self):
        self.ciphertext = f"{self.plaintext} encrypted using {self.__class__.__name__} using key {self.pubkey}"

    def decrypt(self):
        self.plaintext = f"{self.ciphertext} decrypted using {self.__class__.__name__} using key {self.privkey}"

    @staticmethod
    def L(x, n):
        return (x - 1) // n

    def _generate_pq(self):
        p, q = super().generate_key(is_prime=True)
        if gcd(p * q, (p - 1) * (q - 1)) != 1 or p == q:
            p = None
        return p, q

    def generate_key(self):
        p, q, g = self.p, self.q, self.g
        n = p * q
        l = lcm(p - 1, q - 1)
        if g is None:
            # always invertible
            g = n + 1
        gl = self.L(pow(g, l, n * n), n)
        m = pow(gl, -1, n)
        privkey = (l, m)
        pubkey = (g, n)
        return privkey, pubkey

    def validate_input(self):
        pass
