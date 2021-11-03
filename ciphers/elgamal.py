from ciphers.base import BaseCipher
import random


class ElGamal(BaseCipher):
    MIN_NUM = 1e2

    def encrypt(self, k: int = None):
        y, g, p = self._parse_tuple(self.pubkey, 3)
        if k is None:
            k = random.randint(1, p - 2)
        c1 = pow(g, k, p)
        c2 = (pow(y, k, p) * self.plaintext) % p

        self.ciphertext = f"{c1}, {c2}"
        return self.ciphertext

    def decrypt(self):
        a, b = self._parse_tuple(self.ciphertext, 2)
        x, p = self._parse_tuple(self.privkey, 2)
        self.plaintext = (pow(a, p - 1 - x, p) * b) % p
        return self.plaintext

    def generate_key(self, p: int = None, g: int = None, x: int = None):
        while p is None or g is None:
            p, g = super().generate_key(is_prime=True)
            if p < ElGamal.MIN_NUM:
                p = None
        if x is None:
            x = random.randint(1, p - 2)

        y = pow(g, x, p)
        privkey = (x, p)
        pubkey = (y, g, p)
        return privkey, pubkey
