import random
import re
from ciphers.base import BaseCipher
from math import lcm, gcd


class Paillier(BaseCipher):
    def encrypt(self, r: int = None):
        # Slide 19
        self.g, self.n = self._parse_tuple(self.pubkey, 2)
        self.n2 = self.n * self.n
        assert 0 <= self.plaintext < self.n
        if r is None:
            while True:
                r = random.randint(0, self.n - 1)
                if gcd(r, self.n) == 1:
                    break
        self.ciphertext = (pow(self.g, self.plaintext, self.n2) * pow(r, self.n, self.n2)) % self.n2
        return self.ciphertext

    def decrypt(self):
        # Slide 19
        self.l, self.m, self.n = self._parse_tuple(self.privkey, 3)
        self.n2 = self.n * self.n
        self.plaintext = (self.L(pow(self.ciphertext, self.l, self.n2), self.n) * self.m) % self.n
        return self.plaintext

    @staticmethod
    def L(x, n):
        return (x - 1) // n

    def _generate_pq(self):
        p, q = super().generate_key(is_prime=True)
        if gcd(p * q, (p - 1) * (q - 1)) != 1 or p == q:
            p = None
        return p, q

    def generate_key(self, p: int = None, q: int = None, g: int = None):
        # Slide 17
        while p is None or q is None:
            p, q = self._generate_pq()
        n = p * q
        n2 = n * n
        l = lcm(p - 1, q - 1)
        # n + 1 always invertible
        g = g if g is not None else n + 1

        m = pow(self.L(pow(g, l, n2), n), -1, n)
        privkey = (l, m, n)
        pubkey = (g, n)
        return privkey, pubkey

    def validate_input(self):
        pass
