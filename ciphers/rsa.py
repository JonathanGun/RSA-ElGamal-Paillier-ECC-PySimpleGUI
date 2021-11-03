from ciphers.base import BaseCipher
import random


class RSA(BaseCipher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def encrypt(self):
        self.plaintext.replace(" ", "")
        e, n = self._parse_tuple(self.pubkey, 2)
        c = [pow(ord(char), e, n) for char in self.plaintext]

        self.ciphertext = f"{c}"
        return self.ciphertext

    def decrypt(self):
        d, n = self._parse_tuple(self.privkey, 2)
        m = [pow(chr(char), d, n) for char in self.ciphertext]
        self.plaintext = m
        return self.plaintext

    def generate_key(self, p: int = None, q: int = None, e: int = None):
        if p is None or q is None:
            p, q = super().generate_key(is_prime=True)
        n = p * q
        phi = (p - 1) * (q - 1)  # toitent
        if e is None:
            e = random.randint(2, phi)
            e = super().generate_key(is_prime=True)
        d = pow(e, -1, phi)
        privkey = (d, n)
        pubkey = (e, n)

        return privkey, pubkey
