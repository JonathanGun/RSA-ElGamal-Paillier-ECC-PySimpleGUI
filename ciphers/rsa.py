from ciphers.base import BaseCipher


class RSA(BaseCipher):
    def encrypt(self):
        e, n = self._parse_tuple(self.pubkey, 2)
        c = [str(pow(ord(char), e, n)) for char in self.plaintext]

        self.ciphertext = ','.join(c)
        return self.ciphertext

    def decrypt(self):
        d, n = self._parse_tuple(self.privkey, 2)
        m = [pow(char, d, n) for char in map(int, self.ciphertext.split(","))]
        self.plaintext = "".join(map(lambda c: chr(c), m))
        return self.plaintext

    def generate_key(self, p: int = None, q: int = None, e: int = None):
        if p is None or q is None:
            p, q = super().generate_key(is_prime=True)
        n = p * q
        phi = (p - 1) * (q - 1)  # toitent
        if e is None:
            _, e = super().generate_key(is_prime=True, mx=phi)
        d = pow(e, -1, phi)
        privkey = (d, n)
        pubkey = (e, n)

        return privkey, pubkey
