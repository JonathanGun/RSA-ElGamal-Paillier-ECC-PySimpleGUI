from abc import ABC, abstractmethod
import random
import re
from primePy import primes


class BaseCipher(ABC):
    allow_byte = False
    MAX_NUM = int(1e3)

    def __init__(self, plaintext: int = None, ciphertext: int = None, privkey: int = None, pubkey: int = None):
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.privkey = privkey
        self.pubkey = pubkey

    @abstractmethod
    def encrypt(self):
        pass

    @abstractmethod
    def decrypt(self):
        pass

    def generate_key(self, is_prime: bool = False, mx: int = None):
        if mx is None:
            mx = BaseCipher.MAX_NUM
        if is_prime:
            p = primes.upto(mx)
            return random.choice(p), random.choice(p)
        return random.randint(0, mx), random.randint(0, mx)

    def validate_input(self):
        pass

    def _parse_tuple(self, s: str, n: int = 2):
        return list(map(int, re.findall(r'\d+', s)))[:n]
