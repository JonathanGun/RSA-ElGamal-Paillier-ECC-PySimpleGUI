from abc import ABC, abstractmethod
import random


class BaseCipher(ABC):
    allow_byte = False

    def __init__(self, plaintext: int, ciphertext: int, privkey: int, pubkey: int):
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

    def generate_key(seed):
        random.seed(seed)
        return random.randint(0, 1e18), random.randint(0, 1e18)
