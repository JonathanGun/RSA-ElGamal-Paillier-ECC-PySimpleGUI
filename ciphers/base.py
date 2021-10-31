from abc import ABC, abstractmethod
import random


class BaseCipher(ABC):
    allow_byte = False
    MAX_NUM = int(1e18)

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

    def generate_key(self):
        return random.randint(0, BaseCipher.MAX_NUM), random.randint(0, BaseCipher.MAX_NUM)

    def validate_input(self):
        pass
