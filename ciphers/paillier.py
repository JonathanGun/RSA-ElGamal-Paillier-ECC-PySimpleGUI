from ciphers.base import BaseCipher


class Paillier(BaseCipher):
    def encrypt(self):
        self.ciphertext = f"{self.plaintext} encrypted using {self.__class__.__name__} using key {self.pubkey}"

    def decrypt(self):
        self.plaintext = f"{self.ciphertext} decrypted using {self.__class__.__name__} using key {self.privkey}"
