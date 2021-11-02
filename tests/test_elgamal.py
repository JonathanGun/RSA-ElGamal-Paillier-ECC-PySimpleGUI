from ciphers.elgamal import ElGamal
import random

def test_sample():
    elgamal = ElGamal()
    privkey, pubkey = elgamal.generate_key(2357, 2, 1751)
    assert pubkey == (1185, 2, 2357)
    assert privkey == (1751, 2357)
    for _ in range(100):
        privkey, pubkey = ElGamal().generate_key()

    # encrypt decrypt slide 21
    cip = ElGamal(
        plaintext=2035,
        pubkey='1185, 2, 2357'
    ).encrypt(k=1520)
    assert cip == '1430, 697'
    plain = ElGamal(
        ciphertext=cip,
        privkey='1751, 2357'
    ).decrypt()
    assert plain == 2035

    # encrypt decrypt online calc
    # cip = ElGamal(
    #     plaintext=1,
    #     pubkey="(5652, 77)"
    # ).encrypt(r=123)
    # assert cip == 657
    # plain = ElGamal(
    #     ciphertext=657,
    #     privkey="(30, 74, 77)"
    # ).decrypt()
    # assert plain == 1

    privkey, pubkey = ElGamal().generate_key()
    for _ in range(1000):
        plain = random.randint(1, int(1e2))
        cip = ElGamal(
            plaintext=plain,
            pubkey=str(pubkey),
        ).encrypt()
        plain2 = ElGamal(
            ciphertext=cip,
            privkey=str(privkey),
        ).decrypt()
        assert plain == plain2