from ciphers.rsa import RSA
import random

def test_sample():
    rsa = RSA()
    privkey, pubkey = rsa.generate_key(47, 71, 79)
    assert pubkey == (79, 3337)
    assert privkey == (1019, 3337)

    cip = RSA(
        plaintext='HELLO ALICE',
        pubkey='79, 3337'
    ).encrypt()
    assert cip == '285,1689,1903,1903,251,1379,541,1903,725,1479,1689'
    plain = RSA(
        ciphertext=cip,
        privkey='1019, 3337'
    ).decrypt()
    assert plain == 'HELLO ALICE'

    privkey, pubkey = RSA().generate_key()
    for _ in range(1000):
        plain = random.randint(1, int(1e2))
        cip = RSA(
            plaintext=plain,
            pubkey=str(pubkey),
        ).encrypt()
        plain2 = RSA(
            ciphertext=cip,
            privkey=str(privkey),
        ).decrypt()
        assert plain == plain2