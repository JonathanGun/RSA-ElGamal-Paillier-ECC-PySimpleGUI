from ciphers.rsa import RSA


def test_sample():
    rsa = RSA()
    privkey, pubkey = rsa.generate_key(47, 71, 79)
    assert pubkey == (79, 3337)
    assert privkey == (1019, 3337)

    cip = RSA(
        plaintext='HELLO ALICE',
        pubkey='79, 3337'
    ).encrypt()
    assert cip == '72697676796576736769'
    plain = RSA(
        ciphertext=cip,
        privkey='1019, 3337'
    ).decrypt()
    assert plain == 'HELLOALICE'
