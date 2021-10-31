import random
from ciphers.paillier import Paillier


def test_sample():
    # slide sample 18
    privkey, pubkey = Paillier().generate_key(7, 11, 5652)
    assert privkey == (30, 74, 77)
    assert pubkey == (5652, 77)

    # checked against onlice calc
    privkey, pubkey = Paillier().generate_key(199, 17, 1194556)
    assert privkey == (1584, 412, 3383)
    assert pubkey == (1194556, 3383)

    for _ in range(100):
        privkey, pubkey = Paillier().generate_key()

    # encrypt decrypt slide 21
    cip = Paillier(
        plaintext=42,
        pubkey="(5652, 77)"
    ).encrypt(r=23)
    assert cip == 4624
    plain = Paillier(
        ciphertext=4624,
        privkey="(30, 74, 77)"
    ).decrypt()
    assert plain == 42

    # encrypt decrypt online calc
    cip = Paillier(
        plaintext=1,
        pubkey="(5652, 77)"
    ).encrypt(r=123)
    assert cip == 657
    plain = Paillier(
        ciphertext=657,
        privkey="(30, 74, 77)"
    ).decrypt()
    assert plain == 1

    privkey, pubkey = Paillier().generate_key()
    for _ in range(1000):
        plain = random.randint(1, int(1e2))
        cip = Paillier(
            plaintext=plain,
            pubkey=str(pubkey),
        ).encrypt()
        plain2 = Paillier(
            ciphertext=cip,
            privkey=str(privkey),
        ).decrypt()
        assert plain == plain2
