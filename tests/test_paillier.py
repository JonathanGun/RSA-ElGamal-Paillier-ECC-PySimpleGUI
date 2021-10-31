from ciphers.paillier import Paillier


def test_sample():
    # slide sample
    privkey, pubkey = Paillier(7, 11, 5652).generate_key()
    assert privkey == (30, 74)
    assert pubkey == (5652, 77)

    # checked against onlice calc
    privkey, pubkey = Paillier(199, 17, 1194556).generate_key()
    assert privkey == (1584, 412)
    assert pubkey == (1194556, 3383)

    for _ in range(100):
        privkey, pubkey = Paillier().generate_key()
