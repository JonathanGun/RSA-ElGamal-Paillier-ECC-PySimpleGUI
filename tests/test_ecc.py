from ciphers.ecc import ECC, Point


def test_sample():
    ecc = ECC(1, 6, 11, 123)
    # Example slide 30 - 32
    p = Point(2, 4)
    q = Point(5, 9)
    assert len(ecc.curve.all_points) == 13
    assert ecc.curve.add(p, q) == Point(8, 8)
    assert ecc.curve.mult(2, p) == Point(5, 9)
    ans = [Point(x, y) for (x, y) in (
        (2, 4),
        (5, 9),
        (8, 8),
        (10, 9),
        (3, 5),
        (7, 2),
        (7, 9),
        (3, 6),
        (10, 2),
        (8, 3),
        (5, 2),
        (2, 7),
    )]
    ans.append(Point(o=True))
    for i in range(1, len(ecc.curve.all_points) + 1):
        assert ecc.curve.mult(i, p) == ans[i - 1]
    assert ecc.curve.encode(1) == Point(2, 7)
    assert ecc.curve.encode(2) == Point(3, 5)
    assert ecc.curve.decode(Point(5, 2)) == 4
    assert ecc.curve.decode(Point(7, 9)) == 7

    for i in range(100):
        plain1 = 3
        a, pa = ecc.generate_key()
        b, pb = ecc.generate_key()
        cip = ECC(
            1, 6, 11, 123,
            plaintext=plain1,
            pubkey=str(pb),
        ).encrypt()
        plain2 = ECC(
            1, 6, 11, 123,
            ciphertext=cip,
            privkey=int(b),
        ).decrypt()
        assert plain1 == plain2
