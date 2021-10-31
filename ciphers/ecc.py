import re
import random
from ciphers.base import BaseCipher
from dataclasses import dataclass


@dataclass
class Point:
    x: int = 0
    y: int = 0
    o: bool = False

    def __eq__(self, o: object) -> bool:
        return self.x == o.x and self.y == o.y

    def neg(self, p: int):
        return Point(x=self.x, y=(-self.y) % p)

    def __repr__(self):
        if self.o:
            return "Origin"
        return f"({self.x}, {self.y})"


class Curve:
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p
        assert 4 * self.a ** 3 + 27 * self.b ** 2 != 0
        self.all_points = list(self.generate_all_points())

    def generate_all_points(self):
        for i in range(self.p):
            y = Curve.modular_sqrt(i ** 3 + self.a * i + self.b, self.p)
            y1, y2 = min(y, self.p - y), max(y, self.p - y)
            if y != 0:
                yield Point(i, y1)
                yield Point(i, y2)
        yield Point(o=True)

    def modular_sqrt(a, p):
        def legendre_symbol(a, p):
            """ Compute the Legendre symbol a|p using
                Euler's criterion. p is a prime, a is
                relatively prime to p (if p divides
                a, then a|p = 0)
                Returns 1 if a has a square root modulo
                p, -1 otherwise.
            """
            ls = pow(a, (p - 1) // 2, p)
            return -1 if ls == p - 1 else ls

        """ Find a quadratic residue (mod p) of 'a'. p
            must be an odd prime.
            Solve the congruence of the form:
                x^2 = a (mod p)
            And returns x. Note that p - x is also a root.
            0 is returned is no square root exists for
            these a and p.
            The Tonelli-Shanks algorithm is used (except
            for some simple cases in which the solution
            is known from an identity). This algorithm
            runs in polynomial time (unless the
            generalized Riemann hypothesis is false).
        """
        # Simple cases
        #
        if legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return p
        elif p % 4 == 3:
            return pow(a, (p + 1) // 4, p)

        # Partition p-1 to s * 2^e for an odd s (i.e.
        # reduce all the powers of 2 from p-1)
        #
        s = p - 1
        e = 0
        while s % 2 == 0:
            s //= 2
            e += 1

        # Find some 'n' with a legendre symbol n|p = -1.
        # Shouldn't take long.
        #
        n = 2
        while legendre_symbol(n, p) != -1:
            n += 1

        # Here be dragons!
        # Read the paper "Square roots from 1; 24, 51,
        # 10 to Dan Shanks" by Ezra Brown for more
        # information
        #

        # x is a guess of the square root that gets better
        # with each iteration.
        # b is the "fudge factor" - by how much we're off
        # with the guess. The invariant x^2 = ab (mod p)
        # is maintained throughout the loop.
        # g is used for successive powers of n to update
        # both a and b
        # r is the exponent - decreases with each update
        #
        x = pow(a, (s + 1) // 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e

        while True:
            t = b
            m = 0
            for m in range(r):
                if t == 1:
                    break
                t = pow(t, 2, p)

            if m == 0:
                return x

            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m

    def add(self, p: Point, q: Point) -> Point:
        # Multiply with origin
        if p.o:
            return q
        if q.o:
            return p

        # Formula from slide 27-29
        m = None
        if p == q:
            m = ((3 * p.x * p.x + self.a) * pow(2 * p.y, -1, self.p)) % self.p
        elif p.x == q.x:
            return Point(o=True)
        else:
            m = ((p.y - q.y) * pow(p.x - q.x, -1, self.p)) % self.p
        x = (m * m - p.x - q.x) % self.p
        y = (m * (p.x - x) - p.y) % self.p
        return Point(x, y)

    def sub(self, p: Point, q: Point):
        return self.add(p, q.neg(self.p))

    def mult(self, k: int, p: Point):
        ans = Point(o=True)
        while k > 0:
            if k & 1:
                ans = self.add(ans, p)
            k >>= 1
            p = self.add(p, p)
        return ans

    def encode(self, n: int) -> Point:
        return self.all_points[n % len(self.all_points)]

    def decode(self, p: Point) -> int:
        return self.all_points.index(p)


class ECC(BaseCipher):
    def __init__(self, a: int, b: int, p: int, base: int, **kwargs):
        super().__init__(**kwargs)
        self.curve = Curve(a, b, p)
        self.base = base

    def encrypt(self):
        # Slide hal 41
        self.pubkey = Point(*self._parse_tuple(self.pubkey, 2))
        k = random.randint(1, self.curve.p - 1)
        self.plaintext = self.curve.encode(self.plaintext)
        cip = self.curve.add(self.plaintext, self.curve.mult(k, self.pubkey))
        kB = self.curve.mult(k, self.curve.encode(self.base))
        self.ciphertext = f"{self.curve.decode(kB)}, {self.curve.decode(cip)}"
        return self.ciphertext

    def decrypt(self):
        # Slide hal 41
        kB, self.ciphertext = self._parse_tuple(self.ciphertext, 2)
        kB = self.curve.encode(kB)
        self.ciphertext = self.curve.encode(self.ciphertext)
        self.plaintext = self.curve.sub(self.ciphertext, self.curve.mult(self.privkey, kB))
        self.plaintext = self.curve.decode(self.plaintext)
        return self.plaintext

    def _parse_tuple(self, s: str, n: int = 2):
        return list(map(int, re.findall(r'\d+', s)))[:n]

    def generate_key(self):
        privkey, pubkey = super().generate_key()
        privkey %= self.curve.p
        privkey += 1
        pubkey = self.curve.mult(privkey, self.curve.encode(self.base))
        return privkey, pubkey

    def validate_input(self):
        assert 4 * self.curve.a ** 3 + 27 * self.curve.b ** 2 != 0
