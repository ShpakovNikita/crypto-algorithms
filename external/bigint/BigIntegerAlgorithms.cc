#include "BigIntegerAlgorithms.hh"
#include "BigIntegerUtils.hh"
#include "BigUnsigned.hh"
#include <random>

BigUnsigned gcd(BigUnsigned a, BigUnsigned b) {
	BigUnsigned trash;
	// Neat in-place alternating technique.
	for (;;) {
		if (b.isZero())
			return a;
		a.divideWithRemainder(b, trash);
		if (a.isZero())
			return b;
		b.divideWithRemainder(a, trash);
	}
}

void extendedEuclidean(BigInteger m, BigInteger n,
		BigInteger &g, BigInteger &r, BigInteger &s) {
	if (&g == &r || &g == &s || &r == &s)
		throw "BigInteger extendedEuclidean: Outputs are aliased";
	BigInteger r1(1), s1(0), r2(0), s2(1), q;
	/* Invariants:
	 * r1*m(orig) + s1*n(orig) == m(current)
	 * r2*m(orig) + s2*n(orig) == n(current) */
	for (;;) {
		if (n.isZero()) {
			r = r1; s = s1; g = m;
			return;
		}
		// Subtract q times the second invariant from the first invariant.
		m.divideWithRemainder(n, q);
		r1 -= q*r2; s1 -= q*s2;

		if (m.isZero()) {
			r = r2; s = s2; g = n;
			return;
		}
		// Subtract q times the first invariant from the second invariant.
		n.divideWithRemainder(m, q);
		r2 -= q*r1; s2 -= q*s1;
	}
}

BigUnsigned modinv(const BigInteger &x, const BigUnsigned &n) {
	BigInteger g, r, s;
	extendedEuclidean(x, n, g, r, s);
	if (g == 1)
		// r*x + s*n == 1, so r*x === 1 (mod n), so r is the answer.
		return (r % n).getMagnitude(); // (r % n) will be nonnegative
	else
		throw "BigInteger modinv: x and n have a common factor";
}

BigUnsigned modexp(const BigInteger &base, const BigUnsigned &exponent,
		const BigUnsigned &modulus) {
	BigUnsigned ans = 1, base2 = (base % modulus).getMagnitude();
	BigUnsigned::Index i = exponent.bitLength();
	// For each bit of the exponent, most to least significant...
	while (i > 0) {
		i--;
		// Square.
		ans *= ans;
		ans %= modulus;
		// And multiply if the bit is a 1.
		if (exponent.getBit(i)) {
			ans *= base2;
			ans %= modulus;
		}
	}
	return ans;
}

BigUnsigned rand_int(const BigUnsigned& lower, const BigUnsigned& upper) {
	auto lower_bound = lower.getLength(), upper_bound = upper.getLength();

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<unsigned long long> main_result_dist(lower_bound, upper_bound);

	const char alphanum[] =
		"0123456789";
	std::uniform_int_distribution<unsigned long long> num_dist(0, sizeof(alphanum) - 2);

	BigUnsigned generated;

	do 
	{
		uint64_t count = main_result_dist(gen);

		std::string number;
		number.resize(count);

		for (uint64_t j = 0; j < count; ++j) {
			uint64_t i = num_dist(gen);
			number[j] = alphanum[i];
		}

		generated = stringToBigUnsigned(number);

	} while (generated < lower || generated >= upper);

	return generated;
}

BigUnsigned pow(BigUnsigned base, BigUnsigned exp)
{
	BigUnsigned result = 1;
	while (exp != 0) {
		if (exp % 2 == 1)
			result *= base;
		base *= base;
		exp >>= 1;
	}
	return result;
}

BigUnsigned pow(BigUnsigned base, uint64_t exp)
{
	BigUnsigned result = 1;
	while (exp) {
		if (exp & 1)
			result *= base;
		base *= base;
		exp >>= 1;
	}
	return result;
}
