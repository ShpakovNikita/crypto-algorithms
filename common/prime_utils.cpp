#include "prime_utils.hpp"
#include <random>
#include <vector>

namespace prime_utils
{
    // implement this someday to speedup and generate 2048 bit primes https://github.com/cslarsen/miller-rabin
	bool is_prime(const big_unsigned &num, uint64_t tests_count /*= 10*/)
	{
		if (num == 2 || num == 3)
		{
			return true;
		}
		else if (num <= 1 || num % 2 == 0)
		{
			return false;
		}

		big_unsigned s = 0, r = num - 1;
		while (r % 2 == 0)
		{
			s += 1;
			r /= 2;
		}

		for (uint64_t i = 0; i < tests_count; ++i)
		{
			big_unsigned a = rand_int(2, num - 1);
			big_unsigned x = modexp(a, r, num);
			if (x != 1 && x != num - 1)
			{
				big_unsigned j = 1;
				while (j < s && x != num - 1)
				{
					x = modexp(x, 2, num);
					if (x == 1)
					{
						return false;
					}
					j += 1;
				}
				if (x != num - 1)
				{
					return false;
				}
			}
		}

		return true;
	}

	big_unsigned generate_prime_candidate(uint64_t bit_length)
	{
		std::vector<uint8_t> bits;
		bits.resize(bit_length);

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<unsigned long long> num_dist(0, 1);

		for (uint64_t i = 0; i < bit_length; ++i)
		{
			bits[i] = static_cast<uint8_t>(num_dist(gen));
		}

		bits[0] = 1;
		bits[bit_length - 1] = 1;

		big_unsigned result = 0;

		for (uint64_t i = 0; i < bit_length; ++i)
		{
			// optimization
			if (bits[bit_length - i - 1] != 0)
			{
				const big_unsigned two = 2;
				result += pow(two, i);
			}
		}

		return result;
	}

	big_unsigned generate_prime_number(uint64_t bit_length)
	{
		big_unsigned prime;
		do
		{
			prime = generate_prime_candidate(bit_length);
		} while (!is_prime(prime));

		return prime;
	}

	big_unsigned generate_prime_number(const big_unsigned& lower, const big_unsigned& upper)
	{
		big_unsigned prime;
		do
		{
			prime = rand_int(lower, upper);
		} while (!is_prime(prime));

		return prime;
	}
}