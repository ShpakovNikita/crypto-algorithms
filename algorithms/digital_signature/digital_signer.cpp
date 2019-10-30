#include "digital_signer.hpp"
#include <random>
#include <limits>
#include <time.h>
#include <ios>
#include <iosfwd>
#include <iomanip>
#include <sstream>
#include <iostream>
#include "gost_hash.hpp"

constexpr uint64_t MAX_PRIME_VALUE = std::numeric_limits<uint8_t>::max();
constexpr uint64_t MIN_PRIME_VALUE = std::numeric_limits<uint8_t>::max() / 2;
constexpr uint64_t KEY_ALIGN = 64;
constexpr uint64_t HASH_EXPECTED_SIZE = 256;

const std::string DEFAULT_HASH_KEY = "12345678900987654321qwertyuiopas";

namespace _signer_utils
{
	bool miillerTest(big_unsigned d, big_unsigned n)
	{
		// Pick a random number in [2..n-2] 
		// Corner cases make sure that n > 4 

		const big_unsigned two = 2;
		big_unsigned a = two + big_unsigned(rand()) % (n - 4);

		// Compute a^d % n 
		big_unsigned x = modexp(a, d, n);

		if (x == 1 || x == n - 1)
			return true;

		// Keep squaring x while one of the following doesn't 
		// happen 
		// (i)   d does not reach n-1 
		// (ii)  (x^2) % n is not 1 
		// (iii) (x^2) % n is not n-1 
		while (d != n - 1)
		{
			x = modexp(x, x, n);
			d *= 2;

			if (x == 1)      return false;
			if (x == n - 1)    return true;
		}

		// Return composite 
		return false;
	}

	bool isPrime(big_unsigned n, uint64_t k = 4)
	{
		// Corner cases 
		if (n <= 1 || n == 4)  return false;
		if (n <= 3) return true;

		// Find r such that n = 2^d * r + 1 for some r >= 1 
		big_unsigned d = n - 1;
		while (d % 2 == 0)
			d /= 2;

		// Iterate given nber of 'k' times 
		for (uint64_t i = 0; i < k; i++)
			if (!miillerTest(d, n))
				return false;

		return true;
	}

	bool is_prime(big_unsigned n, uint64_t tests_count = 10)
	{
		if (n == 2 || n == 3)
		{
			return true;
		}
		else if (n <= 1 || n % 2 == 0)
		{
			return false;
		}

		big_unsigned s = 0, r = n - 1;
		while (r % 2 == 0)
		{
			s += 1;
			r /= 2;
		}

		for (uint64_t i = 0; i < tests_count; ++i)
		{
			big_unsigned a = rand_int(2, n - 1);
			big_unsigned x = modexp(a, r, n);
			if (x != 1 && x != n - 1)
			{
				big_unsigned j = 1;
				while (j < s && x != n - 1)
				{
					x = modexp(x, 2, n);
					if (x == 1)
					{
						return false;
					}
					j += 1;
				}
				if (x != n - 1)
				{
					return false;
				}
			}
		}

		return true;
	}

	big_unsigned generate_multiplicate_order(big_unsigned p, big_unsigned q)
	{
		big_unsigned g = 1, h = 2;
		while (g == 1)
		{
			g = modexp(h, (p - 1) / q, p);
			++h;
		}

		return g;
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

		auto test = bigUnsignedToString(result);

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

	big_unsigned generate_prime_number_with_divider(big_unsigned divider)
	{
		/*
		big_unsigned result = divider;

		do
		{
			result += divider;
		} while (!is_prime(result + 1));

		return result + 1;
		*/
		big_unsigned k = pow(big_unsigned(2), HASH_EXPECTED_SIZE - HASH_EXPECTED_SIZE);
		big_unsigned result = divider * k + 1;

		while (!is_prime(result))
		{
			++k;
			result = divider * k + 1;
		}

		return result;
	}
    
	big_unsigned str_to_bigint(std::string bytes)
	{
		big_unsigned result = 0;
		bytes[0] |= 0b1000000;
		for (uint64_t i = 0; i < bytes.size(); ++i)
		{
			for (uint64_t j = 0; j < CHAR_BIT; ++j)
			{
				// optimization
				if (((bytes[i] >> j) & 1) != 0)
				{
					const big_unsigned two = 2;
					result += pow(two, 256 - 1 - i * CHAR_BIT - j);
				}
			}
		}

		auto test = bigUnsignedToString(result);

		return result;
	}

    std::tuple<big_unsigned, big_unsigned> generate_signature(const std::string& generated_hash, 
		big_unsigned p, big_unsigned q, big_unsigned g, big_unsigned private_key)
    {
        big_unsigned k = 1, r = 0, s = 0, x = 0;
		big_unsigned hash_value = str_to_bigint(generated_hash);

		auto hash_str = bigUnsignedToString(hash_value);

		[[maybe_unused]]
		bool test = hash_value < q;

        while (true)
        {
			x = modexp(g, k, p);
			r = x % q;
            if (r == 0)
            {
                ++k;
                continue;
            }
            
			// test without % q
            s = (modinv(k, q) * (hash_value + private_key * r) % q);

			if (s == 0)
			{
				++k;
				continue;
			}

			break;
        }
        
        return {r, s};
    }

	std::string key_to_string(big_unsigned key_exp, big_unsigned module)
	{
		std::stringstream stream;
		stream << std::setfill('0') << std::setw(KEY_ALIGN) << std::right << std::hex << module;
		stream << std::setfill('0') << std::setw(KEY_ALIGN) << std::right << std::hex << key_exp;

		std::string result(stream.str());

		return result;
	}

	std::tuple<big_unsigned, big_unsigned> string_to_key(const std::string& key)
	{
		// TODO: proper conversion
		big_unsigned module = std::stoi(key.substr(0, KEY_ALIGN), nullptr, 16);
		big_unsigned key_exp = std::stoi(key.substr(KEY_ALIGN, KEY_ALIGN), nullptr, 16);

		return {key_exp, module};
	}
}

bool digital_signer::verify_message(const std::string& message) const
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);
	big_unsigned hash_value = _signer_utils::str_to_bigint(generated_hash);

	auto hash_str = bigUnsignedToString(hash_value);

	auto signature_it = _signatures.find(generated_hash);
	if (signature_it == _signatures.end())
	{
		return false;
	}

	auto& [r, s] = signature_it->second;

	big_unsigned w = modinv(s, q);
	big_unsigned u_1 = (hash_value * w) % q;
	big_unsigned u_2 = (r * w) % q;
	big_unsigned x = (modexp(g, u_1, p) * modexp(g, u_2, p)) % p;
	big_unsigned v = x % q;

	bool verified = v == r;
	return verified;
}

digital_signer::digital_signer()
{
	q = _signer_utils::generate_prime_number(HASH_EXPECTED_SIZE);
	p = _signer_utils::generate_prime_number_with_divider(q);
	g = _signer_utils::generate_multiplicate_order(p, q);

	[[maybe_unused]]
	bool test = (p - 1) % q == 0;

	auto _q = bigUnsignedToString(q);
	auto _p = bigUnsignedToString(p);
	auto _g = bigUnsignedToString(g);

	_private_key = rand_int(0, q);
	_public_key = modexp(g, _private_key, p);
}

std::string digital_signer::sign_message(const std::string& message)
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);

    auto [r, s] = _signer_utils::generate_signature(generated_hash, p, q, g, _private_key);

	std::string signature = _signer_utils::key_to_string(r, s);

	_signatures.insert({ generated_hash, {r, s} });
	
	return signature;
}

std::string digital_signer::get_public_key() const
{
	return bigUnsignedToString(_public_key);
}

const char* digital_signer::invalid_key::what() const throw ()
{
	return "No key for this message exists in current storage!";
}
