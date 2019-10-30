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

constexpr uint64_t KEY_ALIGN = 64;
constexpr uint64_t HASH_EXPECTED_SIZE = 256;

const std::string DEFAULT_HASH_KEY = "12345678900987654321qwertyuiopas";

namespace _signer_utils
{
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
		bytes[0] &= 0b01111111;
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

		return result;
	}

    std::tuple<big_unsigned, big_unsigned> generate_signature(const std::string& generated_hash, 
		big_unsigned p, big_unsigned q, big_unsigned g, big_unsigned private_key)
    {
        big_unsigned k = 1, r = 0, s = 0, x = 0;
		big_unsigned hash_value = str_to_bigint(generated_hash);

        while (true)
        {
			x = modexp(g, k, p);
			r = x % q;
            if (r == 0)
            {
                ++k;
                continue;
            }
            
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
}

bool digital_signer::verify_message(const std::string& message) const
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);
	big_unsigned hash_value = _signer_utils::str_to_bigint(generated_hash);

	auto signature_it = _signatures.find(generated_hash);
	if (signature_it == _signatures.end())
	{
		return false;
	}

	auto& [r, s] = signature_it->second;

	big_unsigned w = modinv(s, _q);
	big_unsigned u_1 = (hash_value * w) % _q;
	big_unsigned u_2 = (r * w) % _q;
	big_unsigned x = (modexp(_g, u_1, _p) * modexp(_public_key, u_2, _p)) % _p;
	big_unsigned v = x % _q;

	bool verified = v == r;
	return verified;
}

digital_signer::digital_signer()
{
	_q = _signer_utils::generate_prime_number(HASH_EXPECTED_SIZE);
	_p = _signer_utils::generate_prime_number_with_divider(_q);
	_g = _signer_utils::generate_multiplicate_order(_p, _q);

	_private_key = rand_int(0, _q);
	_public_key = modexp(_g, _private_key, _p);
}

std::string digital_signer::sign_message(const std::string& message)
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);

    auto [r, s] = _signer_utils::generate_signature(generated_hash, _p, _q, _g, _private_key);

	_signatures.insert({ generated_hash, {r, s} });
	
	return _signer_utils::key_to_string(r, s);
}

std::string digital_signer::get_public_key() const
{
	return bigUnsignedToString(_public_key);
}

const char* digital_signer::invalid_key::what() const throw ()
{
	return "No key for this message exists in current storage!";
}
