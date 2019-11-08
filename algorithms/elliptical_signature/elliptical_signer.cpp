#include "elliptical_signer.hpp"
#include <random>
#include <limits>
#include <ios>
#include <iosfwd>
#include <iomanip>
#include <sstream>
#include <iostream>

#include "gost_hash.hpp"
#include "prime_utils.hpp"
#include "elliptical_point.hpp"

constexpr uint64_t KEY_ALIGN = 64;

const std::string DEFAULT_HASH_KEY = "12345678900987654321qwertyuiopas";

const big_unsigned CURVE_P = stringToBigUnsigned("6277101735386680763835789423207666416083908700390324961279");
const big_integer CURVE_A = stringToBigInteger("-3");
const big_integer CURVE_B = stringToBigInteger("2455155546008943817740293915197451784769108058161191238065");
const big_integer CURVE_X = stringToBigInteger("602046282375688656758213480587526111916698976636884684818");
const big_integer CURVE_Y = stringToBigInteger("174050332293622031404857552280219410364023488927386650641");
const big_unsigned CURVE_Q = stringToBigUnsigned("6277101735386680763835789423176059013767194773182842284081");

const elliptical_point G_POINT(CURVE_X, CURVE_Y, CURVE_A, CURVE_B, CURVE_P);

namespace _signer_utils
{
	big_integer str_to_bigint(std::string bytes)
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

	std::string key_to_string(big_integer key_exp, big_integer module)
	{
		std::stringstream stream;
		stream << std::setfill('0') << std::setw(KEY_ALIGN) << std::right << std::hex << module;
		stream << std::setfill('0') << std::setw(KEY_ALIGN) << std::right << std::hex << key_exp;

		std::string result(stream.str());

		return result;
	}
}

bool elliptical_signer::verify_message(const std::string& message) const
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);
	big_integer hash_value = _signer_utils::str_to_bigint(generated_hash);

	auto signature_it = _signatures.find(generated_hash);
	if (signature_it == _signatures.end())
	{
		return false;
	}

	auto& [r, s] = signature_it->second;

	if (r < 1 || r > (CURVE_Q - 1) || s < 1 || s > (CURVE_Q - 1)) 
	{
		return false;
	}

	big_integer e = hash_value % CURVE_Q;
	if (e == 0)
	{
		e = 1;
	}

	big_integer v = modinv(e, CURVE_Q);
	big_integer z1 = (s * v) % CURVE_Q;
	big_integer z2 = big_integer(CURVE_Q) + ((-(r * v)) % CURVE_Q);

	elliptical_point a = elliptical_point::multiply(z1, G_POINT);
	elliptical_point b = elliptical_point::multiply(z2, _public_key);
	elliptical_point c = a + b;
	big_integer theoretical_r = c.x % CURVE_Q;

	bool verified = theoretical_r == r;
	return verified;
}

elliptical_signer::elliptical_signer()
{
	uint64_t n_bits_count = bigIntegerToString(CURVE_Q).size();

	_private_key = prime_utils::generate_prime_candidate(n_bits_count);
	_public_key = elliptical_point::multiply(_private_key, G_POINT);
}

std::string elliptical_signer::sign_message(const std::string& message)
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);
	big_integer hash_value = _signer_utils::str_to_bigint(generated_hash);

	big_integer e = hash_value % CURVE_Q;
	if (e == 0)
	{
		e = 1;
	}

	big_integer r;
	big_integer s;

	uint64_t n_bits_count = bigIntegerToString(CURVE_Q).size();

	while (true)
	{
		big_integer k = prime_utils::generate_prime_candidate(n_bits_count);
		elliptical_point c = elliptical_point::multiply(k, G_POINT);

		r = c.x % CURVE_Q;
		if (r == 0)
		{
			continue;
		}

		s = (r * _private_key + k * e) % CURVE_Q;
		if (s == 0)
		{
			continue;
		}

		break;
	}

	_signatures.insert({ generated_hash, {r, s} });

	return _signer_utils::key_to_string(r, s);
}

std::string elliptical_signer::get_public_key() const
{
	return _public_key.to_string();
}

const char* elliptical_signer::invalid_key::what() const throw ()
{
	return "No key for this message exists in current storage!";
}
