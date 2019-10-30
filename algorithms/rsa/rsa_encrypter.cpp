#include "rsa_encrypter.hpp"
#include <random>
#include <ios>
#include <iosfwd>
#include <iomanip>
#include <sstream>

#include "prime_utils.hpp"

constexpr uint64_t MAX_PRIME_VALUE = std::numeric_limits<uint8_t>::max();
constexpr uint64_t MIN_PRIME_VALUE = std::numeric_limits<uint8_t>::max() / 2;
constexpr uint64_t KEY_ALIGN = 8;

namespace _rsa_utils
{
	// TODO: rewrite RSA algorithm on big int like digital signature 
	uint64_t generate_prime_number(uint64_t min_val, uint64_t max_val, uint64_t ignore_prime = 0)
	{
		const big_unsigned ignore_big_prime(static_cast<unsigned long>(ignore_prime));
		const big_unsigned min_val_big(static_cast<unsigned long>(min_val));
		const big_unsigned max_val_big(static_cast<unsigned long>(max_val));

		while (true)
		{
			big_unsigned generated_value = prime_utils::generate_prime_number(min_val_big, max_val_big);

			if (generated_value != ignore_big_prime && prime_utils::is_prime(generated_value))
			{
				return generated_value.toUnsignedLong();
			}
		}
	}

	uint64_t gcd(uint64_t a, uint64_t b)
	{
		while (a > 0 && b > 0)
		{
			if (a > b)
			{
				a %= b;
			}
			else
			{
				b %= a;
			}
		}

		return a + b;
	}

	uint64_t generate_coprime_number(uint64_t min_val, uint64_t coprime)
	{
		while (true)
		{
			uint64_t generated_value = generate_prime_number(min_val, coprime - 1);

			if (gcd(coprime, generated_value) == 1)
			{
				return generated_value;
			}
		}
	}

	std::string key_to_string(int64_t key_exp, int64_t module)
	{
		std::stringstream stream;
		stream << std::setfill('0') << std::setw(KEY_ALIGN) << std::right << std::hex << module;
		stream << std::setfill('0') << std::setw(KEY_ALIGN) << std::right << std::hex << key_exp;

		std::string result(stream.str());

		return result;
	}

	std::tuple<int64_t, int64_t> string_to_key(const std::string& key)
	{
		uint64_t module = std::stoi(key.substr(0, KEY_ALIGN), nullptr, 16);
		uint64_t key_exp = std::stoi(key.substr(KEY_ALIGN, KEY_ALIGN), nullptr, 16);

		return {key_exp, module};
	}

	uint64_t exp_by_module(uint64_t symbol, uint64_t key_exp, uint64_t module)
	{
		uint64_t result = symbol;
		for (uint64_t i = 0; i < key_exp - 1; ++i)
		{
			result = (result * symbol) % module;
		}
		
		return result;
	}

	uint64_t extended_gcd(uint64_t a, uint64_t b, int64_t& x, int64_t& y) {
		if (a == 0) {
			x = 0; y = 1;
			return b;
		}

		int64_t prev_x, prev_y;
		uint64_t d = extended_gcd(b % a, a, prev_x, prev_y);
		x = prev_y - (b / a) * prev_x;
		y = prev_x;
		return d;
	}
}

rsa_encrypter::rsa_encrypter()
{
	_generate_keys();
}

std::string rsa_encrypter::encrypt(const std::string& message) const
{
	return encrypt(message, _public_key);
}

std::string rsa_encrypter::encrypt(const std::string& message, const std::string& key)
{
	auto [key_exp, module] = _rsa_utils::string_to_key(key);
	std::stringstream encryption_stream;

	for (const char symbol : message)
	{
		uint64_t encrypted = _rsa_utils::exp_by_module(symbol, key_exp, module);
		encryption_stream << std::hex << encrypted << " ";
	}

	std::string encrypted_message(encryption_stream.str());
	return encrypted_message;
}

std::string rsa_encrypter::decrypt(const std::string& message) const
{
	auto [d, module] = _rsa_utils::string_to_key(_private_key);

	std::stringstream encryption_stream(message);
	std::string decrypted_message;

	std::string encoded_symbol_string;

	while (encryption_stream >> encoded_symbol_string)
	{
		uint64_t decrypted_symbol = std::stoi(encoded_symbol_string, nullptr, 16);
		decrypted_symbol = _rsa_utils::exp_by_module(decrypted_symbol, d, module);
		decrypted_message += static_cast<char>(decrypted_symbol);
	}
	
	return decrypted_message;
}

const std::string& rsa_encrypter::get_public_key() const
{
	return _public_key;
}

void rsa_encrypter::_generate_keys()
{
	uint64_t _p = _rsa_utils::generate_prime_number(MIN_PRIME_VALUE, MAX_PRIME_VALUE);
	uint64_t _q = _rsa_utils::generate_prime_number(MIN_PRIME_VALUE, MAX_PRIME_VALUE, _p);

	uint64_t module = _p * _q;
	uint64_t theta = (_p - 1) * (_q - 1);

	uint64_t key_exp = _rsa_utils::generate_coprime_number(MIN_PRIME_VALUE, theta);

	int64_t d = 0, y_k = 0;
	_rsa_utils::extended_gcd(key_exp, theta, d, y_k);

	if (d < 0) {
		d += theta;
	}

	_public_key = _rsa_utils::key_to_string(key_exp, module);
	_private_key = _rsa_utils::key_to_string(d, module);
}
