#include "rsa_encrypter.hpp"
#include <random>
#include <limits>
#include <time.h>
#include <ios>
#include <iosfwd>
#include <iomanip>
#include <sstream>

constexpr uint64_t MAX_PRIME_VALUE = std::numeric_limits<uint8_t>::max();
constexpr uint64_t MIN_PRIME_VALUE = std::numeric_limits<uint8_t>::max() / 10;
constexpr uint64_t KEY_ALIGN = 4;

namespace _rsa_utils
{
	bool is_prime(uint64_t n)
	{
		if (n <= 1)
		{
			return false;
		}

		for (int i = 2; i < n; i++)
		{
			if (n % i == 0)
			{
				return false;
			}
		}

		return true;
	}

	uint64_t generate_random_prime(uint64_t min_val, uint64_t max_val)
	{
		std::mt19937 seed(static_cast<uint32_t>(time(0)));
		std::uniform_int_distribution<uint64_t> generator(min_val, max_val);

		while (true)
		{
			uint64_t generated_value = generator(seed);

			if (is_prime(generated_value))
			{
				return generated_value;
			}
		}
	}

	uint64_t generate_coprime_number(uint64_t min_val, uint64_t coprime)
	{
		while (true)
		{
			uint64_t generated_value = generate_random_prime(min_val, coprime - 1);

			if (coprime % generated_value != 0)
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

	std::tuple<int64_t, int64_t, int64_t> extended_gcd(int64_t a, int64_t b)
	{
		if (a == 0)
			return std::make_tuple(b, 0, 1);

		auto [gcd, x, y] = extended_gcd(b % a, a);

		return std::make_tuple(gcd, (y - (b / a) * x), x);
	}

	uint64_t exp_by_module(uint64_t symbol, uint64_t key_exp, uint64_t module)
	{
		uint64_t result = symbol;
		for (int i = 0; i < key_exp - 1; ++i)
		{
			result = (result * symbol) % module;
		}
		
		return result;
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
	uint64_t _p = _rsa_utils::generate_random_prime(MIN_PRIME_VALUE, MAX_PRIME_VALUE);
	uint64_t _q = _rsa_utils::generate_random_prime(MIN_PRIME_VALUE, MAX_PRIME_VALUE);

	// TODO: remove
	_p = 3;
	_q = 7;

	uint64_t module = _p * _q;
	uint64_t theta = (_p - 1) * (_q - 1);

	uint64_t key_exp = _rsa_utils::generate_coprime_number(0 /*MIN_PRIME_VALUE*/, theta);

	// TODO: remove
	key_exp = 5;

	uint64_t d = std::get<1>(_rsa_utils::extended_gcd(key_exp, theta));

	d = 17;

	_public_key = _rsa_utils::key_to_string(key_exp, module);
	_private_key = _rsa_utils::key_to_string(d, module);
}
