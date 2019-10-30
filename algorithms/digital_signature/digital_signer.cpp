#include "digital_signer.hpp"
#include <random>
#include <limits>
#include <time.h>
#include <ios>
#include <iosfwd>
#include <iomanip>
#include <sstream>
#include <iostream>
#include "BigIntegerLibrary.hh"
#include "gost_hash.hpp"

constexpr uint64_t MAX_PRIME_VALUE = std::numeric_limits<uint8_t>::max();
constexpr uint64_t MIN_PRIME_VALUE = std::numeric_limits<uint8_t>::max() / 2;
constexpr uint64_t KEY_ALIGN = 8;

const std::string DEFAULT_HASH_KEY = "12345678900987654321qwertyuiopas";

using big_unsigned = BigUnsigned;

namespace _signer_utils
{
	bool is_prime(big_unsigned n, uint64_t tests_count = 127)
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
	
	big_unsigned generate_prime_candidate(uint64_t bit_length)
	{
		std::vector<uint8_t> bits;
		bits.resize(bit_length);

		for (uint64_t i = 0; i < bit_length; ++i)
		{
			bits[i] = rand() % 2;
		}

		bits[0] = 1;
		bits[bit_length - 1] = 1;

		big_unsigned result = 0;

		for (uint64_t i = 0; i < bit_length; ++i)
		{
			// optimization
			if (bits[bit_length - i - 1] != 0)
			{
				big_unsigned two = 2;
				result += big_unsigned(bits[bit_length - i - 1]) * pow(two, i);
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

	[[ deprecated ]]
	uint64_t generate_random_prime(uint64_t min_val, uint64_t max_val, uint64_t ignore_prime = 0)
	{
		std::mt19937 seed(static_cast<uint32_t>(time(0)));
		std::uniform_int_distribution<uint64_t> generator(min_val, max_val);

		while (true)
		{
			uint64_t generated_value = generator(seed);

			if (generated_value != ignore_prime && is_prime(0 /*generated_value*/))
			{
				return generated_value;
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
			uint64_t generated_value = generate_random_prime(min_val, coprime - 1);

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
		for (int i = 0; i < key_exp - 1; ++i)
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

bool digital_signer::verify_message(const std::string& message) const
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);

	auto private_key_it = _private_keys.find(generated_hash);
	if (private_key_it == _private_keys.end())
	{
		return false;
	}
	
	auto [key_exp, module] = _signer_utils::string_to_key(private_key_it->second);
	std::stringstream encryption_stream;

	for (const char symbol : message)
	{
		uint64_t encrypted = _signer_utils::exp_by_module(symbol, key_exp, module);
		encryption_stream << std::hex << encrypted << " ";
	}

	std::string encrypted_message(encryption_stream.str());
	return true;
}

std::string digital_signer::sign_message(const std::string& message) const
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	std::string generated_hash = hash_generator.generate_hash(message);

	big_unsigned test = _signer_utils::generate_prime_number(256);
	auto test2 = bigUnsignedToString(test);

	auto [d, module] = _signer_utils::string_to_key("" /*_private_key*/);

	std::stringstream encryption_stream(message);
	std::string decrypted_message;

	// TODO: remove after CMake external dependencies add
	big_unsigned headers_test = stringToBigUnsigned("100500100500100500100500100500100500100500100500");
	std::cout << headers_test << std::endl;

	std::string encoded_symbol_string;

	while (encryption_stream >> encoded_symbol_string)
	{
		uint64_t decrypted_symbol = std::stoi(encoded_symbol_string, nullptr, 16);
		decrypted_symbol = _signer_utils::exp_by_module(decrypted_symbol, d, module);
		decrypted_message += static_cast<char>(decrypted_symbol);
	}
	
	return decrypted_message;
}

const std::string& digital_signer::get_public_key(const std::string& message) const
{
	gost_hash hash_generator(DEFAULT_HASH_KEY);
	auto it = _public_keys.find(hash_generator.generate_hash(message));
	if (it != _public_keys.end())
	{
		return it->second;
	}

	throw invalid_key();
}

void digital_signer::_generate_keys(const std::string& message_hash)
{
	uint64_t _p = _signer_utils::generate_random_prime(MIN_PRIME_VALUE, MAX_PRIME_VALUE);
	uint64_t _q = _signer_utils::generate_random_prime(MIN_PRIME_VALUE, MAX_PRIME_VALUE, _p);

	uint64_t module = _p * _q;
	uint64_t theta = (_p - 1) * (_q - 1);

	uint64_t key_exp = _signer_utils::generate_coprime_number(MIN_PRIME_VALUE, theta);

	int64_t d = 0, y_k = 0;
	_signer_utils::extended_gcd(key_exp, theta, d, y_k);

	if (d < 0) {
		d += theta;
	}

	// _public_key = _rsa_utils::key_to_string(key_exp, module);
	// _private_key = _rsa_utils::key_to_string(d, module);
}

const char* digital_signer::invalid_key::what() const throw ()
{
	return "No key for this message exists in current storage!";
}
