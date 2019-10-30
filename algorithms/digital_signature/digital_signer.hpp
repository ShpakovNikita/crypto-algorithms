#pragma once

#include <string>
#include <vector>
#include <unordered_map>

#include "BigIntegerLibrary.hh"

using big_unsigned = BigUnsigned;

class digital_signer
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	digital_signer();
	~digital_signer() = default;

	std::string sign_message(const std::string& message);
	bool verify_message(const std::string& message) const;

	std::string get_public_key() const;

private:
	big_unsigned _private_key;
	big_unsigned _public_key;

    std::unordered_map<std::string, std::tuple<big_unsigned, big_unsigned>> _signatures;

	// domain params
	big_unsigned _p = 0;
	big_unsigned _q = 0;
	big_unsigned _g = 0;
};
