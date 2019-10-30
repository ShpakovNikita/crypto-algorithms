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

	const std::string& get_public_key(const std::string& message) const;

private:
	std::unordered_map<std::string, std::string> _private_keys;
	std::unordered_map<std::string, std::string> _public_keys;

	// TODO: change on string
    std::unordered_map<std::string, std::tuple<big_unsigned, big_unsigned>> _signatures;

	// domain params
	big_unsigned p = 0;
	big_unsigned q = 0;
	big_unsigned g = 0;
};
