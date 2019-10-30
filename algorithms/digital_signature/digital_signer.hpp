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

	digital_signer() = default;
	~digital_signer() = default;

	std::string sign_message(const std::string& message) const;
	bool verify_message(const std::string& message) const;

	const std::string& get_public_key(const std::string& message) const;

private:
	void _generate_keys(const std::string& message_hash);

	std::unordered_map<std::string, std::string> _private_keys;
	std::unordered_map<std::string, std::string> _public_keys;
    std::unordered_map<std::string, big_unsigned> _signatures;
};
