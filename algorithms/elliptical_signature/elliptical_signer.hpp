#pragma once

#include <string>
#include <vector>
#include <unordered_map>

#include "big_integer.hpp"
#include "elliptical_point.hpp"

class elliptical_signer
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	elliptical_signer();
	~elliptical_signer() = default;

	std::string sign_message(const std::string& message);
	bool verify_message(const std::string& message) const;

	std::string get_public_key() const;

private:
	big_unsigned _private_key;
	elliptical_point _public_key;

    std::unordered_map<std::string, std::tuple<big_integer, big_integer>> _signatures;
};
