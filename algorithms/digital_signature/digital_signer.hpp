#pragma once

#include <string>
#include <vector>

class digital_signer
{
public:
	static std::string encrypt(const std::string& message, const std::string& key);

	digital_signer();
	~digital_signer() = default;

	std::string decrypt(const std::string& message) const;
	std::string encrypt(const std::string& message) const;

	const std::string& get_public_key() const;

private:
	void _generate_keys();

	std::string _private_key;
	std::string _public_key;
};
