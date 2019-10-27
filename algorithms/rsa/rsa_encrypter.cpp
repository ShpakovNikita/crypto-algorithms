#include "rsa_encrypter.hpp"


rsa_encrypter::rsa_encrypter()
{
	_generate_keys();
}

std::string rsa_encrypter::encrypt(const std::string& message) const
{
	return encrypt(message, public_key);
}

std::string rsa_encrypter::encrypt(const std::string& message, const std::string& key)
{
	return "fake";
}

std::string rsa_encrypter::decrypt(const std::string& message) const
{
	return "fake";
}

const std::string& rsa_encrypter::get_public_key() const
{
	return public_key;
}

std::string rsa_encrypter::_internal_run(const std::string& message, _e_action action) const
{
	return "fake";
}

void rsa_encrypter::_generate_keys()
{
	_prepare_prime_data();

	private_key = _generate_private_key();
	public_key = _generate_public_key();
}

void rsa_encrypter::_prepare_prime_data()
{

}

std::string rsa_encrypter::_generate_public_key() const
{
	return "fake";
}

std::string rsa_encrypter::_generate_private_key() const
{
	return "fake";
}

const char* rsa_encrypter::invalid_action::what() const throw ()
{
	return "Invalid action passed! Encrypt logical error";
}
