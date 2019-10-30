#include "gost_wrapper.hpp"
#include <stdexcept>

#include "gost_encrypter.hpp"

gost_wrapper::gost_wrapper(const std::string& key_1, const std::string& key_2, 
	const std::string& key_3, gost_wrapper_mode mode)
	: _encrypter_level_1(std::make_unique<gost_encrypter>(key_1))
	, _encrypter_level_2(std::make_unique<gost_encrypter>(key_2))
	, _mode(mode)
{
	if (_mode != gost_wrapper_mode::wrapper_ede2)
	{
		_encrypter_level_3 = std::make_unique<gost_encrypter>(key_3);
	}
}

gost_wrapper::~gost_wrapper() = default;

std::string gost_wrapper::encrypt(const std::string& message) const
{
	switch (_mode)
	{
	case gost_wrapper::gost_wrapper_mode::wrapper_eee3:
		return _encrypt_eee3(message);
		[[fallthrough]];
	case gost_wrapper::gost_wrapper_mode::wrapper_ede3:
		return _encrypt_ede3(message);
		[[fallthrough]];
	case gost_wrapper::gost_wrapper_mode::wrapper_ede2:
		return _encrypt_ede2(message);
		[[fallthrough]];
	default:
		break;
	}

	throw std::runtime_error("undefined wrapper mode!");
}

std::string gost_wrapper::decrypt(const std::string& message) const
{
	switch (_mode)
	{
	case gost_wrapper::gost_wrapper_mode::wrapper_eee3:
		return _decrypt_eee3(message);
		[[fallthrough]];
	case gost_wrapper::gost_wrapper_mode::wrapper_ede3:
		return _decrypt_ede3(message);
		[[fallthrough]];
	case gost_wrapper::gost_wrapper_mode::wrapper_ede2:
		return _decrypt_ede2(message);
		[[fallthrough]];
	default:
		break;
	}

	throw std::runtime_error("undefined wrapper mode!");
}

std::string gost_wrapper::_encrypt_eee3(const std::string& message) const
{
	std::string message_level_1 = _encrypter_level_1->encrypt(message);
	std::string message_level_2 = _encrypter_level_2->encrypt(message_level_1);
	std::string message_level_3 = _encrypter_level_3->encrypt(message_level_2);

	return message_level_3;
}

std::string gost_wrapper::_decrypt_eee3(const std::string& message) const
{
	std::string message_level_2 = _encrypter_level_3->decrypt(message);
	std::string message_level_1 = _encrypter_level_2->decrypt(message_level_2);
	std::string initial_message = _encrypter_level_1->decrypt(message_level_1);

	return initial_message;
}

std::string gost_wrapper::_encrypt_ede3(const std::string& message) const
{
	std::string message_level_1 = _encrypter_level_1->encrypt(message);
	std::string message_level_2 = _encrypter_level_2->decrypt(message_level_1);
	std::string message_level_3 = _encrypter_level_3->encrypt(message_level_2);

	return message_level_3;
}

std::string gost_wrapper::_decrypt_ede3(const std::string& message) const
{
	std::string message_level_2 = _encrypter_level_3->decrypt(message);
	std::string message_level_1 = _encrypter_level_2->encrypt(message_level_2);
	std::string initial_message = _encrypter_level_1->decrypt(message_level_1);

	return initial_message;
}

std::string gost_wrapper::_encrypt_ede2(const std::string& message) const
{
	std::string message_level_1 = _encrypter_level_1->encrypt(message);
	std::string message_level_2 = _encrypter_level_2->decrypt(message_level_1);
	std::string message_level_3 = _encrypter_level_1->encrypt(message_level_2);

	return message_level_3;
}

std::string gost_wrapper::_decrypt_ede2(const std::string& message) const
{
	std::string message_level_2 = _encrypter_level_1->decrypt(message);
	std::string message_level_1 = _encrypter_level_2->encrypt(message_level_2);
	std::string initial_message = _encrypter_level_1->decrypt(message_level_1);

	return initial_message;
}
