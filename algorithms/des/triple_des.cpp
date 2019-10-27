#include "triple_des.hpp"
#include "des_encrypter.hpp"
#include <string>
#include <stdexcept>

triple_des::triple_des(const std::string& key_1, const std::string& key_2, 
	const std::string& key_3, triple_des_mode mode)
	: _encrypter_level_1(std::make_unique<des_encrypter>(key_1))
	, _encrypter_level_2(std::make_unique<des_encrypter>(key_2))
	, _mode(mode)
{
	if (_mode != triple_des_mode::des_ede2)
	{
		_encrypter_level_3 = std::make_unique<des_encrypter>(key_3);
	}
}

triple_des::~triple_des() = default;

std::string triple_des::encrypt(const std::string& message)
{
	switch (_mode)
	{
	case triple_des::triple_des_mode::des_eee3:
		return _encrypt_des_eee3(message);
		[[fallthrough]] ;
	case triple_des::triple_des_mode::des_ede3:
		return _encrypt_des_ede3(message);
		[[fallthrough]];
	case triple_des::triple_des_mode::des_ede2:
		return _encrypt_des_ede2(message);
		[[fallthrough]];
	default:
		break;
	}

	throw std::runtime_error("undefined des mode!");
}

std::string triple_des::decrypt(const std::string& message)
{
	switch (_mode)
	{
	case triple_des::triple_des_mode::des_eee3:
		return _decrypt_des_eee3(message);
		[[fallthrough]];
	case triple_des::triple_des_mode::des_ede3:
		return _decrypt_des_ede3(message);
		[[fallthrough]];
	case triple_des::triple_des_mode::des_ede2:
		return _decrypt_des_ede2(message);
		[[fallthrough]];
	default:
		break;
	}

	throw std::runtime_error("undefined des mode!");
}

std::string triple_des::_encrypt_des_eee3(const std::string& message)
{
	std::string message_level_1 = _encrypter_level_1->encrypt(message);
	std::string message_level_2 = _encrypter_level_2->encrypt(message_level_1);
	std::string message_level_3 = _encrypter_level_3->encrypt(message_level_2);

	return message_level_3;
}

std::string triple_des::_decrypt_des_eee3(const std::string& message)
{
	std::string message_level_2 = _encrypter_level_3->decrypt(message);
	std::string message_level_1 = _encrypter_level_2->decrypt(message_level_2);
	std::string initial_message = _encrypter_level_1->decrypt(message_level_1);

	return initial_message;
}

std::string triple_des::_encrypt_des_ede3(const std::string& message)
{
	std::string message_level_1 = _encrypter_level_1->encrypt(message);
	std::string message_level_2 = _encrypter_level_2->decrypt(message_level_1);
	std::string message_level_3 = _encrypter_level_3->encrypt(message_level_2);

	return message_level_3;
}

std::string triple_des::_decrypt_des_ede3(const std::string& message)
{
	std::string message_level_2 = _encrypter_level_3->decrypt(message);
	std::string message_level_1 = _encrypter_level_2->encrypt(message_level_2);
	std::string initial_message = _encrypter_level_1->decrypt(message_level_1);

	return initial_message;
}

std::string triple_des::_encrypt_des_ede2(const std::string& message)
{
	std::string message_level_1 = _encrypter_level_1->encrypt(message);
	std::string message_level_2 = _encrypter_level_2->decrypt(message_level_1);
	std::string message_level_3 = _encrypter_level_1->encrypt(message_level_2);

	return message_level_3;
}

std::string triple_des::_decrypt_des_ede2(const std::string& message)
{
	std::string message_level_2 = _encrypter_level_1->decrypt(message);
	std::string message_level_1 = _encrypter_level_2->encrypt(message_level_2);
	std::string initial_message = _encrypter_level_1->decrypt(message_level_1);

	return initial_message;
}
