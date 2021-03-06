#include <iostream>
#include <string>
#include <cassert>

#include "rsa_encrypter.hpp"

static uint32_t tests_passed = 0;

#define TEST_CASE_BEGIN(case_name) \
void case_name() \
{ \
	std::cerr << #case_name << " test started!" << std::endl;

#define TEST_CASE_END() \
	std::cerr << __FUNCTION__ << " test passed!\n" << std::endl; \
	++tests_passed; \
}

TEST_CASE_BEGIN(cipher_base_encrypt_decrypt)
{
	std::string message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";

	rsa_encrypter encrypter;
	std::cout << "initial name " << message << std::endl;

	const std::string& public_key = encrypter.get_public_key();
	std::cout << "public key " << public_key << std::endl;

	std::string encrypted = rsa_encrypter::encrypt(message, public_key);
	std::cout << "encrypted name " << encrypted << std::endl;

	assert(message != encrypted);

	std::string decrypted = encrypter.decrypt(encrypted);
	std::cout << "decrypted name " << decrypted << std::endl;

	assert(message == decrypted);
}
TEST_CASE_END()

TEST_CASE_BEGIN(cipher_base_stress)
{
	const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";


	for (uint64_t i = 0; i < 100; ++i)
	{
		std::string message;
		message.resize(100);

		for (uint64_t j = 0; j < 100; ++j) {
			message[j] = alphanum[rand() % (sizeof(alphanum) - 1)];
		}

		rsa_encrypter encrypter;
		const std::string& public_key = encrypter.get_public_key();
		std::string encrypted = rsa_encrypter::encrypt(message, public_key);
		assert(message != encrypted);
		std::string decrypted = encrypter.decrypt(encrypted);
		assert(message == decrypted);
	}
}
TEST_CASE_END()

int main()
{
	try
	{
		cipher_base_encrypt_decrypt();
		cipher_base_stress();

		std::cerr << tests_passed << " tests passed!" << std::endl;
	}
	catch (const std::runtime_error & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
