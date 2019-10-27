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

TEST_CASE_BEGIN(cypher_base_encrypt_decrypt)
{
	std::string message = "Hello world";

	rsa_encrypter encrypter;
	std::cout << "initial name " << message << std::endl;

	const std::string& public_key = encrypter.get_public_key();
	std::cout << "public key " << message << std::endl;

	std::string encrypted = rsa_encrypter::encrypt(message, public_key);
	std::cout << "encrypted name " << encrypted << std::endl;

	assert(message != encrypted);

	std::string decrypted = encrypter.decrypt(encrypted);
	std::cout << "decrypted name " << decrypted << std::endl;

	assert(message == decrypted);
}
TEST_CASE_END()

int main()
{
	try
	{
		cypher_base_encrypt_decrypt();

		std::cerr << tests_passed << " tests passed!" << std::endl;
	}
	catch (const std::runtime_error & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
