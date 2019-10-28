#include <stdio.h>
#include <string>
#include <iostream>
#include <cassert>

#include "gost_encrypter.hpp"

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
	std::string message = "Hello wo";
	std::string key = "secretKDAeAAet_ksedset_kssJhin_k";

	gost_encrypter encrypter(key);
	std::cout << "initial name " << message << std::endl;

	std::string encrypted = encrypter.encrypt(message);
	std::cout << "encrypted name " << encrypted << std::endl;

	assert(message != encrypted);

	std::string decrypted = encrypter.decrypt(encrypted);
	std::cout << "decrypted name " << decrypted << std::endl;

	assert(message == decrypted);
}
TEST_CASE_END()

TEST_CASE_BEGIN(cypher_long_message_encrypt_decrypt)
{
	std::string message = "Hello wssdd#2123osssssssssssssadsadsads adsadas";
	std::string key = "secretKDAeAAet_ksedset_kssJhin_k";

	gost_encrypter encrypter(key);
	std::cout << "initial name " << message << std::endl;

	std::string encrypted = encrypter.encrypt(message);
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
		cypher_long_message_encrypt_decrypt();

		std::cerr << tests_passed << " tests passed!" << std::endl;
	}
	catch (const gost_encrypter::invalid_key & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
