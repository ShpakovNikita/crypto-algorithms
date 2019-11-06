#include <stdio.h>
#include <string>
#include <iostream>
#include <cassert>

#include "blowfish_encrypter.hpp"
#include "testing.hpp"

TEST_CASE_BEGIN(cypher_base_encrypt_decrypt)
{
	std::string message = "Hello wo";
	std::string key = "secret_k";

	des_encrypter encrypter(key);
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
	std::string message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
	std::string key = "secret_s";

	des_encrypter encrypter(key);
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
	catch (const des_encrypter::invalid_key & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
