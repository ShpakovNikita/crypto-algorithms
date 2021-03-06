#include <stdio.h>
#include <string>
#include <iostream>
#include <cassert>

#include "des_encrypter.hpp"
#include "triple_des.hpp"
#include "testing.hpp"

TEST_CASE_BEGIN(cipher_base_encrypt_decrypt)
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

TEST_CASE_BEGIN(cipher_long_message_encrypt_decrypt)
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

TEST_CASE_BEGIN(triple_des_eee3_encrypt_decrypt)
{
	std::string message = "Hello wo";
	std::string key_1 = "secret_k";
	std::string key_2 = "secsst_k";
	std::string key_3 = "swovat_k";

	triple_des encrypter(key_1, key_2, key_3, triple_des::triple_des_mode::des_eee3);
	std::cout << "initial name " << message << std::endl;

	std::string encrypted = encrypter.encrypt(message);
	std::cout << "encrypted name " << encrypted << std::endl;

	assert(message != encrypted);

	std::string decrypted = encrypter.decrypt(encrypted);
	std::cout << "decrypted name " << decrypted << std::endl;

	assert(message == decrypted);
}
TEST_CASE_END()

TEST_CASE_BEGIN(triple_des_ede3_encrypt_decrypt)
{
	std::string message = "Hello wo";
	std::string key_1 = "secret_k";
	std::string key_2 = "secsst_k";
	std::string key_3 = "swovat_k";

	triple_des encrypter(key_1, key_2, key_3, triple_des::triple_des_mode::des_ede3);
	std::cout << "initial name " << message << std::endl;

	std::string encrypted = encrypter.encrypt(message);
	std::cout << "encrypted name " << encrypted << std::endl;

	assert(message != encrypted);

	std::string decrypted = encrypter.decrypt(encrypted);
	std::cout << "decrypted name " << decrypted << std::endl;

	assert(message == decrypted);
}
TEST_CASE_END()

TEST_CASE_BEGIN(triple_des_ede2_encrypt_decrypt)
{
	std::string message = "Hello wo";
	std::string key_1 = "secret_k";
	std::string key_2 = "secsst_k";
	std::string key_3 = "swovat_k";

	triple_des encrypter(key_1, key_2, key_3, triple_des::triple_des_mode::des_ede2);
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
		cipher_base_encrypt_decrypt();
		cipher_long_message_encrypt_decrypt();
		triple_des_eee3_encrypt_decrypt();
		triple_des_ede3_encrypt_decrypt();
		triple_des_ede2_encrypt_decrypt();

		std::cerr << tests_passed << " tests passed!" << std::endl;
	}
	catch (const des_encrypter::invalid_key & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
