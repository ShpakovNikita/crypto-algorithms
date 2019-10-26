#include <stdio.h>
#include <string>
#include <iostream>
#include <cassert>
#include "des_encrypter.hpp"

void test_cypher_base_encrypt_decrypt()
{
	std::string message = "Hello wo";
	std::string key = "secret_k";

	std::unique_ptr<des_encrypter> encrypter = std::make_unique<des_encrypter>(key);

	std::string encrypted = encrypter->encrypt(message);
	std::cout << encrypted << std::endl;

	std::string decrypted = encrypter->decrypt(encrypted);
	std::cout << decrypted << std::endl;
    
    assert(message == decrypted);
    std::cerr << "main::test_cypher_base_encrypt_decrypt() test passed!" << std::endl;
}

int main()
{
	try
	{
		test_cypher_base_encrypt_decrypt();
	}
	catch (const des_encrypter::invalid_key & e)
	{
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
