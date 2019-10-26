#include <stdio.h>
#include <string>
#include <iostream>
#include "des_encrypter.hpp"

void test_cypher()
{
	std::string message = "Hello wo";
	std::string key = "secret_k";

	std::unique_ptr<des_encrypter> encrypter = std::make_unique<des_encrypter>(key);

	std::string encrypted = encrypter->encrypt(message);
	std::cout << encrypted << std::endl;

	std::string decrypted = encrypter->decrypt(message);
	std::cout << decrypted << std::endl;
}

int main()
{
	try
	{
		test_cypher();
	}
	catch (const des_encrypter::invalid_key & e)
	{
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
