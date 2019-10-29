#include <stdio.h>
#include <string>
#include <iostream>
#include <cassert>

#include "gost_hash.hpp"

static uint32_t tests_passed = 0;

#define TEST_CASE_BEGIN(case_name) \
void case_name() \
{ \
	std::cerr << #case_name << " test started!" << std::endl;

#define TEST_CASE_END() \
	std::cerr << __FUNCTION__ << " test passed!\n" << std::endl; \
	++tests_passed; \
}

TEST_CASE_BEGIN(hash_base_encrypt_decrypt)
{
	std::string message = "secretKDAeAAet_ksedset_kssJhin_k";

	gost_hash hash_generator(message);
	std::cout << "initial name " << message << std::endl;

	std::string hash_result = hash_generator.generate_hash(message);
	std::cout << "hash result name " << hash_result << std::endl;

	assert(hash_result != message);
	assert(hash_result.size() == 32);
}
TEST_CASE_END()

TEST_CASE_BEGIN(hash_long_message_encrypt_decrypt)
{
	std::string message = "secretKDAeAAet_ksedset_kssJhin_ksecretKDAeAAet_ksedset_kssJhin_ksecretKDAeAAet_ksedset_kssJhin_kdsdsdsds";

	gost_hash hash_generator(message);
	std::cout << "initial name " << message << std::endl;

	std::string hash_result = hash_generator.generate_hash(message);
	std::cout << "hash result name " << hash_result << std::endl;

	assert(hash_result != message);
	assert(hash_result.size() == 32);
}
TEST_CASE_END()

int main()
{
	try
	{
		hash_base_encrypt_decrypt();
		hash_long_message_encrypt_decrypt();

		std::cerr << tests_passed << " tests passed!" << std::endl;
	}
	catch (const gost_hash::invalid_key & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
