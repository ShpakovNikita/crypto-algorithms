#include <cstdio>
#include <string>
#include <iostream>
#include <cassert>

#include "gost_hash.hpp"
#include "testing.hpp"

TEST_CASE_BEGIN(hash_base_message)
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

TEST_CASE_BEGIN(hash_long_message)
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
		hash_base_message();
		hash_long_message();

		std::cerr << tests_passed << " tests passed!" << std::endl;
	}
	catch (const gost_hash::invalid_key & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
