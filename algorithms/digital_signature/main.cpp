#include <iostream>
#include <string>
#include <cassert>

#include "digital_signer.hpp"
#include "testing.hpp"

TEST_CASE_BEGIN(signer_base_sign_verify)
{
	std::string message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";

	digital_signer signer;
	std::cout << "initial message to sign " << message << std::endl;

	std::string signature = signer.sign_message(message);
	std::cout << "signature " << signature << std::endl;

	const std::string& public_key = signer.get_public_key();
	std::cout << "public key " << public_key << std::endl;

	[[maybe_unused]]
	bool verified = signer.verify_message(message);

	std::cout << "is signature verified? " << verified << std::endl;

	assert(verified);
}
TEST_CASE_END()

int main()
{
	try
	{
		signer_base_sign_verify();

		std::cerr << tests_passed << " tests passed!" << std::endl;
	}
	catch (const std::runtime_error & e)
	{
		std::cerr << tests_passed << " tests passed, before error occurred" << std::endl;

		std::cerr << e.what() << std::endl;
	}

	return EXIT_SUCCESS;
}
