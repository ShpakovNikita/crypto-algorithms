#pragma once

#include "big_integer.hpp"

namespace prime_utils
{
	bool is_prime(const big_unsigned& num, uint64_t tests_count = 10);
	big_unsigned generate_prime_candidate(uint64_t bit_length);
	big_unsigned generate_prime_number(uint64_t bit_length);
	big_unsigned generate_prime_number(const big_unsigned& lower, const big_unsigned& upper);
}