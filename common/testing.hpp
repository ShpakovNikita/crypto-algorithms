#pragma once
#include <iostream>
#include <cstdint>

static uint32_t tests_passed = 0;

#define TEST_CASE_BEGIN(case_name) \
void case_name() \
{ \
	std::cerr << #case_name << " test started!" << std::endl;

#define TEST_CASE_END() \
	std::cerr << __FUNCTION__ << " test passed!\n" << std::endl; \
	++tests_passed; \
}