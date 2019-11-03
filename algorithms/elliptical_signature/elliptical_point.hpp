#pragma once
#include "big_integer.hpp"
#include <string>

struct elliptical_point
{
public:
	static elliptical_point multiply(big_integer x, elliptical_point point);

	elliptical_point(const elliptical_point& point);
	elliptical_point(
		const big_integer& x, 
		const big_integer& y, 
		const big_integer& a,
		const big_integer& b, 
		const big_unsigned& p);
	elliptical_point();

	elliptical_point operator + (const elliptical_point& other_point);

	std::string to_string() const;

	big_integer x;
	big_integer y;
	big_integer a;
	big_integer b;
	big_unsigned p;

private:
	static elliptical_point double_point(const elliptical_point& other_point);
};