#include "elliptical_point.hpp"

elliptical_point::elliptical_point(const elliptical_point& point)
	: x(point.x)
	, y(point.y)
	, a(point.a)
	, b(point.b)
	, p(point.p)
{}

elliptical_point::elliptical_point() = default;

elliptical_point::elliptical_point(
	const big_integer& _x, 
	const big_integer& _y, 
	const big_integer& _a, 
	const big_integer& _b, 
	const big_unsigned& _p)
	: x(_x)
	, y(_y)
	, a(_a)
	, b(_b)
	, p(_p)
{}

std::string elliptical_point::to_string() const
{
	return 
		bigIntegerToString(x) + " " +
		bigIntegerToString(y) + " " +
		bigIntegerToString(a) + " " +
		bigIntegerToString(b) + " " +
		bigUnsignedToString(p);
}

elliptical_point elliptical_point::double_point(const elliptical_point& other_point)
{
	elliptical_point result_point;
	result_point.a = other_point.a;
	result_point.b = other_point.b;
	result_point.p = other_point.p;

	big_integer dy = big_integer(3) * other_point.x * other_point.x + other_point.a;
	big_integer dx = big_integer(2) * other_point.y;

	if (dx < 0)
		dx += other_point.p;
	if (dy < 0)
		dy += other_point.p;

	big_integer m = (dy * modinv(dx, other_point.p)) % other_point.p;
	result_point.x = (m * m - other_point.x - other_point.x) % other_point.p;
	result_point.y = (m * (other_point.x - result_point.x) - other_point.y) % other_point.p;
	if (result_point.x < 0)
		result_point.x += other_point.p;
	if (result_point.y < 0)
		result_point.y += other_point.p;

	return result_point;
}

elliptical_point elliptical_point::multiply(big_integer x, elliptical_point point)
{
	elliptical_point temp = point;
	--x;
	while (x != 0)
	{
		if ((x % 2) != 0)
		{
			if ((temp.x == point.x) || (temp.y == point.y))
				temp = double_point(temp);
			else
				temp = temp + point;

			--x;
		}
		x /= 2;
		point = double_point(point);
	}
	return temp;
}

elliptical_point elliptical_point::operator+(const elliptical_point& other_point)
{
	elliptical_point result_point;
	result_point.a = a;
	result_point.b = b;
	result_point.p = p;

	big_integer dy = other_point.y - y;
	big_integer dx = other_point.x - x;

	if (dx < 0)
		dx += p;
	if (dy < 0)
		dy += p;

	big_integer m = (dy * modinv(dx, p)) % p;
	if (m < 0)
		m += p;

	result_point.x = (m * m - x - other_point.x) % p;
	result_point.y = (m * (x - result_point.x) - y) % p;

	if (result_point.x < 0)
		result_point.x += p;
	if (result_point.y < 0)
		result_point.y += p;
	return result_point;
}
