#pragma once

#include <memory>
#include <string>

class gost_encrypter;

/*
  This class is just my heuristics, inspired by triple des algorithms
*/
class gost_wrapper
{
public:
	enum class gost_wrapper_mode
	{
		wrapper_eee3 = 0,
		wrapper_ede3,
		wrapper_ede2,
		undefined,
	};

	gost_wrapper(const std::string& key_1, const std::string& key_2, 
		const std::string& key_3, gost_wrapper_mode mode);
	~gost_wrapper();

	std::string encrypt(const std::string& message) const;
	std::string decrypt(const std::string& message) const;

private:
	std::string _encrypt_eee3(const std::string& message) const;
	std::string _decrypt_eee3(const std::string& message) const;

	std::string _encrypt_ede3(const std::string& message) const;
	std::string _decrypt_ede3(const std::string& message) const;

	std::string _encrypt_ede2(const std::string& message) const;
	std::string _decrypt_ede2(const std::string& message) const;

	std::unique_ptr<gost_encrypter> _encrypter_level_1;
	std::unique_ptr<gost_encrypter> _encrypter_level_2;
	std::unique_ptr<gost_encrypter> _encrypter_level_3;

	gost_wrapper_mode _mode = gost_wrapper_mode::wrapper_ede3;
};
