#pragma once

#include <memory>
#include <string>

class des_encrypter;

class triple_des
{
public:
	enum class triple_des_mode
	{
		des_eee3 = 0,
		des_ede3,
		des_ede2,
		undefined,
	};

	triple_des(const std::string& key_1, const std::string& key_2, 
		const std::string& key_3, triple_des_mode mode);
	~triple_des();

	std::string encrypt(const std::string& message) const;
	std::string decrypt(const std::string& message) const;

private:
	std::string _encrypt_des_eee3(const std::string& message) const;
	std::string _decrypt_des_eee3(const std::string& message) const;

	std::string _encrypt_des_ede3(const std::string& message) const;
	std::string _decrypt_des_ede3(const std::string& message) const;

	std::string _encrypt_des_ede2(const std::string& message) const;
	std::string _decrypt_des_ede2(const std::string& message) const;

	std::unique_ptr<des_encrypter> _encrypter_level_1;
	std::unique_ptr<des_encrypter> _encrypter_level_2;
	std::unique_ptr<des_encrypter> _encrypter_level_3;

	triple_des_mode _mode = triple_des_mode::des_ede3;
};
