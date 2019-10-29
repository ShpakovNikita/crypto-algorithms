#pragma once

#include <string>
#include <vector>
#include <bitset>

constexpr uint32_t BLOCK_SIZE = 8;
constexpr uint32_t KEY_LENGTH = 32;
constexpr uint32_t HALF_BLOCK_SIZE_BITS = BLOCK_SIZE * CHAR_BIT / 2;

class gost_encrypter
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	gost_encrypter(const std::string& key);
	~gost_encrypter() = default;

	std::string encrypt(const std::string& message) const;
	std::string decrypt(const std::string& message) const;

private:
	struct invalid_action : public std::exception
	{
		const char* what() const throw ();
	};

	enum class _e_action
	{
		encrypt = 0,
		decrypt,
		undefined,
	};

	static std::vector<std::string> _build_message_blocks(const std::string& message);
	static std::string _try_remove_padding(const std::string& message);
	static std::string _check_key(const std::string& key);
	static std::string _construct_padding_message(const std::string& message);

	std::bitset<BLOCK_SIZE * CHAR_BIT> _encrypt_block(const std::string& block, _e_action action) const;
	std::string _internal_run(const std::string& message, _e_action action) const;

	void _generate_keys();
	std::bitset<HALF_BLOCK_SIZE_BITS> feistel_function(
		const std::bitset<HALF_BLOCK_SIZE_BITS>& a_data,
		const std::bitset<HALF_BLOCK_SIZE_BITS>& x_key) const;

	std::string _key;
	std::vector<std::bitset<HALF_BLOCK_SIZE_BITS>> _generated_keys;
};
