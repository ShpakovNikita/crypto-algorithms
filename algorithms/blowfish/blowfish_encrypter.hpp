#pragma once

#include <string>
#include <vector>
#include <bitset>

constexpr uint32_t BLOCK_SIZE = 8;

class blowfish_encrypter
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	blowfish_encrypter(const std::string& key);
	~blowfish_encrypter() = default;

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
	static std::vector<uint32_t> _check_key(const std::string& key);
	static std::string _construct_padding_message(const std::string& message);

	uint32_t blowfish_func(uint32_t x) const;

	std::tuple<uint32_t, uint32_t> _encrypt(uint32_t left_block, uint32_t right_block) const;
	std::tuple<uint32_t, uint32_t> _decrypt(uint32_t left_block, uint32_t right_block) const;

	std::string _internal_run(const std::string& message, _e_action action) const;

	void _generate_keys();

	std::vector<uint32_t> _key;
	std::vector<uint32_t> _generated_keys;
	std::vector<std::vector<uint32_t>> _generated_boxes;
};
