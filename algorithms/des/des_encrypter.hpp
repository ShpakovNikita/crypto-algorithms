#include <string>
#include <vector>
#include <bitset>

constexpr uint32_t BLOCK_SIZE = 8;

class des_encrypter
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	des_encrypter(const std::string& key);
	~des_encrypter() = default;

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

	static std::bitset<BLOCK_SIZE* CHAR_BIT / 2> _substitude_block(const std::bitset<(BLOCK_SIZE - 2)* CHAR_BIT>& block);

	std::bitset<BLOCK_SIZE* CHAR_BIT> _encrypt_block(const std::string& block, _e_action action) const;
	std::string _internal_run(const std::string& message, _e_action action) const;

	void _generate_keys();

	std::string _key;
	std::vector<std::bitset<(BLOCK_SIZE - 2) * CHAR_BIT>> _generated_keys;
};
