#include <string>
#include <vector>


class des_encrypter
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	des_encrypter(const std::string& key);
	~des_encrypter() = default;

	std::string encrypt(const std::string& message);
	std::string decrypt(const std::string& message);

private:
	enum class _e_action
	{
		encrypt = 0,
		decrypt,
	};

	static std::vector<std::string> _build_message_blocks(const std::string& message);

	std::string _check_key(const std::string& key);
	std::string _construct_padding_message(const std::string& message);
	void _generate_keys();

	std::string _internal_run(const std::string& message, _e_action action);

	std::string _key;
	std::vector<std::string> _generated_keys;
};
