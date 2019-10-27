#include <string>
#include <vector>

class rsa_encrypter
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	static std::string encrypt(const std::string& message, const std::string& key);

	rsa_encrypter();
	~rsa_encrypter() = default;

	std::string decrypt(const std::string& message) const;
	std::string encrypt(const std::string& message) const;

	const std::string& get_public_key() const;

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

	std::string _internal_run(const std::string& message, _e_action action) const;

	void _generate_keys();

	void _prepare_prime_data();

	std::string _generate_public_key() const;
	std::string _generate_private_key() const;

	std::string private_key;
	std::string public_key;
};
