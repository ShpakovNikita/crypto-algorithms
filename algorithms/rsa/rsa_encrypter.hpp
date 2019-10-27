#include <string>
#include <vector>

class rsa_encrypter
{
public:
	static std::string encrypt(const std::string& message, const std::string& key);

	rsa_encrypter();
	~rsa_encrypter() = default;

	std::string decrypt(const std::string& message) const;
	std::string encrypt(const std::string& message) const;

	const std::string& get_public_key() const;

private:
	void _generate_keys();

	std::string _private_key;
	std::string _public_key;
};
