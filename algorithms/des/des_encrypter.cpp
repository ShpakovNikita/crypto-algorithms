#include "des_encrypter.hpp"

#define BIT_PERMUT(a, b, c) (((a[(b) / 8] >> (7 - (b % 8))) & 0x01) << (c))
#define BIT_PERMUT_INTR(a, b, c) ((((a) >> (31 - (b))) & 0x00000001) << (c))
#define BIT_PERMUT_INTL(a, b, c) ((((a) << (b)) & 0x80000000) >> (c))
#define SBOX_PERMUT_BIT(a) (((a) & 0x20) | (((a) & 0x1f) >> 1) | (((a) & 0x01) << 4))

constexpr uint32_t BLOCK_SIZE = 8;
constexpr uint32_t ROUNDS_COUNT = 16;


des_encrypter::des_encrypter(const std::string& key)
	: _key(_check_key(key))
{
	_generate_keys();
}

std::string des_encrypter::encrypt(const std::string& message)
{
	return _internal_run(message, _e_action::encrypt);
}

std::string des_encrypter::decrypt(const std::string& message)
{
	return _internal_run(message, _e_action::decrypt);
}

std::vector<std::string> des_encrypter::_build_message_blocks(const std::string& message)
{
	std::vector<std::string> blocks;
	size_t blocks_count = message.size() / BLOCK_SIZE;
	blocks.reserve(blocks_count);
	for (uint32_t i = 0; i < blocks_count; ++i)
	{
		blocks.push_back(message.substr(static_cast<size_t>(i) * BLOCK_SIZE, BLOCK_SIZE));
	}

	return blocks;
}

std::string des_encrypter::_check_key(const std::string& key)
{
	if (key.size() < 8)
	{
		throw invalid_key();
	}

	return key.substr(0, 8);
}

std::string des_encrypter::_construct_padding_message(const std::string& message)
{
	uint8_t padding_len = BLOCK_SIZE - message.size() % BLOCK_SIZE;
	return message + std::string(padding_len, char(padding_len));
}

void des_encrypter::_generate_keys()
{
	_generated_keys.resize(ROUNDS_COUNT, std::string(BLOCK_SIZE - 2, '*'));

	uint32_t C = 0, D = 0;

	uint32_t key_rnd_shift[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
	uint32_t key_perm_c[28] = { 
		56,48,40,32,24,16,8,0,57,49,41,33,25,17,
		9,1,58,50,42,34,26,18,10,2,59,51,43,35 
	};
	uint32_t key_perm_d[28] = {
		62,54,46,38,30,22,14,6,61,53,45,37,29,21,
		13,5,60,52,44,36,28,20,12,4,27,19,11,3 
	};
	uint32_t key_compression[48] = { 
		13,16,10,23,0,4,2,27,14,5,20,9,
		22,18,11,3,25,7,15,6,26,19,12,1,
		40,51,30,36,46,54,29,39,50,44,32,47,
		43,48,38,55,33,52,45,41,49,35,28,31 
	};

	char* key = _key.data();

	for (uint32_t i = 0, j = 31, C = 0; i < 28; ++i, --j)
		C |= BIT_PERMUT(key, key_perm_c[i], j);

	for (uint32_t i = 0, j = 31, D = 0; i < 28; ++i, --j)
		D |= BIT_PERMUT(key, key_perm_d[i], j);

	for (uint32_t i = 0; i < ROUNDS_COUNT; ++i) {
		C = ((C << key_rnd_shift[i]) | (C >> (28 - key_rnd_shift[i]))) & 0xfffffff0;
		D = ((D << key_rnd_shift[i]) | (D >> (28 - key_rnd_shift[i]))) & 0xfffffff0;

		uint32_t to_gen = i;

		for (uint32_t j = 0; j < 6; ++j)
			_generated_keys[to_gen][j] = 0;

		for (uint32_t j = 0; j < 24; ++j)
			_generated_keys[to_gen][j / 8] |= BIT_PERMUT_INTR(C, key_compression[j], 7 - (j % 8));

		for (uint32_t j = 0; j < 48; ++j)
			_generated_keys[to_gen][j / 8] |= BIT_PERMUT_INTR(D, key_compression[j] - 28, 7 - (j % 8));
	}
}

std::string des_encrypter::_internal_run(const std::string& message, _e_action action)
{
	std::string message_to_process = _construct_padding_message(message);
	std::vector<std::string> source_blocks = _build_message_blocks(message_to_process);
	std::vector<std::string> result_blocks;
	result_blocks.reserve(source_blocks.size());

	for (const auto& block : source_blocks)
	{

	}

	return message_to_process;
}

const char* des_encrypter::invalid_key::what() const throw ()
{
	return "Invalid key! Key should be no less than 8 chars";
}
