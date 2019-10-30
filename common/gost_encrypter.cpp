#include "gost_encrypter.hpp"
#include <string>

#include "bit_utils.hpp"

constexpr uint32_t ROUNDS_COUNT = 32;

// id-tc26-gost-28147-param-Z id of S box
const std::vector<std::vector<uint8_t>> S_BOX =
{
	{13, 4, 6, 2, 11, 5, 12, 9, 15, 8, 14, 7, 0, 3, 0, 1},
	{6, 8, 2, 3, 9, 11, 5, 13, 1, 15, 4, 7, 12, 14, 0, 0},
	{12, 3, 5, 8, 2, 0, 11, 14, 15, 1, 7, 4, 13, 9, 6, 0},
	{13, 8, 2, 1, 14, 4, 0, 6, 7, 0, 11, 5, 3, 15, 9, 12},
	{7, 0, 5, 11, 8, 1, 6, 14, 0, 9, 3, 15, 12, 4, 2, 13},
	{5, 14, 0, 6, 9, 2, 13, 11, 12, 7, 8, 1, 4, 3, 15, 0},
	{8, 15, 2, 5, 6, 9, 1, 13, 0, 4, 12, 0, 14, 11, 3, 7},
	{1, 7, 15, 14, 0, 5, 8, 3, 4, 0, 11, 6, 9, 13, 12, 2},
};

gost_encrypter::gost_encrypter(const std::string& key)
	: _key(_check_key(key))
{
	_generate_keys();
}

std::string gost_encrypter::encrypt(const std::string& message) const
{
	return _internal_run(message, _e_action::encrypt);
}

std::string gost_encrypter::decrypt(const std::string& message) const
{
	return _internal_run(message, _e_action::decrypt);
}

std::vector<std::string> gost_encrypter::_build_message_blocks(const std::string& message)
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

std::string gost_encrypter::_try_remove_padding(const std::string& message)
{
	char padding_size = message[message.size() - 1];
	if (padding_size < BLOCK_SIZE)
	{
		return message.substr(0, message.size() - padding_size);
	}

	return message;
}

std::string gost_encrypter::_check_key(const std::string& key)
{
	if (key.size() < KEY_LENGTH)
	{
		throw invalid_key();
	}

	return key.substr(0, KEY_LENGTH);
}

std::string gost_encrypter::_construct_padding_message(const std::string& message)
{
	uint8_t padding_len = (BLOCK_SIZE - message.size()) % BLOCK_SIZE;
	return message + std::string(padding_len, padding_len);
}

void gost_encrypter::_generate_keys()
{
	_generated_keys.reserve(ROUNDS_COUNT);

	auto key = bit_utils::bytes_to_bitset<KEY_LENGTH>(bit_utils::stob(_key));
	auto subkeys = bit_utils::split_bitset<KEY_LENGTH, BLOCK_SIZE>(key);

	for (uint64_t i = 0; i < ROUNDS_COUNT - BLOCK_SIZE; ++i)
	{
		auto current_key = subkeys[i % BLOCK_SIZE];
		_generated_keys.push_back(std::move(current_key));
	}

	for (int64_t i = BLOCK_SIZE - 1; i >= 0; --i)
	{
		auto current_key = subkeys[i];
		_generated_keys.push_back(std::move(current_key));
	}
}

std::bitset<HALF_BLOCK_SIZE_BITS> gost_encrypter::feistel_function(
	const std::bitset<HALF_BLOCK_SIZE_BITS> & a_data,
	const std::bitset<HALF_BLOCK_SIZE_BITS> & x_key) const
{
	auto [overflow, mod_2_product] = bit_utils::add_mod_2<BLOCK_SIZE / 2>(a_data, x_key);
	auto sequences = bit_utils::split_bitset<BLOCK_SIZE / 2, BLOCK_SIZE>(mod_2_product);
	
	std::bitset<HALF_BLOCK_SIZE_BITS> result_subs;

	for (uint64_t i = 0; i < BLOCK_SIZE; ++i)
	{
		const auto & sequence = sequences[i];
		uint32_t s_input = 0b1000 * sequence[0] + 0b0100 * sequence[1] + 0b0010 * sequence[2] + 0b0001 * sequence[3];
		std::bitset<BLOCK_SIZE / 2> s_output(S_BOX[i][s_input]);

		for (uint64_t j = 0; j < BLOCK_SIZE / 2; ++j)
		{
			// default bitset conversion inversed, because of that we have to flip values
			result_subs[i * BLOCK_SIZE / 2 + j] = s_output[BLOCK_SIZE / 2 - j - 1];
		}
	}

	auto shifted_result = bit_utils::shift_bitset_cyclic<HALF_BLOCK_SIZE_BITS>(result_subs, 11);
	return shifted_result;
}

std::string gost_encrypter::_internal_run(const std::string& message, _e_action action) const
{
	std::string message_to_process = _construct_padding_message(message);
	std::vector<std::string> source_blocks = _build_message_blocks(message_to_process);
	std::vector<std::bitset<BLOCK_SIZE * CHAR_BIT>> result_blocks;
	result_blocks.reserve(source_blocks.size());

	for (const auto& block : source_blocks)
	{
        auto&& encrypted_block = _encrypt_block(block, action);
		result_blocks.push_back(std::move(encrypted_block));
	}
	
	std::string result_message;
	result_message.reserve(BLOCK_SIZE * result_blocks.size());
	
	for (const auto& block : result_blocks)
	{
		result_message += bit_utils::bitset_to_bytes<BLOCK_SIZE>(block);
	}

	if (action == _e_action::decrypt)
	{
		result_message = _try_remove_padding(result_message);
	}

	return result_message;
}

std::bitset<BLOCK_SIZE * CHAR_BIT> gost_encrypter::_encrypt_block(const std::string& block, _e_action action) const
{
	auto bitset_block = bit_utils::bytes_to_bitset<BLOCK_SIZE>(bit_utils::stob(block));

	auto pair = bit_utils::split_bitset<BLOCK_SIZE>(bitset_block);
	auto a_data = pair[0], b_data = pair[1];

	auto keys = _generated_keys;
	switch (action)
	{
	case gost_encrypter::_e_action::decrypt:
		std::reverse(keys.begin(), keys.end());
		break;
	default:
		break;
	}

	for (uint64_t i = 0; i < ROUNDS_COUNT; ++i)
	{
		auto new_A_data = b_data ^ feistel_function(a_data, keys[i]);

		b_data = a_data;
		a_data = new_A_data;
	}

	auto merged_bitset = bit_utils::merge_bitset<BLOCK_SIZE>(b_data, a_data);

	return merged_bitset;
}

const char* gost_encrypter::invalid_key::what() const throw ()
{
	return "Invalid key! Key should be no less than 32 chars";
}

const char* gost_encrypter::invalid_action::what() const throw ()
{
	return "Invalid action passed! Encrypt logical error";
}
