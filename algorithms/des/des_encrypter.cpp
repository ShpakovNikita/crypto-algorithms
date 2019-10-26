#include "des_encrypter.hpp"
#include <string>

constexpr uint32_t ROUNDS_COUNT = 16;

// initial permutations matrix for the data
const std::vector<uint8_t> PI = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
};

// initial permutations made on the key
const std::vector<uint8_t> CP_1 = 
{ 
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
};

// permutations applied on shifted key to get Ki + 1
const std::vector<uint8_t> CP_2 =
{
	14, 17, 11, 24, 1, 5, 3, 28,
	15, 6, 21, 10, 23, 19, 12, 4,
	26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56,
	34, 53, 46, 42, 50, 36, 29, 32,
};

// expand matrix to get a 48bits matrix of data to apply the xor with Ki
const std::vector<uint8_t> E =
{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
};

// final permutations for data after the 16 rounds
const std::vector<uint8_t> PI_1 = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
};

// permutations made after each SBox substitution for each round
const std::vector<uint8_t> P =
{
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25,
};

// matrix that determine the shift for each round of keys
const std::vector<uint8_t> SHIFT = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

namespace _bit_utils
{
	template <uint32_t initial_bytes_count, uint32_t output_bytes_count>
	static std::bitset<output_bytes_count* CHAR_BIT> perform_permutations(
		const std::bitset<initial_bytes_count* CHAR_BIT>& data, const std::vector<uint8_t>& table)
	{
		std::bitset<output_bytes_count* CHAR_BIT> permutated_bits;

		for (uint64_t i = 0; i < permutated_bits.size(); ++i)
		{
			permutated_bits[i] = data[table[i] - 1];
		}

		return permutated_bits;
	}

	template <uint32_t bytes_count>
	static std::bitset<bytes_count* CHAR_BIT> bytes_to_bitset(uint8_t* data)
	{
		std::bitset<bytes_count* CHAR_BIT> bitset;

		for (uint64_t i = 0; i < bytes_count; ++i)
		{
			uint8_t current_byte = data[i];
			uint64_t offset = i * CHAR_BIT;

			for (uint64_t bit = 0; bit < CHAR_BIT; ++bit)
			{
				uint64_t byte_offset = CHAR_BIT - bit - 1;
				bitset[offset + byte_offset] = current_byte & 1;
				current_byte >>= 1;
			}
		}

		return bitset;
	}

	template <uint32_t bytes_count>
	static std::string_view bitset_to_bytes(const std::bitset<bytes_count* CHAR_BIT>& data)
	{
		std::string_view bytes;

		for (uint64_t i = 0; i < bytes_count; ++i)
		{
			uint8_t current_byte = 0x0;
			uint64_t offset = i * CHAR_BIT;

			for (uint64_t bit = 0; bit < CHAR_BIT; ++bit)
			{
				uint8_t selected_bit = (data[offset] & 1) >> bit;
				++offset;
				current_byte |= selected_bit;
			}

			bytes += current_byte;
		}

		return bitset;
	}

	template <uint32_t bytes_count>
	static std::tuple<std::bitset<bytes_count * CHAR_BIT / 2>, 
		std::bitset<bytes_count* CHAR_BIT / 2>> split_bitset(
			const std::bitset<bytes_count * CHAR_BIT>& data)
	{
		constexpr uint64_t split_size = bytes_count * CHAR_BIT / 2;
		std::bitset<split_size> left, right;
		for (uint64_t i = 0; i < split_size; ++i)
		{
			left[i] = data[i];
			right[i] = data[i + split_size];
		}

		return std::make_tuple(left, right);
	}

	template <uint32_t bytes_count>
	static std::bitset<bytes_count * CHAR_BIT> merge_bitset(
		const std::bitset<bytes_count * CHAR_BIT / 2>& left,
		const std::bitset<bytes_count * CHAR_BIT / 2>& right)
	{
		constexpr uint64_t split_size = bytes_count * CHAR_BIT / 2;
		std::bitset<bytes_count * CHAR_BIT> merged_bitset;
		for (uint64_t i = 0; i < split_size; ++i)
		{
			merged_bitset[i] = left[i];
			merged_bitset[i + split_size] = right[i];
		}

		return merged_bitset;
	}

	template <uint32_t bits_count>
	static std::bitset<bits_count> shift_bitset_cyclic(const std::bitset<bits_count>& data, uint8_t offset)
	{
		std::bitset<bits_count> output_data(data);
		for (uint64_t i = 0; i < bits_count - offset; ++i)
		{
			output_data[i] = data[i + offset];
		}

		uint64_t start_pos = bits_count - offset;
		for (uint64_t i = 0; i < offset; ++i)
		{
			output_data[start_pos + i] = data[i];
		}

		return output_data;
	}

	uint8_t* stob(const std::string& str)
	{
		return reinterpret_cast<uint8_t*>(const_cast<char*>(str.data()));
	}
}


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
	uint8_t padding_len = (BLOCK_SIZE - message.size()) % BLOCK_SIZE;
	return message + std::string(padding_len, padding_len);
}

void des_encrypter::_generate_keys()
{
	_generated_keys.reserve(ROUNDS_COUNT);

	auto key = _bit_utils::bytes_to_bitset<BLOCK_SIZE>(_bit_utils::stob(_key));
	auto permutated_key = _bit_utils::perform_permutations<BLOCK_SIZE, (BLOCK_SIZE - 1)>(key, CP_1);
	auto [left, right] = _bit_utils::split_bitset<(BLOCK_SIZE - 1)>(permutated_key);

	for (uint64_t i = 0; i < ROUNDS_COUNT; ++i)
	{
		left = _bit_utils::shift_bitset_cyclic<(BLOCK_SIZE - 1) * CHAR_BIT / 2>(left, SHIFT[i]);
		right = _bit_utils::shift_bitset_cyclic<(BLOCK_SIZE - 1) * CHAR_BIT / 2>(right, SHIFT[i]);

		auto merged_bitset = _bit_utils::merge_bitset<(BLOCK_SIZE - 1)>(left, right);
		auto generated_key_bitset = _bit_utils::perform_permutations<(BLOCK_SIZE - 1), (BLOCK_SIZE - 2)>(
			merged_bitset, CP_2);
		_generated_keys.push_back(std::move(generated_key_bitset));
	}
}

std::string des_encrypter::_internal_run(const std::string& message, _e_action action)
{
	std::string message_to_process = _construct_padding_message(message);
	std::vector<std::string> source_blocks = _build_message_blocks(message_to_process);
	std::vector<std::bitset<BLOCK_SIZE * CHAR_BIT>> result_blocks;
	result_blocks.reserve(source_blocks.size());

	for (const auto& block : source_blocks)
	{
		result_blocks.push_back(std::move(_encrypt_block(block, action)));
	}
	
	std::string result_message;
	result_message.reserve(BLOCK_SIZE * result_blocks.size());
	
	for (const auto& block : result_blocks)
	{
		result_message += block.to_string();
	}

	return result_message;
}

std::bitset<BLOCK_SIZE* CHAR_BIT> des_encrypter::_encrypt_block(const std::string& block, _e_action action)
{
	auto bitset_block = _bit_utils::bytes_to_bitset<BLOCK_SIZE>(_bit_utils::stob(block));
	auto permutated_block = _bit_utils::perform_permutations<BLOCK_SIZE, BLOCK_SIZE>(bitset_block, PI);

	auto& [left, right] = _bit_utils::split_bitset<BLOCK_SIZE>(permutated_block);

	for (uint64_t i = 0; i < ROUNDS_COUNT; ++i)
	{
		auto right_e = _bit_utils::perform_permutations<BLOCK_SIZE / 2, (BLOCK_SIZE - 2)>(right, E);

		uint64_t key_index = 0;
		switch (action)
		{
		case des_encrypter::_e_action::encrypt:
			key_index = i;
			break;
		case des_encrypter::_e_action::decrypt:
			key_index = ROUNDS_COUNT - i - 1;
			break;
		default:
			throw invalid_action();
			break;
		}

		auto new_right_xor = _generated_keys[key_index] ^ right_e;
		// auto new_right_subs = substitude
		auto new_right_permutated =
			_bit_utils::perform_permutations<(BLOCK_SIZE - 2), BLOCK_SIZE / 2>(new_right_xor /*subs*/, P);
		auto result_new_right = left ^ new_right_permutated;


		left = right;
		right = result_new_right;
	}

	auto merged_bitset = _bit_utils::merge_bitset<BLOCK_SIZE>(right, left);
	auto result_block = _bit_utils::perform_permutations<BLOCK_SIZE, BLOCK_SIZE>(bitset_block, PI_1);

	return result_block;
}

const char* des_encrypter::invalid_key::what() const throw ()
{
	return "Invalid key! Key should be no less than 8 chars";
}

const char* des_encrypter::invalid_action::what() const throw ()
{
	return "Invalid action passed! Encrypt logical error";
}
