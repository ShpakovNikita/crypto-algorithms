#include "des_encrypter.hpp"
#include <string>

constexpr uint32_t ROUNDS_COUNT = 16;
constexpr uint32_t KEY_LENGTH = 8;

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

const std::vector<std::vector<uint8_t>> S_BOX_1 =
{
	{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
	{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
	{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
	{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
};

const std::vector<std::vector<uint8_t>> S_BOX_2 =
{
	{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
	{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
	{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
	{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
};

const std::vector<std::vector<uint8_t>> S_BOX_3 =
{
	{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
	{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
	{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
	{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
};

const std::vector<std::vector<uint8_t>> S_BOX_4 =
{
	{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
	{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
	{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
	{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
};

const std::vector<std::vector<uint8_t>> S_BOX_5 =
{
	{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
	{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
	{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
	{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
};

const std::vector<std::vector<uint8_t>> S_BOX_6 =
{
	{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
	{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
	{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
	{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
};

const std::vector<std::vector<uint8_t>> S_BOX_7 =
{
	{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
	{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
	{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
	{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
};

const std::vector<std::vector<uint8_t>> S_BOX_8 =
{
	{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
	{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
	{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
	{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
};

const std::vector<std::vector<std::vector<uint8_t>>> S_BOX =
{
	S_BOX_1, S_BOX_2, S_BOX_3, S_BOX_4, S_BOX_5, S_BOX_6, S_BOX_7, S_BOX_8,
};


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
	static std::bitset<bytes_count * CHAR_BIT> bytes_to_bitset(uint8_t* data)
	{
		std::bitset<bytes_count * CHAR_BIT> bitset;

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
	static std::string bitset_to_bytes(const std::bitset<bytes_count * CHAR_BIT>& data)
	{
		std::string bytes;

		for (uint64_t i = 0; i < bytes_count; ++i)
		{
			uint8_t current_byte = 0x0;
			uint64_t offset = i * CHAR_BIT;

			for (uint64_t bit = 0; bit < CHAR_BIT; ++bit)
			{
                // default bitset conversion inversed, because of that we have to flip values
				uint8_t selected_bit = (data[offset + bit] & 1) << (CHAR_BIT - bit - 1);
				current_byte |= selected_bit;
			}
            
            bytes += current_byte;
		}
        
		return bytes;
	}

	template <uint32_t bytes_count, uint32_t slices_count = 2>
	static std::vector<std::bitset<bytes_count * CHAR_BIT / slices_count>> split_bitset(
			const std::bitset<bytes_count * CHAR_BIT>& data)
	{
		constexpr uint64_t split_size = bytes_count * CHAR_BIT / slices_count;
		std::vector<std::bitset<split_size>> slices;
        slices.resize(slices_count);

		for (uint64_t i = 0; i < split_size; ++i)
		{
            for (uint64_t j = 0; j < slices_count; ++j)
            {
                slices[j][i] = data[j * split_size + i];
            }
		}

		return slices;
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

std::string des_encrypter::encrypt(const std::string& message) const
{
	return _internal_run(message, _e_action::encrypt);
}

std::string des_encrypter::decrypt(const std::string& message) const
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

std::string des_encrypter::_try_remove_padding(const std::string& message)
{
	uint8_t padding_size = message[message.size() - 1];
	if (padding_size < static_cast<uint8_t>(BLOCK_SIZE))
	{
		return message.substr(0, message.size() - padding_size);
	}

	return message;
}

std::string des_encrypter::_check_key(const std::string& key)
{
	if (key.size() < KEY_LENGTH)
	{
		throw invalid_key();
	}

	return key.substr(0, KEY_LENGTH);
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
	auto pair = _bit_utils::split_bitset<(BLOCK_SIZE - 1)>(permutated_key);
	auto left = pair[0], right = pair[1];

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

std::string des_encrypter::_internal_run(const std::string& message, _e_action action) const
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
		result_message += _bit_utils::bitset_to_bytes<BLOCK_SIZE>(block);
	}

	if (action == _e_action::decrypt)
	{
		result_message = _try_remove_padding(result_message);
	}

	return result_message;
}

std::bitset<BLOCK_SIZE* CHAR_BIT> des_encrypter::_encrypt_block(const std::string& block, _e_action action) const
{
	auto bitset_block = _bit_utils::bytes_to_bitset<BLOCK_SIZE>(_bit_utils::stob(block));
	auto permutated_block = _bit_utils::perform_permutations<BLOCK_SIZE, BLOCK_SIZE>(bitset_block, PI);
    
	auto pair = _bit_utils::split_bitset<BLOCK_SIZE>(permutated_block);
	auto left = pair[0], right = pair[1];

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
        auto new_right_subs = _substitude_block(new_right_xor);
		auto new_right_permutated =
			_bit_utils::perform_permutations<BLOCK_SIZE / 2, BLOCK_SIZE / 2>(new_right_subs, P);
		auto result_new_right = left ^ new_right_permutated;


		left = right;
		right = result_new_right;
	}

	auto merged_bitset = _bit_utils::merge_bitset<BLOCK_SIZE>(right, left);
	auto result_block = _bit_utils::perform_permutations<BLOCK_SIZE, BLOCK_SIZE>(merged_bitset, PI_1);

	return result_block;
}

std::bitset<BLOCK_SIZE * CHAR_BIT / 2> des_encrypter::_substitude_block(const std::bitset<(BLOCK_SIZE - 2) * CHAR_BIT>& block)
{
    std::bitset<BLOCK_SIZE * CHAR_BIT / 2> result_subs;
    auto subblocks = _bit_utils::split_bitset<(BLOCK_SIZE - 2), BLOCK_SIZE>(block);
    for (uint64_t i = 0; i < CHAR_BIT; ++i)
    {
        auto &subblock = subblocks[i];
        uint32_t row = 0b10 * subblock[0] + 0b01 * subblock[5];
        uint32_t col = 0b1000 * subblock[1] + 0b0100 * subblock[2] + 0b0010 * subblock[3] + 0b0001 * subblock[4];
        auto val = std::bitset<BLOCK_SIZE / 2>(S_BOX[i][row][col]);
        for (uint64_t j = 0; j < BLOCK_SIZE / 2; ++j)
        {
            // default bitset conversion inversed, because of that we have to flip values
            result_subs[i * BLOCK_SIZE / 2 + j] = val[BLOCK_SIZE / 2 - j - 1];
        }
    }
    
	return result_subs;
}

const char* des_encrypter::invalid_key::what() const throw ()
{
	return "Invalid key! Key should be no less than 8 chars";
}

const char* des_encrypter::invalid_action::what() const throw ()
{
	return "Invalid action passed! Encrypt logical error";
}
