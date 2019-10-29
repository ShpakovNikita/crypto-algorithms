#include "gost_hash.hpp"
#include <string>
#include <cmath>

// TODO: create something like common module with common algorithms
#include "gost_encrypter.hpp"

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

const uint8_t CONSTANT_2 = 0;

const uint8_t CONSTANT_3[32] =
{
	0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
	0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
	0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
	0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
};

const uint8_t CONSTANT_4 = 0;

static std::vector<std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>> KEYGEN_CONSTANTS;

namespace _bit_utils
{
	std::vector<uint8_t> int_to_bytes(uint64_t long_value)
	{
		std::vector<uint8_t> bytes_array(32);
		for (uint64_t i = 0; i < 32; i++)
			bytes_array[31 - i] = static_cast<uint8_t>(long_value >> (i * 8));

		return bytes_array;
	}

	template <uint32_t bytes_count>
	static std::tuple<bool, std::bitset<bytes_count * CHAR_BIT>> add_mod_2(
		const std::bitset<bytes_count* CHAR_BIT>& first,
		const std::bitset<bytes_count* CHAR_BIT>& second)
	{
		uint8_t overflow = 0;
		std::bitset<bytes_count* CHAR_BIT> result;

		for (int64_t i = first.size() - 1; i >= 0; i--) {
			result[i] = (first[i] ^ second[i]) ^ overflow;
			overflow = static_cast<uint8_t>(first[i]) + 
				static_cast<uint8_t>(second[i]) + 
				static_cast<uint8_t>(overflow) >= 2;
		}

		return { overflow, result };
	}

	template <uint32_t bytes_count>
	static std::bitset<bytes_count * CHAR_BIT> bytes_to_bitset(const uint8_t* data)
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

	template <uint32_t bytes_count, uint32_t initial_bitsets_bytes_count>
	static std::bitset<bytes_count * CHAR_BIT> merge_bitsets(
		const std::vector<std::bitset<initial_bitsets_bytes_count * CHAR_BIT>>& bitsets)
	{
		std::bitset<bytes_count * CHAR_BIT> merged_bitset;
		for (uint64_t i = 0; i < bitsets.size(); ++i)
		{
			for (uint64_t j = 0; j < initial_bitsets_bytes_count * CHAR_BIT; ++j)
			{
				merged_bitset[i * initial_bitsets_bytes_count * CHAR_BIT + j] = bitsets[i][j];
			}
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

	static uint8_t* stob(const std::string& str)
	{
		return reinterpret_cast<uint8_t*>(const_cast<char*>(str.data()));
	}
}

gost_hash::gost_hash(const std::string& starting_hash_block)
{
	uint8_t* hash_bytes = _bit_utils::stob(_check_starting_block(starting_hash_block));
	_starting_hash_block = _bit_utils::bytes_to_bitset<HASH_BLOCK_SIZE>(hash_bytes);

	if (KEYGEN_CONSTANTS.empty())
	{
		KEYGEN_CONSTANTS.push_back(CONSTANT_2);
		KEYGEN_CONSTANTS.push_back(_bit_utils::bytes_to_bitset<HASH_BLOCK_SIZE>(CONSTANT_3));
		KEYGEN_CONSTANTS.push_back(CONSTANT_4);
	}
}

std::string gost_hash::generate_hash(const std::string& message) const
{
	return _internal_run(message);
}

std::vector<std::string> gost_hash::_build_message_blocks(const std::string& message)
{
	std::vector<std::string> blocks;
	size_t blocks_count = message.size() / HASH_BLOCK_SIZE;
	blocks.reserve(blocks_count);
	for (uint32_t i = 0; i < blocks_count; ++i)
	{
		blocks.push_back(message.substr(static_cast<size_t>(i) * HASH_BLOCK_SIZE, HASH_BLOCK_SIZE));
	}

	return blocks;
}

std::string gost_hash::_check_starting_block(const std::string& key)
{
	if (key.size() < HASH_BLOCK_SIZE)
	{
		throw invalid_key();
	}

	return key.substr(0, HASH_BLOCK_SIZE);
}

std::string gost_hash::_construct_padding_message(const std::string& message)
{
	uint8_t padding_len = (HASH_BLOCK_SIZE - message.size()) % HASH_BLOCK_SIZE;

	// msvc16 bug?
	uint8_t zero_character = 0;
	return message + std::string(zero_character, padding_len);
}

uint64_t gost_hash::_get_phi_index(uint64_t input_index)
{
	uint64_t x = input_index + 1;
	uint64_t k = static_cast<uint64_t>(ceil(x / 4.0f));
	uint64_t i = x - 4 * k + 3;
	return 8 * i + k - 1;
}

std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> gost_hash::_a_transform(const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& block)
{
	auto y_blocks = _bit_utils::split_bitset<HASH_BLOCK_SIZE, 4>(block);
	auto first_merge = _bit_utils::merge_bitset<HASH_BLOCK_SIZE / 2>(y_blocks[0] ^ y_blocks[1], y_blocks[3]);
	auto second_merge = _bit_utils::merge_bitset<HASH_BLOCK_SIZE / 2>(y_blocks[2], y_blocks[3]);
	auto result_merge = _bit_utils::merge_bitset<HASH_BLOCK_SIZE>(first_merge, second_merge);

	return result_merge;
}

std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> gost_hash::_p_transform(const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& block)
{
	std::vector<std::bitset<CHAR_BIT>> y_blocks = _bit_utils::split_bitset<HASH_BLOCK_SIZE, 32>(block);
	std::vector<std::bitset<CHAR_BIT>> y_blocks_permutated;
	y_blocks_permutated.resize(y_blocks.size());

	for (int64_t i = 31; i >= 0; --i)
	{
		y_blocks_permutated[31 - i] = y_blocks[_get_phi_index(i)];
	}

	auto merged_bitset = _bit_utils::merge_bitsets<HASH_BLOCK_SIZE, 1>(y_blocks_permutated);
	return merged_bitset;
}

std::bitset<HASH_BLOCK_SIZE* CHAR_BIT> gost_hash::_psi_transform(const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& block)
{
	auto y_subkeys = _bit_utils::split_bitset<HASH_BLOCK_SIZE, 16>(block);
	std::vector<std::bitset<CHAR_BIT * 2>> y_blocks_permutated;
	y_blocks_permutated.resize(y_subkeys.size());

	y_blocks_permutated[0] = y_subkeys[0] ^ y_subkeys[1] ^ y_subkeys[2] ^ y_subkeys[3] ^ y_subkeys[12] ^ y_subkeys[15];

	for (int64_t i = 15; i >= 1; --i)
	{
		// we start from 1 index
		y_blocks_permutated[16 - i] = y_subkeys[i];
	}

	auto merged_bitset = _bit_utils::merge_bitsets<HASH_BLOCK_SIZE, 2>(y_blocks_permutated);
	return merged_bitset;
}

std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> gost_hash::_generate_s_block(
	const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& block, const std::vector<std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>>& keys)
{
	auto h_subblocks = _bit_utils::split_bitset<HASH_BLOCK_SIZE, 4>(block);
	std::vector<std::bitset<HASH_BLOCK_SIZE * 2>> s_subblocks;
	s_subblocks.reserve(4);

	for (uint64_t i = 0; i < 4; ++i)
	{
		std::string gost_key = _bit_utils::bitset_to_bytes<HASH_BLOCK_SIZE>(keys[i]);
		gost_encrypter encrypter(gost_key);

		std::string h_message = _bit_utils::bitset_to_bytes<HASH_BLOCK_SIZE / 4>(h_subblocks[i]);
		std::string s_subblock = encrypter.encrypt(h_message);
		s_subblocks.push_back(_bit_utils::bytes_to_bitset<HASH_BLOCK_SIZE / 4>(_bit_utils::stob(s_subblock)));
	}

	auto merged_bitset = _bit_utils::merge_bitsets<HASH_BLOCK_SIZE, HASH_BLOCK_SIZE / 4>(s_subblocks);
	return merged_bitset;
}

std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> gost_hash::_permutate_hash_step(
	const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& m_block, 
	const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& h_block, 
	const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& s_block)
{
	std::bitset<HASH_BLOCK_SIZE* CHAR_BIT> first_step = s_block;

	for (uint64_t i = 0; i < 12; ++i)
	{
		first_step = _psi_transform(first_step);
	}

	std::bitset<HASH_BLOCK_SIZE* CHAR_BIT> second_step = first_step ^ m_block;
	second_step = _psi_transform(second_step);

	std::bitset<HASH_BLOCK_SIZE* CHAR_BIT> third_step = h_block ^ second_step;

	for (uint64_t i = 0; i < 61; ++i)
	{
		third_step = _psi_transform(third_step);
	}

	return third_step;
}

std::vector<std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>> gost_hash::_generate_keys(
	const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& h_block, const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& m_block)
{
	auto u_block = h_block, v_block = m_block;
	auto W_block = u_block ^ v_block;

	std::vector<std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>> generated_keys;
	generated_keys.reserve(4);
	generated_keys.push_back(_p_transform(W_block));

	for (uint64_t i = 0; i < 3; ++i)
	{
		u_block = _a_transform(u_block) ^ KEYGEN_CONSTANTS[i];
		v_block = _a_transform(_a_transform(v_block));
		W_block = u_block ^ W_block;
		generated_keys.push_back(_p_transform(W_block));
	}

	return generated_keys;
}

std::string gost_hash::_internal_run(const std::string& message) const
{
	uint64_t message_len = message.size() * CHAR_BIT;

	std::string message_to_process = _construct_padding_message(message);
	std::vector<std::string> source_blocks = _build_message_blocks(message_to_process);
	std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> result_block = _starting_hash_block;
	std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> control_sum = 0;

	for (const auto& block : source_blocks)
	{
		auto block_bitset = _bit_utils::bytes_to_bitset<HASH_BLOCK_SIZE>(_bit_utils::stob(block));
		result_block = _hash_block(result_block, block_bitset);
		std::tie(std::ignore, control_sum) = _bit_utils::add_mod_2<HASH_BLOCK_SIZE>(control_sum, block_bitset);

		std::string def1 = _bit_utils::bitset_to_bytes<HASH_BLOCK_SIZE>(result_block);
		std::string def2 = _bit_utils::bitset_to_bytes<HASH_BLOCK_SIZE>(control_sum);
	}

	std::string def1 = _bit_utils::bitset_to_bytes<HASH_BLOCK_SIZE>(result_block);
	std::string def2 = _bit_utils::bitset_to_bytes<HASH_BLOCK_SIZE>(control_sum);

	auto len_bitset = _bit_utils::bytes_to_bitset<HASH_BLOCK_SIZE>(_bit_utils::int_to_bytes(message_len).data());

	result_block = _hash_block(result_block, len_bitset);
	result_block = _hash_block(result_block, control_sum);
	
	std::string result_message = _bit_utils::bitset_to_bytes<HASH_BLOCK_SIZE>(result_block);

	return result_message;
}

std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> gost_hash::_hash_block(const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& h_block, 
	const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& message_block) const
{
	auto keys = _generate_keys(h_block, message_block);
	auto s_block = _generate_s_block(h_block, keys);
	auto permutate_block = _permutate_hash_step(message_block, h_block, s_block);
	return permutate_block;
}

const char* gost_hash::invalid_key::what() const throw ()
{
	return "Invalid start hash! Hash should be no less than 32 chars";
}
