#include "gost_encrypter.hpp"
#include <string>

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

namespace _bit_utils
{
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

	auto key = _bit_utils::bytes_to_bitset<KEY_LENGTH>(_bit_utils::stob(_key));
	auto subkeys = _bit_utils::split_bitset<KEY_LENGTH, BLOCK_SIZE>(key);

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
	auto [overflow, mod_2_product] = _bit_utils::add_mod_2<BLOCK_SIZE / 2>(a_data, x_key);
	auto sequences = _bit_utils::split_bitset<BLOCK_SIZE / 2, BLOCK_SIZE>(mod_2_product);
	
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

	auto shifted_result = _bit_utils::shift_bitset_cyclic<HALF_BLOCK_SIZE_BITS>(result_subs, 11);
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
		result_message += _bit_utils::bitset_to_bytes<BLOCK_SIZE>(block);
	}

	if (action == _e_action::decrypt)
	{
		result_message = _try_remove_padding(result_message);
	}

	return result_message;
}

std::bitset<BLOCK_SIZE * CHAR_BIT> gost_encrypter::_encrypt_block(const std::string& block, _e_action action) const
{
	auto bitset_block = _bit_utils::bytes_to_bitset<BLOCK_SIZE>(_bit_utils::stob(block));

	auto pair = _bit_utils::split_bitset<BLOCK_SIZE>(bitset_block);
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

	auto merged_bitset = _bit_utils::merge_bitset<BLOCK_SIZE>(b_data, a_data);

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
