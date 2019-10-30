#pragma once

#include <bitset>


namespace bit_utils
{
	inline std::vector<uint8_t> int_to_bytes(uint64_t long_value)
	{
		std::vector<uint8_t> bytes_array(32);
		for (uint64_t i = 0; i < 32; i++)
			bytes_array[31 - i] = static_cast<uint8_t>(long_value >> (i * 8));

		return bytes_array;
	}

	inline uint8_t* stob(const std::string& str)
	{
		return reinterpret_cast<uint8_t*>(const_cast<char*>(str.data()));
	}

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
}