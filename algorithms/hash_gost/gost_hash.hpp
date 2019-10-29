#pragma once

#include <string>
#include <vector>
#include <bitset>

constexpr uint32_t HASH_BLOCK_SIZE = 32;

class gost_hash
{
public:
	struct invalid_key : public std::exception
	{
		const char* what() const throw ();
	};

	gost_hash(const std::string& starting_hash_block);
	~gost_hash() = default;

	std::string generate_hash(const std::string& message) const;

private:
	static std::vector<std::string> _build_message_blocks(const std::string& message);
	static std::string _try_remove_padding(const std::string& message);
	static std::string _check_starting_block(const std::string& key);
	static std::string _construct_padding_message(const std::string& message);

	static uint64_t _get_phi_index(uint64_t x);
	static std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> _a_transform(const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& block);
	static std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> _p_transform(const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& block);
	static std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> _psi_transform(const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& block);

	static std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> _generate_s_block(const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& block, 
		const std::vector<std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>>& keys);	
	static std::bitset<HASH_BLOCK_SIZE* CHAR_BIT> _permutate_hash_step(const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& m_block,
		const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& h_block, const std::bitset<HASH_BLOCK_SIZE* CHAR_BIT>& s_block);

	static std::vector<std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>> _generate_keys(
		const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& h_block, const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& m_block);

	std::bitset<HASH_BLOCK_SIZE * CHAR_BIT> _hash_block(const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& h_block, 
		const std::bitset<HASH_BLOCK_SIZE * CHAR_BIT>& message_block) const;
	std::string _internal_run(const std::string& message) const;

	std::bitset<HASH_BLOCK_SIZE* CHAR_BIT> _starting_hash_block;
};
