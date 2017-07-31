#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <uuid/uuid.h>
#include <linux/fs.h>

#include "mkmint.h"

static const char mjsb_magic[16] = {0x6c, 0x69, 0x6c, 0x79, 0x6d, 0x75, 0x66,
	0x66, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** @brief Print progress bar
 *
 * @param i Current index
 * @param n Total number of things
 * @param r How many times to update
 * @param w Total width of progress bar
 */
static inline uint8_t progress(uint64_t i, uint64_t n, uint8_t w, uint8_t old){
	if (i != n && (i * 100 / n) <= old) {
		return old;
	}
	// if ((n/r) != 0 && i % (n/r) != 0 && i != n){ return; }
	char line[w + 1];
	sprintf(line, " %3ju%% [", i != n ? i * 100 / n : 100);
	uint8_t points = i != n ? 7 + (w - 9) * i / n : 7 + w - 9;
	for (uint8_t i = 7; i < points; i++) {
		line[i] = '=';
	}
	for (uint8_t i = points; i < w - 2; i++) {
		line[i] = ' ';
	}
	line[w - 2] = ']';
	line[w - 1] = '\r';
	line[w] = 0;
	fprintf(stderr, "%s", line);
	return i * 100 / n;
}

/** @brief Convert an array of bytes to a hex strings
 *
 * Caller's responsibility to check that out is long enough
 *
 * @param bytes Bytes to convert
 * @param len Number of bytes
 * @param out[out] Null terminated hex string of bytes
 */
void bytes_to_hex(const char *bytes, size_t len, char *out){
	for (size_t i = 0; i < len; i++) {
		out += sprintf(out, "%02x", (uint8_t)bytes[i]);
	}
	*(out + 1) = 0;
}

/*! @brief Convert an ascii string of hex bytes to bytes
 *
 * Out should be of length len/2
 *
 * @param hex Hex string to convert
 * @param len Length of hex string
 * @param out[out] Output bytes
 *
 * @return 0 no error, -1 error in parsing
 */
int hex_to_bytes(const char *hex, size_t len, char *out){
	for (size_t i = 0; i < len / 2; i++){ 
		if (sscanf(hex + 2 * i, "%02x", (unsigned int*)&out[i]) != 1) {
			return -1;
		}
	}
	return 0;
}

/** @brief Print out the superblock struct to stdout
 *
 * @param sb Superblock
 */
void print_superblock(struct mint_superblock *sb){
	char *buf = (char*)(malloc(4096));
	const EVP_MD *md;
	md = EVP_get_digestbyname(sb->hash_algorithm);
	uint32_t hash_bytes = EVP_MD_size(md);
	printf("[ dm-mintegrity superblock ]\n");
	printf("Magic: %#0x\n", sb->magic);
	printf("Version: %u\n", sb->version);
	bytes_to_hex(sb->uuid, 16, buf);
	printf("UUID: %s\n", buf);
	printf("Hash_Type: %s\n", sb->hash_algorithm);
	printf("Hmac_Type: %s\n", sb->hmac_algorithm);
	printf("Block_Size: %u\n", sb->block_size);
	printf("Data_Blocks: %ju\n", sb->data_blocks);
	printf("Hash_Blocks: %u\n", sb->hash_blocks);
	printf("JB_Blocks: %u\n", sb->jb_blocks);
	printf("Salt_Size: %u\n", sb->salt_size);
	bytes_to_hex(sb->salt, sb->salt_size, buf);
	printf("Salt: %s\n", buf);
	bytes_to_hex(sb->root, hash_bytes, buf);
	printf("Root_Hash: %s\n", buf);
	free(buf);
}

/** @brief Compute the number of hash blocks needed
 *
 * Does not include empty branches in computation
 *
 * @param data_blocks Number of data blocks
 * @param fanout Tree fanout
 * @param levels[out] Number of tree levels (not including data level)
 * @param hash_blocks[out] Number of necessary hash blocks
 *
 * @return Non zero value means error, else 0
 */
int compute_hash_blocks(uint64_t data_blocks, uint32_t fanout,
	uint32_t *levels, uint32_t *hash_blocks, uint32_t *blocks_per_level){
	*levels = 0;
	*hash_blocks = 0;
	uint32_t i = divide_up(data_blocks, fanout);
	while (i != 1) {
		blocks_per_level[*levels] = i;
		*hash_blocks += i;
		*levels += 1;
		i = divide_up(i, fanout);
	}
	// Top level
	blocks_per_level[*levels] = 1;
	*levels += 1;
	*hash_blocks += 1;
	if (i == 0) {
		return -1;
	} else {
		return 0;
	}
}

/** @brief Compute the optimal number of data blocks to fill disk
 *
 * @param blocks Total number of blocks to work with
 * @param fanout Number of hashes that fit in a hash block
 * @param data_blocks[out] Number of data blocks writeable
 * @param hash_blocks[out] Number of blocks needed for hashes
 * @param jb_blocks[out] Number of blocks needed for journal
 * @param pad_blocks[out] Number of blocks wasted
 * @param levels[out] Number of hash block levels (not including data level)
 *
 * @return 0 if ok else error
 */
int compute_block_numbers(uint64_t blocks, uint32_t block_size, uint32_t fanout,
	uint32_t journal_blocks, uint64_t *data_blocks, uint32_t *hash_blocks,
	uint32_t *jb_blocks, uint32_t *pad_blocks, uint32_t *levels,
	uint32_t *blocks_per_level, uint32_t hash_bytes){

	if (blocks < 6) {
		exit_error_f("Not enough space! Need at least 6 blocks!");
		return -1;
	}
	// Remove one for superblocks
	blocks = blocks - 1;
	*pad_blocks = blocks;

	uint64_t low = 0;
	uint64_t high = blocks;
	uint32_t *bpl = (uint32_t*)malloc(sizeof(uint32_t) * DM_MINTEGRITY_MAX_LEVELS);


	while (high >= low && high != 0) {
		uint64_t mid = low + divide_up((high - low), 2);  // Non overflow method
		uint64_t db = mid, used = 0;
		uint32_t hb = 0, jb = 0, pb = 0;
		uint32_t lev;
		// Number of hash blocks, levels needed for this many data blocks
		if (compute_hash_blocks(db, fanout, &lev, &hb, bpl) != 0) {
			break; // Barf
		}

		// Number of jb blocks needed
		jb = journal_blocks;
		used = db + jb + hb;
		pb = blocks - used;

		// Result is better
		if (used <= blocks && pb < *pad_blocks) {
			*data_blocks = db;
			*hash_blocks = hb;
			*jb_blocks = jb;
			*pad_blocks = pb;
			*levels = lev;
			for (int i = 0; i < *levels; i++) {
				blocks_per_level[i] = bpl[i];
			}
		}

		if (used > blocks) { // Too many - go down
			high = mid - 1;
		} else if (used < blocks) { // Not enough - go up
			low = mid + 1;
		} else { // Optimal! Wow!
			break;
		}
	}
	free(bpl);
	// Failed at first try
	if (*pad_blocks == blocks) {
		return -1;
	} else {
		return 0;
	}
}

/** @brief Compute the hash of some input with a salt
 *
 * Salt length can be 0. Updates are: update(salt), update(input), update(salt)
 *
 * @param md Message digest algorithm
 * @param mdctx Message digest context
 * @param input Input bytes
 * @param i Number of input bytes
 * @param salt Salt bytes
 * @param s Number of salt bytes
 * @param out[out] Binary digest output
 * @param hash_length[out] Size of digest in bytes
 */
void hash(const EVP_MD *md, EVP_MD_CTX *mdctx, const char *input, size_t i,
	const char *salt, size_t s, char *out, uint32_t *hash_length){
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, salt, s);
	EVP_DigestUpdate(mdctx, input, i);
	EVP_DigestFinal_ex(mdctx, (unsigned char*)out, hash_length);
}

int main(int argc, char const *argv[]) {
	// Check for arguments
	if (argc != 11) {
		exit_error_f("Usage:\n%s MINT_DEV DATA_DEV BLOCK_SIZE JOURNAL_BLOCKS HASH_TYPE SALT HMAC_TYPE SECRET lazy|nolazy full|sector\n", argv[0]);
	}
	const char *dev, *dev2, *hash_type, *hmac_type, *salt_str, *secret_str;
	uint32_t block_size, journal_blocks;
	bool zero;
	bool full_journal;
	bool two_disks;

	if (!strcmp(argv[9], "lazy")) {
		zero = false;
	} else if (!strcmp(argv[9], "nolazy")) {
		zero = true;
	} else {
		exit_error_f("Unsupported lazy|nolazy argument: %s", argv[9]);
	}

	if (!strcmp(argv[10], "full")) {
		full_journal = true;
	} else if (!strcmp(argv[10], "sector")) {
		full_journal = false;
	} else {
		exit_error_f("Unsupported full|sector argument: %s", argv[argc - 1]);
	}

	dev = argv[1];
	dev2 = argv[2];
	two_disks = strcmp(argv[1], argv[2]) ? 1 : 0;
	hash_type = argv[5];
	salt_str = argv[6];
	hmac_type = argv[7];
	secret_str = argv[8];

	// Open destination device
	int file, file2;
	if ((file = open(dev, O_RDWR)) < 0) {
		exit_error_f("Could not open: '%s' for writing, %s", dev, strerror(errno));
	}

	// Get size
	// TODO: size of file in 512 chunks?
	struct stat file_stats, file_stats2;
	if (fstat(file, &file_stats) != 0) {
		exit_error_f("Could not get file stats for: '%s', %s", dev, strerror(errno));
	}

	if (!(S_ISREG(file_stats.st_mode) || S_ISBLK(file_stats.st_mode))) {
		exit_error_f("File is neither a regular file nor block device");
	}

	if (two_disks) {
		if ((file2 = open(dev2, O_RDWR)) < 0) {
			exit_error_f("Could not open: '%s' for writing, %s", dev2, strerror(errno));
		}

		// Get size
		// TODO: size of file in 512 chunks?
		if (fstat(file2, &file_stats2) != 0) {
			exit_error_f("Could not get file stats for: '%s', %s", dev2, strerror(errno));
		}

		if (!(S_ISREG(file_stats2.st_mode) || S_ISBLK(file_stats2.st_mode))) {
			exit_error_f("File is neither a regular file nor block device");
		}
	}

	// Get block size
	if (sscanf(argv[3], "%u", &block_size) != 1) {
		exit_error_f("Invalid block size: '%s'", argv[3]);
	}
	if (block_size < 512) {
		exit_error_f("Invalid block size: '%u' < 512", block_size);
	}

	// Remainder check
	if (S_ISREG(file_stats.st_mode) && file_stats.st_size % block_size != 0) {
		warn("File is not a multiple of block_size: %d. %ju bytes left over",
			block_size, file_stats.st_size % block_size);
	}
	if (two_disks && S_ISREG(file_stats2.st_mode)
			&& file_stats2.st_size % block_size != 0) {
		warn("File is not a multiple of block_size: %d. %ju bytes left over",
			block_size, file_stats.st_size % block_size);
	}

	// Number of journal blocks
	if (sscanf(argv[3 + two_disks], "%u", &journal_blocks) != 1) {
		exit_error_f("Invalid journal blocks number: '%s'", argv[3 + two_disks]);
	}

	OpenSSL_add_all_digests();

	// Block hash algorithm
	EVP_MD_CTX *mdctx_hash = EVP_MD_CTX_create();
	const EVP_MD *md_hash;
	md_hash = EVP_get_digestbyname(hash_type);
	if (!md_hash) {
		exit_error_f("Unsupported hash type: %s", hash_type);
	}
	uint32_t hash_bytes = EVP_MD_size(md_hash);

	// Hmac algorithm
	const EVP_MD *md_hmac;
	md_hmac = EVP_get_digestbyname(hmac_type);
	if (!md_hmac) {
		exit_error_f("Unsupported hmac type: %s", hmac_type);
	}

	// Parse and check salt
	char salt[128];
	if (strlen(salt_str) % 2 != 0) {
		exit_error_f("Invalid hex salt: length not a multiple of 2");
	}
	if (strlen(salt_str) > 256) {
		exit_error_f("Salt is too long. %lu > %d", strlen(salt_str), 256);
	}
	if (hex_to_bytes(salt_str, strlen(salt_str), (char*)salt) != 0) {
		exit_error_f("Invalid hex salt: '%s'", salt_str);
	}

	// Parse and check secrets
	char secret[hash_bytes];
	if (strlen(secret_str) % 2 != 0) {
		exit_error_f("Invalid hex secret: length not a multiple of 2");
	}
	if (hex_to_bytes(secret_str, strlen(secret_str), (char*)secret) != 0) {
		exit_error_f("Invalid hex inner pad: '%s'", secret_str);
	}

	// Calculate data size, hash block size, journal size
	// TODO: uh...this is 64 bits...
	uint64_t data_blocks = 0;
	uint32_t hash_blocks = 0;
	uint32_t jb_blocks = 0;
	uint32_t pad_blocks = 0;
	uint32_t *blocks_per_level = malloc(sizeof(uint32_t) * DM_MINTEGRITY_MAX_LEVELS);
	uint32_t levels = 0;
	uint64_t blocks, blocks2;

	if (S_ISREG(file_stats.st_mode)) {
		blocks = file_stats.st_size / block_size;
	} else if (S_ISBLK(file_stats.st_mode)) {
		if(ioctl(file, BLKGETSIZE64, &blocks) != 0){
			exit_error_f("ioctl for block size failed: %s", strerror(errno));
		}
		blocks = blocks / block_size;
	}

	if (two_disks) {
		if (S_ISREG(file_stats2.st_mode)) {
			blocks2 = file_stats2.st_size / block_size;
		} else if (S_ISBLK(file_stats2.st_mode)) {
			if(ioctl(file2, BLKGETSIZE64, &blocks2) != 0){
				exit_error_f("ioctl for block size failed: %s", strerror(errno));
			}
			blocks2 = blocks2 / block_size;
		}
	}

	// Fanout
	uint8_t fls, pls = 0;
	uint32_t fanout = block_size / hash_bytes;
	while (fanout > 0) {
		if ((fanout & 1) == 1) {
			fls = pls;
		}
		pls ++;
		fanout = fanout >> 1;
	}
	fanout = 1 << fls;

	// Use up entire block device
	if (!two_disks) {
		compute_block_numbers(blocks, block_size, fanout, journal_blocks, &data_blocks,
			&hash_blocks, &jb_blocks, &pad_blocks, &levels, blocks_per_level, hash_bytes);
	} else {
		jb_blocks = journal_blocks;
		data_blocks = blocks2;
		compute_hash_blocks(blocks2, fanout, &levels, &hash_blocks, blocks_per_level);
		if (hash_blocks + journal_blocks > blocks2) {
			exit_error_f("Need: %u hash + journal blocks, but %s only has %ju",
				hash_blocks + journal_blocks, dev, blocks);
		}
	}
	
	// Result info
	info("Blocks: %ju = Superblock: 1, Data: %ju, Hash: %u, JB: %u, Pad: %u, Levels: %u",
			blocks, data_blocks, hash_blocks, jb_blocks, pad_blocks, levels);

	// Calculate each hash block level
	char **hash_levels = (char**)malloc(sizeof(char*) * levels);
	char hash_output[EVP_MAX_MD_SIZE];
	uint32_t hash_length;
	char *zero_block = (char*)malloc(block_size);
	char *temp_block = (char*)malloc(block_size);
	bzero(zero_block, block_size);

	char buf[128];

	// Data hash
	hash(md_hash, mdctx_hash, zero_block, block_size, salt,
		strlen(salt_str) / 2, hash_output, &hash_length);

	// Now loop through each level
	for (uint32_t i = 0; i < levels; i++) {
		hash_levels[i] = (char*)malloc(block_size);
		// Fill block with hashes - padding is zeros
		bzero(hash_levels[i], block_size);
		for (uint32_t f = 0; f < fanout; f++) {
			for (int b = 0; b < hash_bytes; b++) {
				hash_levels[i][f * (block_size / (1 << fls)) + b] = hash_output[b];
			}
		}
		// Compute hash of this level for next iteration/root
		hash(md_hash, mdctx_hash, hash_levels[i], block_size, salt,
			strlen(salt_str) / 2, hash_output, &hash_length);
	}

	// Write out hash superblock
	struct mint_superblock *msb = malloc(sizeof(struct mint_superblock));
	// Zero out everything
	bzero(msb, sizeof(struct mint_superblock));
	// Magic
	msb->magic = 0x796c694c;
	// Version
	msb->version = 1;
	// Make a new uuid!
	uuid_t uuid;
	uuid_generate(uuid);
	// TODO: is there a better way of doing this?
	memcpy(&msb->uuid, &uuid, 16);
	// Copy hash algorithm name
	strcpy(msb->hash_algorithm, hash_type);
	// Copy hmac algorithm name
	strcpy(msb->hmac_algorithm, hmac_type);
	// Block size!
	msb->block_size = block_size;
	// Set block numbers
	msb->data_blocks = data_blocks;
	msb->hash_blocks = hash_blocks;
	msb->jb_blocks = jb_blocks;
	// Set salt size
	msb->salt_size = strlen(salt_str) / 2;
	// Copy salt
	memcpy(msb->salt, salt, msb->salt_size);
	// Set root hash
	memcpy(msb->root, hash_output, hash_length);
	// Write it out!
	if (write(file, msb, sizeof(struct mint_superblock)) < 0) {
		exit_error_f("Failed to write MSB: %s", strerror(errno));
	}
	if (write(file, zero_block, block_size - 512) < 0) {
		exit_error_f("Failed to write MSB pad: %s", strerror(errno));
	}

	// Big block buffer
	uint32_t multiple = 1024;
	char *big_block = (char*)malloc(block_size * multiple);
	bzero(big_block, block_size * multiple);

	// Write out hash block levels
	uint8_t p = 0;
	info("Writing hash blocks...");
	uint32_t h_written = 1;
	for (int i = levels - 1; i >= 0; i--) {
		// Copy into big buffer
		for (uint32_t m = 0; m < multiple; m++) {
			memcpy(big_block + m * block_size, hash_levels[i], block_size);
		}
		// Write out big buffer
		for (uint32_t j = 0; j < blocks_per_level[i] / multiple; j++) {
			h_written += multiple;
			p = progress(h_written, hash_blocks, 79, p);
			if(write(file, big_block, block_size * multiple) < 0){
				exit_error_f("Failed to write hash block: %u, %s",
					h_written - 1, strerror(errno));
			}
		}
		for (uint32_t j = 0; j < blocks_per_level[i] % multiple; j++) {
			p = progress(h_written++, hash_blocks, 79, p);
			if(write(file, hash_levels[i], block_size) < 0){
				exit_error_f("Failed to write hash block: %u, %s",
					h_written - 1, strerror(errno));
			}
		}
	}
	fprintf(stderr, "\n");

	// Initialize journal
	struct mint_journal_superblock *mjsb = (struct mint_journal_superblock*)
		malloc(sizeof(struct mint_journal_superblock));
	bzero(mjsb, sizeof(struct mint_journal_superblock));
	// Magic
	mjsb->header.magic = MJ_MAGIC;
	// Superblock
	mjsb->header.type = TYPE_MJSB;
	// Number of blocks
	mjsb->blocks = jb_blocks;
	// Head, tail, and fill are 0
	mjsb->head = 0;
	mjsb->tail = 0;
	mjsb->fill = 0;
	mjsb->sequence = 0;
	// Clean
	mjsb->state = 0;

	info("Writing journal...");
	if (write(file, mjsb, sizeof(struct mint_journal_superblock)) < 0) {
		exit_error_f("Failed to write journal superblock:, %s",
		strerror(errno));
	}
	if (write(file, zero_block, block_size - 512) < 0) {
		exit_error_f("Failed to write journal superblock pad: %s", strerror(errno));
	}

	struct mint_journal_header *mjh = (struct mint_journal_header*)
		malloc(sizeof(struct mint_journal_header));
	bzero(mjh, sizeof(struct mint_journal_header));
	// Magic
	mjh->magic = MJ_MAGIC;
	// Nothing block
	mjh->type = TYPE_MJNB;

	// Copy headers into start of every block
	bzero(big_block, block_size * multiple);
	for (uint64_t i = 0; i < multiple; i++) {
		memcpy(big_block + i * block_size, mjh, sizeof(struct mint_journal_header));
	}
	p = 0;
	for (uint64_t i = 0; i < (jb_blocks - 1) / multiple; i++) {
		if(write(file, big_block, block_size * multiple) < 0){
			exit_error_f("Failed to write journal block: %ju, %s", i,
				strerror(errno));
		}
		p = progress(i * multiple + 1, jb_blocks, 79, p);
	}
	for (uint64_t i = 0; i < (jb_blocks - 1) % multiple; i++) {
		if(write(file, big_block, block_size) < 0){
			exit_error_f("Failed to write journal block: %ju, %s", i,
				strerror(errno));
		}
		p = progress(jb_blocks - ((jb_blocks - 1) % multiple) + i + 2, jb_blocks, 79, p);
	}
	fprintf(stderr, "\n");

	// Zero out data
	if (zero) {
		int f = two_disks ? file2 : file;
		bzero(big_block, block_size * multiple);
		info("Writing data blocks...");
		p = 0;
		for (uint64_t i = 0; i < data_blocks / multiple; i++) {
			if(write(f, big_block, block_size * multiple) < 0){
				exit_error_f("Failed to write data block: %ju, %s", i,
					strerror(errno));
			}
			p = progress(i * multiple, data_blocks, 79, p);
		}
		for (uint64_t i = 0; i < data_blocks % multiple; i++) {
			if(write(f, zero_block, block_size) < 0){
				exit_error_f("Failed to write data block: %ju, %s", i,
					strerror(errno));
			}
			p = progress(data_blocks - (data_blocks % multiple) + i + 1,
				data_blocks, 79, p);
		}
		fprintf(stderr, "\n");
	} else {
		info("Skipping disk zeroing...");
	}

	close(file);
	if (two_disks) {
		close(file2);
	}

	print_superblock(msb);
	bytes_to_hex(msb->root, hash_bytes, buf);
	printf("dmsetup create meow --table \"%u %ju mintegrity %s %s %u %u %u %ju "
		"%s %s %s %s %s%s %s\"\n",
		0,             // Start is 0
		data_blocks * (block_size / 512),   // Size of device given to device mapper
		// Mintegrity options
		dev,           // String of block device
		two_disks ? dev2 : dev,
		block_size,    // Block size
		hash_blocks,   // Number of hash blocks
		jb_blocks,     // Number of journaling blocks
		data_blocks,   // Number of data blocks
		hash_type,     // Hash type
		buf,           // Root digest to verity
		salt_str,      // Salt
		hmac_type,     // Hash type for hmac
		secret_str,    // Hmac secret
		zero ? "nolazy" : " lazy",
		full_journal ? "full" : "sector"
		);

	free(mjh);
	free(mjsb);
	free(msb);
	free(blocks_per_level);
	free(zero_block);
	free(big_block);
	free(temp_block);
	for (int i = 0; i < levels; i++) {
		free(hash_levels[i]);
	}
	free(hash_levels);
	EVP_MD_CTX_destroy(mdctx_hash);
	return 0;
}
