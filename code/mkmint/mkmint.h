#define DM_MINTEGRITY_MAX_LEVELS 63

#define divide_up(x, y) (x == 0 ? x : (1 + ((x - 1) / y)))

#define MS_MAGIC 0x796c694c
#define MJ_MAGIC 0x594c494c

struct mint_superblock {
	uint32_t magic;           /**< 0x796c694c */
	uint32_t version;         /**< dm-mintegrity superblock version */
	char uuid[16];            /**< Device uuid */
	char hash_algorithm[32];  /**< Hash block algorithm */
	char hmac_algorithm[32];  /**< Hmac algorithm for root */
	uint64_t data_blocks;     /**< Number of data blocks */
	uint32_t hash_blocks;     /**< Number of hash blocks */
	uint32_t jb_blocks;       /**< Number of JB blocks */
	uint32_t block_size;      /**< Size of one data/hash block */
	uint16_t salt_size;       /**< Size of salt */
	char salt[128];           /**< Salt */
	char root[128];           /**< Root hash */     
	char pad[146];            /**< Padding */
}__attribute__((packed));

/** Mint Journal Nothing Block */
#define TYPE_MJNB 0
/** Mint Journal Super Block */
#define TYPE_MJSB 1
/** Mint Journal Descriptor Block */
#define TYPE_MJDB 2
/** Mint Journal Commit Block */
#define TYPE_MJCB 3

struct mint_journal_header {
	uint32_t magic;     /**< 0x594c494c */
	uint32_t type;      /**< Super/Descriptor/Commit Block */
	uint32_t sequence;  /**< Sequence number */
	uint32_t options;   /**< Options */
};

struct mint_journal_descriptor {
	struct mint_journal_header header;
	/** Block fill followed by tags */
};

struct mint_journal_commit {
	struct mint_journal_header header;
	/** Followed by char array of hmac */
};

struct mint_journal_block_tag {
	uint32_t low;      /**< Destination sector low */
	uint32_t high;     /**< Destination sector high */
	uint32_t options;  /**< Last or bits for escaped blocks */
};

struct mint_journal_superblock {
	struct mint_journal_header header;
	uint32_t blocks;      /**< Number of block in this journal (including superblock) */
	uint32_t head;        /**< Circular buffer head position */
	uint32_t tail;        /**< Circular buffer tail position */
	uint32_t fill;        /**< Number of used blocks */
	uint32_t sequence;    /* Current sequence number */
	char state;           /**< Clean, Dirty */
};

/**
struct mint_metadata_entry {
	uint32_t sector;
	char level_1[hash_bytes];
	char level_2[hash_bytes];
	...
}

As many as will fill a BLOCK_SIZE, rest space padded
**/

///////////////////////////////////////////////////////////////////////////////
////////////////////////////////// Printing ///////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

/*! @brief Exit the program with code 1 and an error message
 *
 * @param message String to write to standard error
 */
#define exit_error(message) fprintf(stderr, "\033[31m%s\033[0m\n", message); exit(1);

/*! @brief Exit the program with code 1 and an error message
 *
 * Adds a newline to the end of the printed string
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define exit_error_f(fmt, ...) fprintf(stderr, "\033[31m"fmt"\033[0m\n", ##__VA_ARGS__); exit(1);

/*! @brief Print a debug message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#ifdef DEBUG
#define debug(fmt, ...) fprintf(stderr, "\033[33m[DEBUG]\033[0m \033[35m%s:%d:\033[0m " fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define debug(fmr, ...)
#endif

/*! @brief Print an info message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define info(fmt, ...) fprintf(stderr, "\033[32m[INFO]\033[0m " fmt"\n", ##__VA_ARGS__)

/*! @brief Print a log message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define log(fmt, ...) fprintf(stderr, "\033[36m[LOG]\033[0m " fmt"\n", ##__VA_ARGS__)

/*! @brief Print a warning message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define warn(fmt, ...) fprintf(stderr, "\033[31m[WARN]\033[0m \033[35m%s:%d:\033[0m " fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__)
