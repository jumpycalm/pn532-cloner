#ifndef MFOC_H__
#define MFOC_H__

#include "nfc-types.h"

#define MEM_CHUNK               10000
#define TRY_KEYS                50

// Number of trailers == number of sectors
// Mifare Classic 1k 16x64b = 16
#define NR_TRAILERS_1k  (16)
// Mifare Classic Mini
#define NR_TRAILERS_MINI (5)
// Mifare Classic 4k 32x64b + 8*256b = 40
#define NR_TRAILERS_4k  (40)
// Mifare Classic 2k 32x64b
#define NR_TRAILERS_2k  (32)

// Number of blocks
// Mifare Classic 1k
#define NR_BLOCKS_1k 0x3f
// Mifare Classic Mini
#define NR_BLOCKS_MINI 0x13
// Mifare Classic 4k
#define NR_BLOCKS_4k 0xff
// Mifare Classic 2k
#define NR_BLOCKS_2k 0x7f

#define MAX_FRAME_LEN 264

// Used for counting nonce distances, explore [nd-value, nd+value]
#define DEFAULT_TOLERANCE       20

// Default number of distance probes
#define DEFAULT_DIST_NR         15

// Default number of probes for a key recovery for one sector
#define DEFAULT_PROBES_NR       150

// Number of sets with 32b keys
#define DEFAULT_SETS_NR         5

#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)

typedef struct {
  uint8_t KeyA[6];
  uint8_t KeyB[6];
  bool foundKeyA;
  bool foundKeyB;
  uint8_t trailer;                         // Value of a trailer block
} sector;

typedef struct {
  uint32_t       *distances;
  uint32_t       median;
  uint32_t       num_distances;
  uint32_t       tolerance;
  uint8_t        parity[3];              // used for 3 bits of parity information
} denonce;                                      // Revealed information about nonce

typedef struct {
  nfc_target	 nt;
  sector         *sectors;                // Allocate later, we do not know the number of sectors yet
  sector         e_sector;		// Exploit sector
  uint8_t        num_sectors; // Actual total number of sectors, for example for 4K, it's 40
  uint8_t        num_blocks;  // Max block num, for example for 4K, it's 255
  uint32_t       authuid;
} mftag;

typedef struct {
  uint64_t       *possibleKeys;
  uint32_t       size;
} pKeys;

typedef struct {
  uint64_t       *brokenKeys;
  uint32_t       size;
} bKeys;

typedef struct {
  nfc_device     *pdi;
} mfreader;

typedef struct {
  uint64_t       key;
  int            count;
} countKeys;


extern mftag        t;
extern mfreader    r;
extern uint8_t hardnested_broken_key[6];


void usage(FILE *stream, uint8_t errnr);
bool mf_init(mfreader *r);
bool mf_configure(nfc_device *pdi);
bool mf_select_tag(nfc_device *pdi, nfc_target *pnt);
bool mf_anticollision(mftag t, mfreader r);
bool get_rats_is_2k(mftag t, mfreader r);
uint32_t median(denonce d);
int compar_int(const void *a, const void *b);
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, uint8_t *parity);
int compar_special_int(const void *a, const void *b);
void num_to_bytes(uint64_t n, uint32_t len, uint8_t *dest);
long long unsigned int bytes_to_num(uint8_t *src, uint32_t len);

int8_t test_keys(mifare_param *mp);
bool if_tag_is_blank(nfc_iso14443a_info tag_info);
void generate_file_name(char *name, uint8_t num_blocks, uint8_t uid_len, uint8_t *uid);
bool is_first_block(uint32_t uiBlock);
bool is_trailer_block(uint32_t block);
void sanitize_mfc_buffer(void);
bool write_blank_mfc(bool write_block_zero);
bool clean_mfc(bool force);
bool write_mfc(bool force, char *file_name);
bool read_mfc();

#endif