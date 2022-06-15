#ifndef MFOC_H__
#define MFOC_H__

#include "mifare.h"
#include "nfc-types.h"

// Number of trailers == number of sectors
// Mifare Classic 1k 16x64b = 16
#define NR_TRAILERS_1k (16)
// Mifare Classic Mini
#define NR_TRAILERS_MINI (5)
// Mifare Classic 4k 32x64b + 8*256b = 40
#define NR_TRAILERS_4k (40)
// Mifare Classic 2k 32x64b
#define NR_TRAILERS_2k (32)

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

#define odd_parity(i) (((i) ^ (i) >> 1 ^ (i) >> 2 ^ (i) >> 3 ^ (i) >> 4 ^ (i) >> 5 ^ (i) >> 6 ^ (i) >> 7 ^ 1) & 0x01)

typedef struct {
  uint8_t KeyA[6];
  uint8_t KeyB[6];
  bool foundKeyA;
  bool foundKeyB;
  uint8_t trailer; // Value of a trailer block
} sector;

typedef struct {
  nfc_target nt;
  sector sectors[NR_TRAILERS_4k];
  uint8_t num_sectors; // Actual total number of sectors, for example for 4K, it's 40
  uint8_t num_blocks; // Max block num, for example for 4K, it's 255
  uint32_t authuid;
} mftag;

typedef struct {
  nfc_device *pdi;
} mfreader;

extern mftag t;
extern mfreader r;
extern uint8_t hardnested_broken_key[6];

void usage(FILE *stream, uint8_t errnr);
bool mf_init(mfreader *r);
bool mf_configure(nfc_device *pdi);
bool mf_select_tag(mftag t, mfreader r);
bool get_rats_is_2k(mftag t, mfreader r);
void num_to_bytes(uint64_t n, uint32_t len, uint8_t *dest);
long long unsigned int bytes_to_num(uint8_t *src, uint32_t len);

int8_t test_keys(mifare_param *mp, bool test_block_0_only, bool test_key_a_only);
bool if_tag_is_blank(nfc_iso14443a_info tag_info);
void generate_file_name(char *name, uint8_t num_blocks, uint8_t uid_len, uint8_t *uid);
bool is_first_block(uint32_t uiBlock);
bool is_trailer_block(uint32_t block);
void sanitize_mfc_buffer_for_gen2_magic(void);
void sanitize_mfc_buffer_for_salto_compatible_tag(void);
bool write_blank_gen2(void);
bool write_blank_gen3(void);
bool write_salto_compatible_tag(bool if_4k_tag);
bool clean_mfc(bool force);
bool write_mfc(bool force, char *file_name);
bool read_mfc();

#endif