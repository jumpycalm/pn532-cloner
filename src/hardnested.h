//-----------------------------------------------------------------------------
// Copyright (C) 2015 piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// hardnested functions
//-----------------------------------------------------------------------------

#ifndef HARDNESTED_H__
#define HARDNESTED_H__

#include <stdbool.h>
#include <stdint.h>

#define NUM_SUMS 19 // number of possible sum property values

typedef enum {
  EVEN_STATE = 0,
  ODD_STATE = 1
} odd_even_t;

typedef enum {
  TO_BE_DONE,
  WORK_IN_PROGRESS,
  COMPLETED
} work_status_t;

typedef struct guess_sum_a8 {
  float prob;
  uint64_t num_states;
  uint8_t sum_a8_idx;
} guess_sum_a8_t;

typedef struct noncelistentry {
  uint32_t nonce_enc;
  uint8_t par_enc;
  void *next;
} noncelistentry_t;

typedef struct noncelist {
  uint16_t num;
  uint16_t Sum;
  guess_sum_a8_t sum_a8_guess[NUM_SUMS];
  bool sum_a8_guess_dirty;
  float expected_num_brute_force;
  uint8_t BitFlips[0x400];
  uint32_t *states_bitarray[2];
  uint32_t num_states_bitarray[2];
  bool all_bitflips_dirty[2];
  noncelistentry_t *first;
} noncelist_t;

bool mfnestedhard(uint8_t src_sector, uint8_t src_key_type, uint8_t *key, uint8_t trg_sector, uint8_t trg_key_type);
void hardnested_print_progress(uint32_t nonces, char *activity, float brute_force, uint8_t trgKeySector, uint8_t trgKeyType, bool newline);

#endif
