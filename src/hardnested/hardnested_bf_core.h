#include "hardnested_bruteforce.h"

uint64_t CRACK_STATES_BITSLICED(uint32_t cuid, uint8_t *best_first_bytes, statelist_t *p, uint32_t *keys_found,
    uint64_t *num_keys_tested, uint32_t nonces_to_bruteforce,
    const uint8_t *bf_test_nonce_2nd_byte, noncelist_t *nonces);

void BITSLICE_TEST_NONCES(uint32_t nonces_to_bruteforce, const uint32_t *bf_test_nonce, const uint8_t *bf_test_nonce_par);
