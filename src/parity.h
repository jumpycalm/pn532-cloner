//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Parity functions
//-----------------------------------------------------------------------------

// all functions defined in header file by purpose. Allows compiler optimizations. 

#ifndef __PARITY_H
#define __PARITY_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

extern const uint8_t OddByteParity[256];

static inline bool oddparity8(const uint8_t x) {
    return OddByteParity[x];
}

static inline bool evenparity8(const uint8_t x) {
    return !OddByteParity[x];
}

static inline bool evenparity32(uint32_t x) {
    return __builtin_parity(x);
}

#endif /* __PARITY_H */
