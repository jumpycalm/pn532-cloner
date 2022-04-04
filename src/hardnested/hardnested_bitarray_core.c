#include "hardnested_bitarray_core.h"
#include "hardnested_bf_core.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef __APPLE__
#include <malloc.h>
#endif

inline uint32_t *MALLOC_BITARRAY(uint32_t x)
{
#if defined(_WIN32)
  return __builtin_assume_aligned(_aligned_malloc((x), __BIGGEST_ALIGNMENT__), __BIGGEST_ALIGNMENT__);
#elif defined(__APPLE__)
  uint32_t *allocated_memory;
  if (posix_memalign((void **)&allocated_memory, __BIGGEST_ALIGNMENT__, x)) {
    return NULL;
  } else {
    return __builtin_assume_aligned(allocated_memory, __BIGGEST_ALIGNMENT__);
  }
#else
  return __builtin_assume_aligned(memalign(__BIGGEST_ALIGNMENT__, (x)), __BIGGEST_ALIGNMENT__);
#endif
}

inline void FREE_BITARRAY(uint32_t *x)
{
#ifdef _WIN32
  _aligned_free(x);
#else
  free(x);
#endif
}

inline uint32_t BITCOUNT(uint32_t a)
{
  return __builtin_popcountl(a);
}

inline uint32_t COUNT_STATES(uint32_t *A)
{
  uint32_t count = 0;
  for (uint32_t i = 0; i < (1 << 19); i++) {
    count += BITCOUNT(A[i]);
  }
  return count;
}

inline void BITARRAY_AND(uint32_t *restrict A, uint32_t *restrict B)
{
  A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  for (uint32_t i = 0; i < (1 << 19); i++) {
    A[i] &= B[i];
  }
}

inline void BITARRAY_LOW20_AND(uint32_t *restrict A, uint32_t *restrict B)
{
  uint16_t *a = (uint16_t *)__builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  uint16_t *b = (uint16_t *)__builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);

  for (uint32_t i = 0; i < (1 << 20); i++) {
    if (!b[i]) {
      a[i] = 0;
    }
  }
}

inline uint32_t COUNT_BITARRAY_AND(uint32_t *restrict A, uint32_t *restrict B)
{
  A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  uint32_t count = 0;
  for (uint32_t i = 0; i < (1 << 19); i++) {
    A[i] &= B[i];
    count += BITCOUNT(A[i]);
  }
  return count;
}

inline uint32_t COUNT_BITARRAY_LOW20_AND(uint32_t *restrict A, uint32_t *restrict B)
{
  uint16_t *a = (uint16_t *)__builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  uint16_t *b = (uint16_t *)__builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  uint32_t count = 0;

  for (uint32_t i = 0; i < (1 << 20); i++) {
    if (!b[i]) {
      a[i] = 0;
    }
    count += BITCOUNT(a[i]);
  }
  return count;
}

inline void BITARRAY_AND4(uint32_t *restrict A, uint32_t *restrict B, uint32_t *restrict C, uint32_t *restrict D)
{
  A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  C = __builtin_assume_aligned(C, __BIGGEST_ALIGNMENT__);
  D = __builtin_assume_aligned(D, __BIGGEST_ALIGNMENT__);
  for (uint32_t i = 0; i < (1 << 19); i++) {
    A[i] = B[i] & C[i] & D[i];
  }
}

inline void BITARRAY_OR(uint32_t *restrict A, uint32_t *restrict B)
{
  A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  for (uint32_t i = 0; i < (1 << 19); i++) {
    A[i] |= B[i];
  }
}

inline uint32_t COUNT_BITARRAY_AND2(uint32_t *restrict A, uint32_t *restrict B)
{
  A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  uint32_t count = 0;
  for (uint32_t i = 0; i < (1 << 19); i++) {
    count += BITCOUNT(A[i] & B[i]);
  }
  return count;
}

inline uint32_t COUNT_BITARRAY_AND3(uint32_t *restrict A, uint32_t *restrict B, uint32_t *restrict C)
{
  A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  C = __builtin_assume_aligned(C, __BIGGEST_ALIGNMENT__);
  uint32_t count = 0;
  for (uint32_t i = 0; i < (1 << 19); i++) {
    count += BITCOUNT(A[i] & B[i] & C[i]);
  }
  return count;
}

inline uint32_t COUNT_BITARRAY_AND4(uint32_t *restrict A, uint32_t *restrict B, uint32_t *restrict C, uint32_t *restrict D)
{
  A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
  B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
  C = __builtin_assume_aligned(C, __BIGGEST_ALIGNMENT__);
  D = __builtin_assume_aligned(D, __BIGGEST_ALIGNMENT__);
  uint32_t count = 0;
  for (uint32_t i = 0; i < (1 << 19); i++) {
    count += BITCOUNT(A[i] & B[i] & C[i] & D[i]);
  }
  return count;
}