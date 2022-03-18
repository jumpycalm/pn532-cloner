#ifndef HARDNESTED_BITARRAY_CORE_H__
#define HARDNESTED_BITARRAY_CORE_H__

#include <stdint.h>

uint32_t *MALLOC_BITARRAY(uint32_t x);
void FREE_BITARRAY(uint32_t *x);
uint32_t BITCOUNT(uint32_t a);
uint32_t COUNT_STATES(uint32_t *A);
void BITARRAY_AND(uint32_t *A, uint32_t *B);
void BITARRAY_LOW20_AND(uint32_t *A, uint32_t *B);
uint32_t COUNT_BITARRAY_AND(uint32_t *A, uint32_t *B);
uint32_t COUNT_BITARRAY_LOW20_AND(uint32_t *A, uint32_t *B);
void BITARRAY_AND4(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D);
void BITARRAY_OR(uint32_t *A, uint32_t *B);
uint32_t COUNT_BITARRAY_AND2(uint32_t *A, uint32_t *B);
uint32_t COUNT_BITARRAY_AND3(uint32_t *A, uint32_t *B, uint32_t *C);
uint32_t COUNT_BITARRAY_AND4(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D);

#endif
