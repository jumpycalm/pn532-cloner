/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   tables.h
 * Author: vk496
 *
 * Created on 15 de noviembre de 2018, 17:42
 */

#ifndef TABLES_H
#define TABLES_H

#include "../hardnested.h"
#include <errno.h>
#if defined(_WIN32)
#include "../../lib_win_x64/lzma.h"
#elif defined(__APPLE__)
#include "../../lib_darwin_x64/lzma.h"
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bitflip_info {
  uint32_t len;
  uint8_t *input_buffer;
} bitflip_info;

bitflip_info get_bitflip(odd_even_t odd_num, uint16_t id);
bool decompress(lzma_stream *strm);
bool lzma_init_inflate(lzma_stream *strm, uint8_t *inbuf, uint32_t inbuf_len, uint8_t *outbuf, uint32_t outbuf_len);
bool lzma_init_decoder(lzma_stream *strm);

#endif /* TABLES_H */
