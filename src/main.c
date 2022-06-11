/*-
 * Mifare Classic Offline Cracker
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Contact: <mifare@nethemba.com>
 *
 * Porting to libnfc 1.3.3: Michal Boska <boska.michal@gmail.com>
 * Porting to libnfc 1.3.9 and upper: Romuald Conty <romuald@libnfc.org>
 *
 */

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * http://eprint.iacr.org/2009/137.pdf
 * http://www.sos.cs.ru.nl/applications/rfid/2008-esorics.pdf
 * http://www.cosic.esat.kuleuven.be/rfidsec09/Papers/mifare_courtois_rfidsec09.pdf
 * http://www.cs.ru.nl/~petervr/papers/grvw_2009_pickpocket.pdf
 */

#define _XOPEN_SOURCE 1 // To enable getopt

#include "util_posix.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // stat
#include <windows.h> //Sleep
#ifdef _MSC_VER
#include "getopt.h"
#include "unistd_w.h"
#else
#include <unistd.h>
#endif

// NFC
#include "nfc.h"

// Crapto1
#include "crapto1.h"

// Internal
#include "main.h"
#include "mifare.h"
#include "nfc-utils.h"

// SLRE
#include "hardnested.h"
#include "slre.h"

#define MAX_FRAME_LEN 264
#define MAX_FILE_LEN 22 // 3 leading chars as type, followed by up to 7-byte UID (14 chars), followed by .bin and ending char (5 chars)

#define WHITE_SPACE "                                                                            "

#define PN532_CLONER_VER "0.4.0"

mftag t;
mfreader r;
uint8_t hardnested_broken_key[6];

static const nfc_modulation nm = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

nfc_context *context;

// mtDump saves the memory dump of last read MFC tag
// last_read_type saves the last success read MFC tag
typedef enum {
  MFC_TYPE_INVALID = 0,
  MFC_TYPE_C14,
  MFC_TYPE_C17,
  MFC_TYPE_C44,
  MFC_TYPE_C47,
} mfc_type;
static mfc_type last_read_mfc_type = MFC_TYPE_INVALID;
static uint8_t last_read_uid[7];
static mifare_classic_tag mtDump;
static char file_name[MAX_FILE_LEN];

static const uint8_t default_key[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t blank_key[6] = { 0 };
static const uint8_t default_data_block[16] = { 0 };
static const uint8_t default_trailer_block[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

// Array with default MIFARE Classic keys (Keys for Sestor 0)
static uint8_t defaultKeys[][6] = {
  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, // Factory default key
  { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 }, // NFCForum MAD key
  { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 },
  { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 }, // NFCForum content key
};

// Array with special MIFARE Classic keys (keys for non-Sector 0)
static uint8_t specialKeys[][6] = {
  { 0x6a, 0x19, 0x87, 0xc4, 0x0a, 0x21 }, // Salto Key A
  { 0x7f, 0x33, 0x62, 0x5b, 0xc1, 0x29 }, // Salto Key B
};

static void pn532_cloner_usage()
{
  printf("\n\n\n");
  printf("###################################################################################\n");
  printf("Usage:\n");
  printf("r             - (R)ead a tag\n");
  printf("w             - (W)rite to a magic tag using the data from the most recent read tag\n");
  printf("w <File name> - (W)rite to a magic tag using the data from a saved dump file\n");
  printf("c             - (C)lean/Restore a magic tag to the factory default\n");
  printf("e             - (E)xit\n");
  printf("\n");
  printf("Example:\n");
  printf("Enter \"r\" to read a tag\n");
  printf("Enter \"w\" to write to a magic tag using the data from the tag you just read\n");
  printf("###################################################################################\n");
  printf("\n");
}

// Test if the given key is valid, if the key is valid, add the key to the found key in global variable
// Return number of new exploited keys
// Return -1 if error is detected such as tag is removed
int8_t test_keys(mifare_param *mp, bool test_block_0_only, bool test_key_a_only)
{
  int8_t num_of_exploited_keys = 0;
  uint8_t current_block;
  int res;
  mifare_param mp_tmp; // Used for trying Key B if Key B is able to recover from reading the trailer block

  for (uint8_t i = 0; i < t.num_sectors; i++) {
    bool just_found_key_a = false;
    current_block = get_trailer_block_num_from_sector_num(i);
    // Logic for testing Key A, if Key A is broken, try to see if we can break Key B
    if (!t.sectors[i].foundKeyA) {
      if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, current_block, mp)) < 0) {
        if (res != NFC_EMFCAUTHFAIL) {
          nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
          return -1;
        }
        if (!mf_select_tag(t, r))
          return -1;
      } else {
        // Save all information about successfully keyA authentication
        memcpy(t.sectors[i].KeyA, mp->mpa.abtKey, sizeof(mp->mpa.abtKey));
        t.sectors[i].foundKeyA = true;
        num_of_exploited_keys++;
        just_found_key_a = true;
      }
    }
    // Logic for testing Key B
    if (!t.sectors[i].foundKeyB && !test_key_a_only) {
      if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, current_block, mp)) < 0) {
        if (res != NFC_EMFCAUTHFAIL) {
          nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
          return -1;
        }
        if (!mf_select_tag(t, r))
          return -1;
      } else {
        memcpy(t.sectors[i].KeyB, mp->mpa.abtKey, sizeof(mp->mpa.abtKey));
        t.sectors[i].foundKeyB = true;
        num_of_exploited_keys++;
      }
    }
    // Logic for trying to get Key B by reading the trailer block
    // Because for commercial application, this backdoor is sealed, the success rate is very low
    // Only perform this task if found Key A but not Key B
    // All the gen 2 tags wrote by this application keep this back door open
    if (just_found_key_a && !t.sectors[i].foundKeyB && !test_key_a_only) {
      if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, current_block, mp)) < 0) {
        if (res != NFC_EMFCAUTHFAIL) {
          nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
          return -1;
        }
        if (!mf_select_tag(t, r))
          return -1;
      } else {
        if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_READ, current_block, &mp_tmp)) >= 0) {
          if (!memcmp(mp_tmp.mpd.abtData + 10, blank_key, sizeof(blank_key)))
            continue;

          memcpy(mp_tmp.mpa.abtKey, mp_tmp.mpd.abtData + 10, sizeof(mp_tmp.mpa.abtKey));
          if ((mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, current_block, &mp_tmp)) < 0) {
            if (!mf_configure(r.pdi))
              return -1;
            if (!mf_select_tag(t, r))
              return -1;
          } else {
            memcpy(t.sectors[i].KeyB, mp_tmp.mpd.abtData + 10, sizeof(t.sectors[i].KeyB));
            t.sectors[i].foundKeyB = true;
            num_of_exploited_keys++;
          }
        } else {
          if (res != NFC_ERFTRANS) {
            nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
            return -1;
          }
          if (!mf_select_tag(t, r))
            return -1;
        }
      }
    }

    // Save position of a trailer block to sector struct
    t.sectors[i].trailer = current_block;

    if (i == 0 && test_block_0_only)
      break;
  }
  // printf("Debug! num_of_exploited_keys = %d\n", num_of_exploited_keys);
  return num_of_exploited_keys;
}

bool if_tag_is_blank(nfc_iso14443a_info tag_info)
{
  for (uint8_t i = 0; i < tag_info.szUidLen; i++)
    if (tag_info.abtUid[i])
      return false;
  return true;
}

bool is_first_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock) % 4 == 0);
  else
    return ((uiBlock) % 16 == 0);
}

bool is_trailer_block(uint32_t block)
{
  // Test if we are in the small or big sectors
  return (block < 128) ? ((block + 1) % 4 == 0) : ((block + 1) % 16 == 0);
}
/*
static uint32_t get_trailer_block(uint32_t uiFirstBlock)
{
  // Test if we are in the small or big sectors
  uint32_t trailer_block = 0;
  if (uiFirstBlock < 128) {
    trailer_block = uiFirstBlock + (3 - (uiFirstBlock % 4));
  } else {
    trailer_block = uiFirstBlock + (15 - (uiFirstBlock % 16));
  }
  return trailer_block;
}
*/

// Calculate if we reached the 1st block that needs authentication
static bool if_need_authenticate(uint16_t current_block, bool write_block_zero)
{
  int i; // i must be a signed number because we are doing minus, it's possible i will reach to -1 to compare with 0
  if (is_trailer_block(current_block)) {
    if (!memcmp(&mtDump.amb[current_block], default_trailer_block, 16))
      return false;
  } else {
    if (!memcmp(&mtDump.amb[current_block], default_data_block, 16))
      return false;
  }

  // If the leading block is not default, we need to authenticate this block
  if (get_leading_block_num_from_block_num(current_block, write_block_zero) == current_block)
    return true;
  // If the current block is not the leading block, we need to check if there's any block before this block is not default
  for (i = current_block - 1; i >= get_leading_block_num_from_block_num(current_block, write_block_zero); i--) {
    if (memcmp(&mtDump.amb[i], default_data_block, 16))
      return false;
  }
  return true;
}

// Check if we need to write this block (if data is the default data, no need to write)
static bool if_need_write_current_block(uint16_t current_block)
{
  if (is_trailer_block(current_block)) {
    if (!memcmp(&mtDump.amb[current_block], default_trailer_block, 16))
      return false;
  } else {
    if (!memcmp(&mtDump.amb[current_block], default_data_block, 16))
      return false;
  }
  return true;
}

// Write to a gen 2 tag that has been initialized to factory default
bool write_blank_gen2(void)
{
  uint32_t current_block;
  uint32_t total_blocks = NR_BLOCKS_1k + 1;
  mifare_param mp;
  uint32_t last_authenticate_block_num = 0;

  // Check to see if we have a success read
  if (last_read_mfc_type == MFC_TYPE_INVALID) {
    printf("Please read your original tag first before write to a new tag.\n");
    return false;
  } else if (last_read_mfc_type != MFC_TYPE_C14) {
    printf("Programming error detected.\n");
    return false;
  }

  sanitize_mfc_buffer_for_gen2_magic();

  if (!mf_configure(r.pdi))
    return false;

  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) <= 0) {
    printf("Error: tag was removed\n");
    return false;
  }

  // Completely write the card, but skipping block 0 if we don't need to write on it
  for (current_block = 0; current_block < total_blocks; current_block++) {
    // Authenticate everytime we reach new block and need to actually write a data on
    if (if_need_authenticate(current_block, true)) {
      // printf("Block %u needs authentication\n", current_block);

      // Check if we need to reslect with the new UID
      if (current_block > 3 && last_authenticate_block_num < 4) {
        if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) <= 0) {
          printf("Error: tag was removed\n");
          return false;
        }
      }

      memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);
      memcpy(mp.mpa.abtKey, default_key, 6);
      if (!nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, current_block, &mp)) {
        printf("Authentication error\n");
        return false;
      }

      last_authenticate_block_num = current_block;
    }

    // Write data
    if (if_need_write_current_block(current_block)) {
      memcpy(mp.mpd.abtData, mtDump.amb[current_block].mbd.abtData, sizeof(mp.mpd.abtData));
      if (!nfc_initiator_mifare_cmd(r.pdi, MC_WRITE, current_block, &mp)) {
        printf("Failed at writing block %d \n", current_block);
        return false;
      }
      // printf("Block %u write success.\n", current_block);
    }
  }

  return true;
}

// Write to a gen 3 tag that has been initialized to factory default
bool write_blank_gen3(void)
{
  uint32_t current_block;
  uint32_t total_blocks = NR_BLOCKS_1k + 1;
  mifare_param mp;

  // Check to see if we have a success read
  if (last_read_mfc_type == MFC_TYPE_INVALID) {
    printf("Please read your original tag first before write to a new tag\n");
    return false;
  } else if (last_read_mfc_type == MFC_TYPE_C44 || last_read_mfc_type == MFC_TYPE_C47)
    total_blocks = NR_BLOCKS_4k + 1;

  if (!mf_configure(r.pdi))
    return false;

  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) <= 0) {
    printf("Error: tag was removed\n");
    return false;
  }

  // Completely write the card, but skipping block 0
  for (current_block = 1; current_block < total_blocks; current_block++) {
    // Authenticate everytime we reach new block and need to actually write a data on
    if (if_need_authenticate(current_block, false)) {
      // printf("Block %u needs authentication\n", current_block);
      memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);
      memcpy(mp.mpa.abtKey, default_key, 6);
      if (!nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, current_block, &mp)) {
        printf("Authentication error\n");
        return false;
      }
    }

    // Write data
    if (if_need_write_current_block(current_block)) {
      memcpy(mp.mpd.abtData, mtDump.amb[current_block].mbd.abtData, sizeof(mp.mpd.abtData));
      if (!nfc_initiator_mifare_cmd(r.pdi, MC_WRITE, current_block, &mp)) {
        printf("Failed at writing block %d \n", current_block);
        return false;
      }
      // printf("Block %u write success.\n", current_block);
    }
  }

  return true;
}

// Gen 2 magic can be read/write with Key A with the default access bits
// This function will set marker bytes for Block 0 and set all the configuration blocks with the default access bits (easier for key cracking)
void sanitize_mfc_buffer_for_gen2_magic(void)
{
  uint8_t default_acl[] = { 0xff, 0x07, 0x80, 0x69 };
  mtDump.amb[0].mbd.abtData[14] = 0xe1;
  mtDump.amb[0].mbd.abtData[15] = 0xe2;
  for (uint8_t i = 0; i < NR_TRAILERS_1k; i++)
    memcpy(mtDump.amb[get_trailer_block_num_from_sector_num(i)].mbt.abtAccessBits, default_acl, sizeof(default_acl));
}

void generate_file_name(char *name, uint8_t num_blocks, uint8_t uid_len, uint8_t *uid)
{
  if (num_blocks == NR_BLOCKS_1k && uid_len == 4)
    sprintf(name, "C14%02x%02x%02x%02x.bin", uid[0], uid[1], uid[2], uid[3]);
  else if (num_blocks == NR_BLOCKS_1k && uid_len == 7)
    sprintf(name, "C17%02x%02x%02x%02x%02x%02x%02x.bin", uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);
  if (num_blocks == NR_BLOCKS_4k && uid_len == 4)
    sprintf(name, "C44%02x%02x%02x%02x.bin", uid[0], uid[1], uid[2], uid[3]);
  else if (num_blocks == NR_BLOCKS_4k && uid_len == 7)
    sprintf(name, "C47%02x%02x%02x%02x%02x%02x%02x.bin", uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);
  else
    name = NULL;
}

// Modern MIFARE Classic tags are all MIFARE Classic EV1 tags, which means they are not vulnerable to old faster attacks
// such as Darkside attack, nested attack. Therefore, we only use hardnested attack to recover the unknown keys
bool read_mfc()
{
  int i;
  int block;
  bool read_success = false;
  int remaining_keys_to_be_found;
  int remaining_keys_to_be_found_before_hardnested;
  int8_t test_key_res;
  int res_auth;
  int res_read;
  bool try_key_b;
  uint64_t start_time = msclock();
  uint8_t hardnested_runs = 0;

  static mifare_param mp;

  FILE *pfDump = NULL;

  last_read_mfc_type = MFC_TYPE_INVALID; // Always assume read is failed before performing the read

  // Initialize t.sectors, keys are not known yet
  memset(&t, 0, sizeof(t));

  if (!mf_configure(r.pdi))
    return false;

  int tag_count;
  if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    return false;
  } else if (tag_count == 0) {
    ERR("No tag found.");
    return false;
  }

  // Test if a compatible MIFARE tag is used
  if (((t.nt.nti.nai.btSak & 0x08) == 0) && (t.nt.nti.nai.btSak != 0x01)) {
    printf("Only MIFARE Classic tags are supported");
    return false;
  }

  t.authuid = (uint32_t)bytes_to_num(t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);

  // Get Mifare Classic type from SAK
  // see http://www.nxp.com/documents/application_note/AN10833.pdf Section 3.2
  switch (t.nt.nti.nai.btSak) {
  case 0x01:
  case 0x08:
  case 0x88:
  case 0x28:
    if (get_rats_is_2k(t, r)) {
      printf("MIFARE Plus 2K tagis not supported\n");
      return false;
    } else {
      t.num_sectors = NR_TRAILERS_1k;
      t.num_blocks = NR_BLOCKS_1k;
      if (t.nt.nti.nai.szUidLen == 4)
        printf("Detected MIFARE Classic 1K 4-Byte tag\n");
      else if (t.nt.nti.nai.szUidLen == 7)
        printf("Detected MIFARE Classic 1K 7-Byte tag\n");
      else {
        printf("Unsupported UID length\n");
        return false;
      }
    }
    break;
  case 0x09:
    printf("MIFARE Classic Mini tag is not supported\n");
    return false;
    break;
  case 0x18:
    t.num_sectors = NR_TRAILERS_4k;
    t.num_blocks = NR_BLOCKS_4k;
    if (t.nt.nti.nai.szUidLen == 4)
      printf("Detected MIFARE Classic 4K 4-Byte tag\n");
    else if (t.nt.nti.nai.szUidLen == 7)
      printf("Detected MIFARE Classic 4K 7-Byte tag\n");
    else {
      printf("Unsupported UID length\n");
      return false;
    }
    break;
  default:
    ERR("Cannot determine card type from SAK");
    return false;
  }

  // Check if the tag is a blank tag by checking the UID
  if (if_tag_is_blank(t.nt.nti.nai)) {
    printf("This is blank tag\n");
    return false;
  }

  // Check if the tag is on the file
  // Pick a file name based on the tag's type and UID
  generate_file_name(file_name, t.num_blocks, t.nt.nti.nai.szUidLen, t.nt.nti.nai.abtUid);

  // Check if the file is already exist (data is already on file)
  struct stat buffer;
  if (!stat(file_name, &buffer)) {
    printf("This tag is already on file\n");
    printf("To re-read this file, please delete %s file and retry\n", file_name);
    printf("To write this tag to a new tag, please execute \"w %s\"\n", file_name);
    return false;
  }

  print_nfc_target(&t.nt, false);

  // Test the facotry default keys
  remaining_keys_to_be_found = t.num_sectors * 2;
  memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
  printf("\nChecking encryption keys, please wait up to 8s\n");

  memcpy(mp.mpa.abtKey, defaultKeys[0], sizeof(defaultKeys[0]));
  test_key_res = test_keys(&mp, false, false);
  if (test_key_res < 0)
    goto out;
  else
    remaining_keys_to_be_found -= test_key_res;

  // For all non-factory default keys, only test Block 0 as if the key does not work for Block 0,
  // they will unlikely to be able to work with other blocks as well.
  for (i = 1; i < sizeof(defaultKeys) / sizeof(defaultKeys[0]); i++) {
    memcpy(mp.mpa.abtKey, defaultKeys[i], sizeof(defaultKeys[i]));
    test_key_res = test_keys(&mp, true, false);
    if (test_key_res < 0)
      goto out;
    else
      remaining_keys_to_be_found -= test_key_res;
  }

  // Test special keys
  for (i = 0; i < sizeof(specialKeys) / sizeof(specialKeys[0]); i++) {
    memcpy(mp.mpa.abtKey, specialKeys[i], sizeof(specialKeys[i]));
    test_key_res = test_keys(&mp, false, false);
    if (test_key_res < 0)
      goto out;
    else
      remaining_keys_to_be_found -= test_key_res;
  }

  if (remaining_keys_to_be_found == t.num_sectors * 2) {
    printf("Fully encrypted MIFARE Classic tag is not supported.\n");
    printf("If you wish to support the fully encrypted MIFARE Classic tags, please contact us.\n");
    printf("If there's enough demand, we will add support\n");
    goto out;
  }

  if (remaining_keys_to_be_found == 0) {
    printf("Unencrypted MIFARE Classic tag\n");
    goto read_tag;
  }

  printf("This tag is encrypted with %u encryption keys.\n", remaining_keys_to_be_found);
  printf("The ETA to crack all the encryption keys is %u minutes.\n", (uint16_t)remaining_keys_to_be_found * 5);
  remaining_keys_to_be_found_before_hardnested = remaining_keys_to_be_found;

  // Use hardnested to crack the unknown keys
  uint8_t hardnested_src_sector;
  uint8_t hardnested_src_key_type;
  uint8_t hardnested_src_key[6];
  i = t.num_sectors - 1;
  while (true) {
    if (t.sectors[i].foundKeyA) {
      hardnested_src_sector = i;
      hardnested_src_key_type = MC_AUTH_A;
      memcpy(hardnested_src_key, t.sectors[i].KeyA, sizeof(t.sectors[i].KeyA));
      break;
    }
    if (t.sectors[i].foundKeyB) {
      hardnested_src_sector = i;
      hardnested_src_key_type = MC_AUTH_B;
      memcpy(hardnested_src_key, t.sectors[i].KeyB, sizeof(t.sectors[i].KeyB));
      break;
    }
    i--;
  }

  for (i = 0; i < t.num_sectors; i++) {
    if (!t.sectors[i].foundKeyA) {
      if (!mfnestedhard(hardnested_src_sector, hardnested_src_key_type, hardnested_src_key, i, MC_AUTH_A))
        goto out;
      hardnested_runs++;
      memcpy(mp.mpa.abtKey, hardnested_broken_key, sizeof(hardnested_broken_key));
      if (!mf_configure(r.pdi))
        goto out;
      if (!mf_select_tag(t, r))
        goto out;
      test_key_res = test_keys(&mp, false, false);
      if (test_key_res < 0)
        goto out;
      if (!test_key_res) {
        printf("Hardnested found the wrong key, please report bug!\n");
        goto out;
      }
      remaining_keys_to_be_found -= test_key_res;
      // Print overall status
      printf("%u/%u keys have been cracked!\n", remaining_keys_to_be_found_before_hardnested - remaining_keys_to_be_found, remaining_keys_to_be_found_before_hardnested);
      if (remaining_keys_to_be_found)
        printf("The ETA to crack the remaining encryption keys is %u minutes.\n", (uint16_t)remaining_keys_to_be_found * 5);
    }

    if (!t.sectors[i].foundKeyB) {
      if (!mfnestedhard(hardnested_src_sector, hardnested_src_key_type, hardnested_src_key, i, MC_AUTH_B))
        goto out;
      hardnested_runs++;
      memcpy(mp.mpa.abtKey, hardnested_broken_key, sizeof(hardnested_broken_key));
      if (!mf_configure(r.pdi))
        goto out;
      if (!mf_select_tag(t, r))
        goto out;
      test_key_res = test_keys(&mp, false, false);
      if (test_key_res < 0)
        goto out;
      if (!test_key_res) {
        printf("Hardnested found the wrong key, please report bug!\n");
        goto out;
      }
      remaining_keys_to_be_found -= test_key_res;
      // Print overall status
      printf("%u/%u keys have been cracked!\n", remaining_keys_to_be_found_before_hardnested - remaining_keys_to_be_found, remaining_keys_to_be_found_before_hardnested);
      if (remaining_keys_to_be_found)
        printf("The ETA to crack the remaining encryption keys is %u minutes.\n", (uint16_t)remaining_keys_to_be_found * 5);
    }

    if (!remaining_keys_to_be_found)
      break;
  }

read_tag:
  if (t.num_sectors == NR_TRAILERS_1k)
    printf("All keys found! Reading the tag.\n");
  else
    printf("All keys found! Reading the tag, please wait up to 6s.\n");

  i = t.num_sectors; // Sector counter
  // Read all blocks
  for (block = t.num_blocks; block >= 0; block--) {
    is_trailer_block(block) ? i-- : i;

    // Three possibility of mfoc_nfc_initiator_mifare_cmd return code:
    // 0 success
    // NFC_ERFTRANS: Key is correct, but not enough privilege (Need to try another key)
    // Other negative value, something is not correct, go to out
    try_key_b = false;
    memcpy(mp.mpa.abtKey, t.sectors[i].KeyA, sizeof(t.sectors[i].KeyA));
    res_auth = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, block, &mp);
    if (!res_auth) {
      res_read = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_READ, block, &mp);
      if (!res_read) {
        printf("\r" WHITE_SPACE);
        printf("\r Read Block %u/%u with key A success!", block, t.num_blocks);
      } else if (res_read == NFC_ERFTRANS)
        try_key_b = true;
      else
        goto out;
    } else if (res_read == NFC_ERFTRANS)
      try_key_b = true;
    else {
      printf("\r" WHITE_SPACE);
      printf("\r Read Block %u/%u with key A failed!", block, t.num_blocks);
      goto out;
    }

    if (try_key_b) {
      memcpy(mp.mpa.abtKey, t.sectors[i].KeyB, sizeof(t.sectors[i].KeyB));
      if (mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, block, &mp)) {
        printf("\r" WHITE_SPACE);
        printf("\r Authentic Block %u/%u with key B failed!", block, t.num_blocks);
        goto out;
      }
      if (mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_READ, block, &mp)) {
        printf("\r" WHITE_SPACE);
        printf("\r Read Block %u/%u with key B failed!", block, t.num_blocks);
        goto out;
      }
    }

    memcpy(mtDump.amb[block].mbd.abtData, mp.mpd.abtData, 16);
    if (is_trailer_block(block)) {
      memcpy(mtDump.amb[block].mbt.abtKeyA, t.sectors[i].KeyA, 6);
      memcpy(mtDump.amb[block].mbt.abtKeyB, t.sectors[i].KeyB, 6);
    }
    // The last 2 bytes in Block 0 is used as a marker bytes for the target tag
    if (!block) {
      mtDump.amb[block].mbd.abtData[14] = 0;
      mtDump.amb[block].mbd.abtData[15] = 0;
    }
    memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
  }

  // Up till this point, we have read the tag successfully
  printf("\n");

  // Save the information to global buffer in order to feed into the write function
  if (t.nt.nti.nai.szUidLen == 4) {
    if (t.num_blocks == NR_BLOCKS_1k)
      last_read_mfc_type = MFC_TYPE_C14;
    else
      last_read_mfc_type = MFC_TYPE_C44;
  } else {
    if (t.num_blocks == NR_BLOCKS_1k)
      last_read_mfc_type = MFC_TYPE_C17;
    else
      last_read_mfc_type = MFC_TYPE_C47;
  }
  memcpy(last_read_uid, t.nt.nti.nai.abtUid, 7);

  if (!(pfDump = fopen(file_name, "wb"))) {
    fprintf(stderr, "Saving log file failed\n");
    return false;
  }

  // Finally save all keys + data to file
  if (pfDump) {
    uint16_t dump_size = (t.num_blocks + 1) * 16;
    if (fwrite(&mtDump, 1, dump_size, pfDump) != dump_size) {
      fprintf(stdout, "Error, cannot write dump\n");
      fclose(pfDump);
      return false;
    }
    fclose(pfDump);
    read_success = true;
  }

out:
  // Reset the "advanced" configuration to normal
  nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true);
  nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true);

  printf("\n");

  if (hardnested_runs)
    printf("Total hardnested key crack runs performed: %u.\n", hardnested_runs);
  printf("Total time elapsed reading this tag: %llu s.\n", (msclock() - start_time) / 1000);

  if (read_success) {
    printf("\nRead tag success!\n");
    return true;
  } else {
    printf("\nRead tag fail!\n");
    return false;
  }
}

static bool load_mfc_file(char *file_name)
{
  uint16_t total_blocks;
  uint8_t uid_len;
  uint8_t i;
  if (file_name[0] != 'C')
    return false;
  if (file_name[1] == '1')
    total_blocks = NR_BLOCKS_1k + 1;
  else if (file_name[1] == '4')
    total_blocks = NR_BLOCKS_4k + 1;
  else
    return false;
  if (file_name[2] == '4')
    uid_len = 4;
  else if (file_name[2] == '7')
    uid_len = 7;
  else
    return false;

  // Sanity check the UID part to see if they are valid number or hex
  for (i = 0; i < uid_len * 2; i++) {
    if (!isxdigit(file_name[3 + i]))
      return false;
  }
  // Parse UID from the file name into last_read_uid
  for (i = 0; i < uid_len; i++) {
    if (sscanf(file_name + 3 + i * 2, "%2hhx", last_read_uid + i) != 1)
      return false;
  }

  // Load the content into mtDump
  // First need to patch the file_name as the last entry of the file_name may be a carriage return instead of a 0
  if (uid_len == 4)
    file_name[15] = 0;
  else
    file_name[21] = 0;
  FILE *pfDump = fopen(file_name, "rb");
  if (pfDump == NULL) {
    printf("Unable to find file\n");
    return false;
  }

  if (fread(&mtDump, 1, total_blocks * sizeof(mifare_classic_block), pfDump) != total_blocks * sizeof(mifare_classic_block)) {
    printf("File is corrupted\n");
    fclose(pfDump);
    return false;
  }
  fclose(pfDump);

  // Set global variables
  if (uid_len == 4) {
    if (total_blocks == NR_BLOCKS_1k + 1)
      last_read_mfc_type = MFC_TYPE_C14;
    else
      last_read_mfc_type = MFC_TYPE_C44;
  } else {
    if (total_blocks == NR_BLOCKS_1k + 1)
      last_read_mfc_type = MFC_TYPE_C17;
    else
      last_read_mfc_type = MFC_TYPE_C47;
  }
  return true;
}

// If the force flag is not set, will only clean tags with the Block 0 last 2 bytes with e1 and e2
bool write_mfc(bool force, char *file_name)
{
  int tag_count;
  int res;
  uint8_t abtCmd[21] = { 0x30, 0x00 }; // Gen 3 Magic command for reading Block 0
  uint8_t abtRx[16] = { 0 };

  // If the file_name starts with C, that indicates a MIFARE Classic binary file is parsed in
  // Try to load this file into the global buffer, if loading file failed, stop writing the file
  if (file_name[0] == 'C') {
    if (!load_mfc_file(file_name)) {
      printf("Unable to open %s\n", file_name);
      return false;
    }
  }

  if (!mf_configure(r.pdi))
    return false;

  if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    return false;
  } else if (tag_count == 0) {
    ERR("No tag found.");
    return false;
  }

  // Check and make sure the target tag type matches the source tag type
  // Check if the last read result is successfull
  if (last_read_mfc_type == MFC_TYPE_INVALID) {
    printf("Please read your original tag first before write to a new tag.\n");
    return false;
  }

  // Check if the capacity matches
  if (t.nt.nti.nai.btSak == 0x08 || t.nt.nti.nai.btSak == 0x88) {
    if (last_read_mfc_type == MFC_TYPE_C44 || last_read_mfc_type == MFC_TYPE_C47) {
      printf("Wrong type of tag detected, please use the same type of magic tag as the original tag.\n");
      return false;
    }
  } else if (t.nt.nti.nai.btSak == 0x18) {
    if (last_read_mfc_type == MFC_TYPE_C14 || last_read_mfc_type == MFC_TYPE_C17) {
      printf("Wrong type of tag detected, please use the same type of magic tag as the original tag.\n");
      return false;
    }
  } else {
    printf("Wrong type of tag detected, please use the same type of magic tag as the original tag.\n");
    return false;
  }

  // Check if the UID length matches
  if (t.nt.nti.nai.szUidLen == 4) {
    if (last_read_mfc_type == MFC_TYPE_C17 || last_read_mfc_type == MFC_TYPE_C47) {
      printf("Wrong type of tag detected, please use the same type of magic tag as the original tag.\n");
      return false;
    }
  } else if (t.nt.nti.nai.szUidLen == 7) {
    if (last_read_mfc_type == MFC_TYPE_C14 || last_read_mfc_type == MFC_TYPE_C44) {
      printf("Wrong type of tag detected, please use the same type of magic tag as the original tag.\n");
      return false;
    }
  } else {
    printf("Software bug detected, please report bug.\n");
    return false;
  }

  // Use raw send/receive methods
  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(r.pdi, "nfc_configure");
    return false;
  }

  // Send Gen3 Magic command to see if the tag is a Gen3 magic
  // Using default timeout
  res = nfc_initiator_transceive_bytes(r.pdi, abtCmd, 2, abtRx, sizeof(abtRx), -1);
  // Magic Gen 3 tag
  if (res == 16) {
    if (!force) {
      if ((abtRx[14] != 0xe1) || (abtRx[15] != 0xe2)) {
        printf("Tag is not supported\n");
        return false;
      }
    }
    // Check if the tag is a blank tag by checking Block 0's UID memory
    for (uint8_t i = 0; i < t.nt.nti.nai.szUidLen; i++) {
      if (t.nt.nti.nai.abtUid[i] != 0) {
        if (!clean_mfc(force))
          return false;
        else
          break;
      }
    }

    // Gen3 magic use special command to write Block 0
    memset(abtCmd, 0, sizeof(abtCmd));
    memcpy(abtCmd, "\x90\xf0\xcc\xcc\x10", 5);
    memcpy(abtCmd + 5, mtDump.amb[0].mbd.abtData, 14);
    if (last_read_mfc_type == MFC_TYPE_C17 || last_read_mfc_type == MFC_TYPE_C47)
      memcpy(abtCmd + 5, last_read_uid, 7);
    else
      memcpy(abtCmd + 5, last_read_uid, 4);
    memcpy(abtCmd + 5 + 14, "\xe1\xe2", 2);

    if (!mf_configure(r.pdi))
      return false;

    if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
      nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
      return false;
    } else if (tag_count == 0) {
      ERR("No tag found.");
      return false;
    }

    if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
      nfc_perror(r.pdi, "nfc_configure");
      return false;
    }
    res = nfc_initiator_transceive_bytes(r.pdi, abtCmd, sizeof(abtCmd), NULL, 0, 2000);
    // Must keep the RF field on for at least 1 second for the tag to complete initialization
    // even after we have alreagy got a response from the tag.
    // Failure to do so, will brick the tag
    Sleep(1000);
    if (res == 2) {
      printf("Start writing to the Magic tag, please wait up to 5s\n");
      if (!write_blank_gen3()) {
        printf("Write to a new tag failed\n");
        return false;
      } else {
        printf("Write to a Magic tag success!\n");
        return true;
      }
    } else {
      printf("Block 0 write failed. res = %d\n", res);
      return false;
    }

    return true;
  } else {
    // All gen 2 magic tags are MFC_TYPE_C14 tags
    if (last_read_mfc_type != MFC_TYPE_C14) {
      printf("Unsupported tag!\n");
      return false;
    }
    // Always clean the tag before write
    // The clean function also ensure the tag is a supported magic tag
    if (!clean_mfc(force))
      return false;
    if (!write_blank_gen2()) {
      printf("Write to a new tag failed\n");
      return false;
    } else {
      printf("Write to a Magic tag success!\n");
      return true;
    }
  }
}

// If the force flag is not set, will only clean tags with the Block 0 last 2 bytes with e1 and e2
bool clean_mfc(bool force)
{
  int tag_count;
  int res;
  uint8_t abtCmd[21] = { 0x30, 0x00 }; // Gen 3 Magic command for reading Block 0
  uint8_t abtRx[16] = { 0 };
  uint8_t i;

  if (!mf_configure(r.pdi))
    return false;

  // Initialize t.sectors, keys are not known yet
  memset(&t, 0, sizeof(t));

  if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    return false;
  } else if (tag_count == 0) {
    ERR("No tag found.");
    return false;
  }

  // Use raw send/receive methods
  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(r.pdi, "nfc_configure");
    return false;
  }

  // Send Gen3 Magic command to see if the tag is a Gen3 magic
  // Using default timeout
  res = nfc_initiator_transceive_bytes(r.pdi, abtCmd, 2, abtRx, sizeof(abtRx), -1);
  // Magic Gen 3 tag
  if (res == 16) {
    if (!force) {
      if ((abtRx[14] != 0xe1) || (abtRx[15] != 0xe2)) {
        printf("Tag is not supported\n");
        return false;
      }
    }
    // Simply write all 0s + the last 2 marker bytes into the Magic Gen 3 tag.
    // When changing the Block 0, the 1st 4 or 7 bytes are the UID, the rest bytes can be any value
    // When changing the Block 0, the whole tag is resetted to factory default (including the keys)
    // Magic preamble to write Block 0 and rest tag is 90F0CCCC10
    memset(abtCmd, 0, sizeof(abtCmd));
    memcpy(abtCmd, "\x90\xf0\xcc\xcc\x10", 5);
    memcpy(abtCmd + 5 + 14, "\xe1\xe2", 2);

    if (!mf_configure(r.pdi))
      return false;

    if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
      nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
      return false;
    } else if (tag_count == 0) {
      ERR("No tag found.");
      return false;
    }

    if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
      nfc_perror(r.pdi, "nfc_configure");
      return false;
    }
    res = nfc_initiator_transceive_bytes(r.pdi, abtCmd, sizeof(abtCmd), NULL, 0, 2000);
    // Must keep the RF field on for at least 1 second for the tag to complete initialization
    // even after we have alreagy got a response from the tag.
    // Failure to do so, will brick the tag
    Sleep(1000);
    if (res == 2) {
      printf("Clean a Gen 3 MIFARE Classic tag successfully!\n");
      return true;
    } else {
      printf("Clean a Gen 3 MIFARE Classic tag failed. res = %d\n", res);
      return false;
    }
    return true;
  } else {
    if (t.nt.nti.nai.szUidLen != 4 || t.nt.nti.nai.btSak != 0x08) {
      printf("Unsupported tag!\n");
      return false;
    }

    t.authuid = (uint32_t)bytes_to_num(t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);
    t.num_sectors = NR_TRAILERS_1k;
    t.num_blocks = NR_BLOCKS_1k;

    int remaining_keys_to_be_found = t.num_sectors;
    int remaining_keys_to_be_found_before_hardnested;
    int test_key_res;

    // Try to check keys for sector 0 in order to read Block 0
    static mifare_param mp;
    memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
    if (!mf_select_tag(t, r))
      return false;
    for (i = 0; i < sizeof(defaultKeys) / sizeof(defaultKeys[0]); i++) {
      memcpy(mp.mpa.abtKey, defaultKeys[i], 6);
      test_key_res = test_keys(&mp, true, true);
      if (test_key_res > 0)
        remaining_keys_to_be_found -= test_key_res;
    }

    if (!t.sectors[0].foundKeyA) {
      printf("Unsupported tag!\n");
      return false;
    }

    // Read Block 0
    memcpy(mp.mpa.abtKey, t.sectors[0].KeyA, sizeof(t.sectors[0].KeyA));
    if (mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, 0, &mp)) {
      printf("Failed to authenticate Block 0!\n");
      return false;
    }

    if (mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_READ, 0, &mp)) {
      printf("Failed to read Block 0!\n");
      return false;
    }

    uint8_t block_0[16];
    memcpy(block_0, mp.mpd.abtData, 16);

    // Inspect if the last 2 bytes are e1 e2
    if (!force) {
      if (block_0[14] != 0xe1 || block_0[15] != 0xe2) {
        printf("Unsupported tag!\n");
        return false;
      }
    }
    // Write the same data back to check if the tag is a Magic Gen 2 tag
    if (!mf_select_tag(t, r))
      return false;

    memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
    memcpy(mp.mpa.abtKey, t.sectors[0].KeyA, sizeof(t.sectors[0].KeyA));
    if (!nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, 0, &mp)) {
      printf("Authentication error\n");
      return false;
    }

    memcpy(mp.mpd.abtData, block_0, 16);
    if (!nfc_initiator_mifare_cmd(r.pdi, MC_WRITE, 0, &mp)) {
      printf("Tag not supported\n");
      return false;
    }

    printf("Gen 2 Magic tag detected.\n");

    if (!force) {
      for (i = 0; i < 4; i++) {
        if (t.nt.nti.nai.abtUid[i])
          goto crack_key;
      }
      printf("Blank tag detected.\n");
      return true;
    }

  crack_key:
    // Check keys for non-Sector 0. For 1K 4-Byte UID MIFARE Classic tags, we don't need to check dictionary as
    // non of the tags we have seen use fixed keys
    memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
    if (!mf_select_tag(t, r))
      return false;
    memcpy(mp.mpa.abtKey, defaultKeys[0], sizeof(defaultKeys[0]));
    test_key_res = test_keys(&mp, false, true);
    if (test_key_res > 0)
      remaining_keys_to_be_found -= test_key_res;

    if (remaining_keys_to_be_found) {
      printf("This tag is encrypted with %u encryption keys.\n", remaining_keys_to_be_found);
      printf("The ETA to crack all the encryption keys is %u minutes.\n", (uint16_t)remaining_keys_to_be_found * 5);

      remaining_keys_to_be_found_before_hardnested = remaining_keys_to_be_found;

      // Use hardnested to crack the unknown keys
      uint8_t hardnested_src_sector;
      uint8_t hardnested_src_key_type;
      uint8_t hardnested_src_key[6];
      i = t.num_sectors - 1;
      while (true) {
        if (t.sectors[i].foundKeyA) {
          hardnested_src_sector = i;
          hardnested_src_key_type = MC_AUTH_A;
          memcpy(hardnested_src_key, t.sectors[i].KeyA, sizeof(t.sectors[i].KeyA));
          break;
        }
        i--;
      }

      for (i = 0; i < t.num_sectors; i++) {
        if (!t.sectors[i].foundKeyA) {
          if (!mfnestedhard(hardnested_src_sector, hardnested_src_key_type, hardnested_src_key, i, MC_AUTH_A)) {
            printf("Clean tag failed at hardnested\n");
            return false;
          }
          memcpy(mp.mpa.abtKey, hardnested_broken_key, sizeof(hardnested_broken_key));
          if (!mf_configure(r.pdi))
            return false;
          if (!mf_select_tag(t, r))
            return false;
          test_key_res = test_keys(&mp, false, true);
          if (test_key_res < 0)
            return false;
          if (!test_key_res) {
            printf("Hardnested found the wrong key, please report bug!\n");
            return false;
          }
          remaining_keys_to_be_found -= test_key_res;
          // Print overall status
          printf("%u/%u keys have been cracked!\n", remaining_keys_to_be_found_before_hardnested - remaining_keys_to_be_found, remaining_keys_to_be_found_before_hardnested);
          if (remaining_keys_to_be_found)
            printf("The ETA to crack the remaining encryption keys is %u minutes.\n", (uint16_t)remaining_keys_to_be_found * 5);
        }

        if (!remaining_keys_to_be_found)
          break;
      }
    }

    // As of here, we have the Key A for all the sectors
    if (!mf_configure(r.pdi))
      return false;

    if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) <= 0) {
      printf("Error: tag was removed\n");
      return false;
    }
    for (i = 1; i <= t.num_blocks; i++) {
      if (i == 1 || is_first_block(i)) {
        memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);
        memcpy(mp.mpa.abtKey, t.sectors[get_sector_num_from_block_num(i)].KeyA, 6);
        if (!nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, i, &mp)) {
          printf("Authentication error\n");
          return false;
        }
      }
      if (is_trailer_block(i))
        memcpy(mp.mpd.abtData, default_trailer_block, sizeof(default_trailer_block));
      else
        memcpy(mp.mpd.abtData, default_data_block, sizeof(default_data_block));
      if (!nfc_initiator_mifare_cmd(r.pdi, MC_WRITE, i, &mp)) {
        printf("Failed at writing block %d \n", i);
        return false;
      }
    }

    // Write Block 0
    memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);
    memcpy(mp.mpa.abtKey, default_key, sizeof(default_key));
    if (!nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, 0, &mp)) {
      printf("Authentication error\n");
      return false;
    }
    uint8_t blank_gen2_block0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe1, 0xe2 };
    memcpy(mp.mpd.abtData, blank_gen2_block0, sizeof(blank_gen2_block0));
    if (!nfc_initiator_mifare_cmd(r.pdi, MC_WRITE, 0, &mp)) {
      printf("Failed at writing block 0 \n");
      return false;
    }

    printf("Clean a Gen 2 MIFARE Classic tag successfully!\n");
    return true;
  }
}

int main(int argc, char *const argv[])
{
  char line[3 + MAX_FILE_LEN] = { 0 }; // Leading command + space + carriage return = need extra 3 bytes

  // Print banner and version
  printf("PN532 Cloner     Ver: " PN532_CLONER_VER "\n");
  printf("https://github.com/jumpycalm/pn532-cloner\n");

  while (true) {
    // Before performing any task, alway call mf_init() to check if the reader is connected
    if (!mf_init(&r)) {
      getchar();
      continue;
    }

    pn532_cloner_usage();

    fgets(line, sizeof(line), stdin);
    if (line[0] == 'r' || line[0] == 'R')
      read_mfc();
    else if (line[0] == 'w' || line[0] == 'W') {
      if (line[2] == 'F' || line[2] == 'f')
        write_mfc(true, line + 2);
      else
        write_mfc(false, line + 2);
    } else if (line[0] == 'c' || line[0] == 'C') {
      if (line[2] == 'F' || line[2] == 'f')
        clean_mfc(true);
      else
        clean_mfc(false);
    } else if (line[0] == 'E' || line[0] == 'e')
      break;

    nfc_close(r.pdi);
    nfc_exit(context);
  }
  return 0;
}

bool mf_init(mfreader *r)
{
  // Connect to the first NFC device
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    return false;
  }
  r->pdi = nfc_open(context, NULL);
  if (!r->pdi) {
    printf("Unable to find NXP PN532 reader.\n");
    printf("Please ensure the reader is connected to the PC and the reader is detected as a serial port.\n");
    printf("Press any key to retry...\n");
    return false;
  }
  return true;
}

bool mf_configure(nfc_device *pdi)
{
  if (nfc_initiator_init(pdi) < 0) {
    printf("nfc_initiator_init\n");
    return false;
  }
  // Drop the field for a while, so can be reset
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, false) < 0) {
    printf("nfc_device_set_property_bool activate field\n");
    return false;
  }
  // Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pdi, NP_INFINITE_SELECT, false) < 0) {
    printf("nfc_device_set_property_bool infinite select\n");
    return false;
  }
  // Configure the CRC and Parity settings
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_CRC, true) < 0) {
    printf("nfc_device_set_property_bool crc\n");
    return false;
  }
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_PARITY, true) < 0) {
    printf("nfc_device_set_property_bool parity\n");
    return false;
  }
  // Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
  if (nfc_device_set_property_bool(pdi, NP_AUTO_ISO14443_4, false) < 0) {
    printf("nfc_device_set_property_bool\n");
    return false;
  }
  // Enable the field so more power consuming cards can power themselves up
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, true) < 0) {
    printf("nfc_device_set_property_bool activate field\n");
    return false;
  }
  return true;
}

bool mf_select_tag(mftag t, mfreader r)
{
  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) < 0) {
    printf("Unable to select the tag. Possible the tag has been removed.\n");
    return false;
  }
  return true;
}

bool get_rats_is_2k(mftag t, mfreader r)
{
  int res;
  uint8_t abtRx[MAX_FRAME_LEN];
  uint8_t abtRats[2] = { 0xe0, 0x50 };
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(r.pdi, "nfc_configure");
    return false;
  }
  res = nfc_initiator_transceive_bytes(r.pdi, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0);
  if (res > 0) {
    // ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
    if (nfc_device_set_property_bool(r.pdi, NP_ACTIVATE_FIELD, false) < 0) {
      nfc_perror(r.pdi, "nfc_configure");
      return false;
    }
    if (nfc_device_set_property_bool(r.pdi, NP_ACTIVATE_FIELD, true) < 0) {
      nfc_perror(r.pdi, "nfc_configure");
      return false;
    }
  }
  // Reselect tag
  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) <= 0) {
    printf("Error: tag disappeared\n");
    nfc_close(r.pdi);
    nfc_exit(context);
    return false;
  }
  if (res >= 10) {
    printf("ATS %02X%02X%02X%02X%02X|%02X%02X%02X%02X%02X\n", res, abtRx[0], abtRx[1], abtRx[2], abtRx[3], abtRx[4], abtRx[5], abtRx[6], abtRx[7], abtRx[8]);
    return ((abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
        && (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
        && ((t.nt.nti.nai.abtAtqa[1] & 0x02) == 0x00));
  } else {
    // printf("ATS len = %d\n", res);
    return false;
  }
}

void num_to_bytes(uint64_t n, uint32_t len, uint8_t *dest)
{
  while (len--) {
    dest[len] = (uint8_t)n;
    n >>= 8;
  }
}

long long unsigned int bytes_to_num(uint8_t *src, uint32_t len)
{
  uint64_t num = 0;
  while (len--) {
    num = (num << 8) | (*src);
    src++;
  }
  return num;
}
