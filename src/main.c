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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <windows.h> //Sleep
#include <sys/stat.h>   // stat
#ifdef _MSC_VER
#include "unistd_w.h"
#include "getopt.h"
#else
#include <unistd.h>
#endif

// NFC
#include "nfc.h"

// Crapto1
#include "crapto1.h"

// Internal
#include "mifare.h"
#include "nfc-utils.h"
#include "main.h"

//SLRE 
#include "slre.h"
#include "hardnested.h"

#define MAX_FRAME_LEN 264
#define MAX_FILE_LEN 22 // 3 leading chars as type, followed by up to 7-byte UID (14 chars), followed by .bin and ending char (5 chars)

#define PN532_CLONER_VER "0.1.0"

mftag    t;
mfreader r;
uint8_t hardnested_broken_key[6];

static const nfc_modulation nm = {
.nmt = NMT_ISO14443A,
.nbr = NBR_106,
};

nfc_context *context;

uint64_t knownKey = 0;
char knownKeyLetter = 'A';
uint32_t knownSector = 0;
uint32_t unknownSector = 0;
char unknownKeyLetter = 'A';
uint32_t unexpected_random = 0;

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


static const uint8_t default_key[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t blank_key[6] = { 0 };
static const uint8_t default_acl[] = {0xff, 0x07, 0x80, 0x69};
static const uint8_t default_data_block[16] = { 0 };
static const uint8_t default_trailer_block[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


static void pn532_cloner_usage()
{
  printf("\n\n\n");
  printf("###################################################################################\n");
  printf("Usage:\n");
  printf("r             - (R)ead a tag\n");
  printf("w             - (W)rite to a magic tag using the data from the most recent read tag\n");
  printf("w <File name> - (W)rite to a magic tag using the data from a saved dump file\n");
  printf("c             - (C)lean/Restore a magic tag to the factory default\n");
  printf("r             - (E)xit\n");
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
int8_t test_keys(mifare_param *mp)
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
        if (!mf_anticollision(t, r))
          return -1;
      } else {
        // Save all information about successfull keyA authentization
        memcpy(t.sectors[i].KeyA, mp->mpa.abtKey, sizeof(mp->mpa.abtKey));
        t.sectors[i].foundKeyA = true;
        num_of_exploited_keys++;
        just_found_key_a = true;
      }
    }
    // Logic for testing Key B
    if (!t.sectors[i].foundKeyB) {
      if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, current_block, mp)) < 0) {
        if (res != NFC_EMFCAUTHFAIL) {
          nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
          return -1;
        }
        if (!mf_anticollision(t, r))
          return -1;
      } else {
        memcpy(t.sectors[i].KeyB, mp->mpa.abtKey, sizeof(mp->mpa.abtKey));
        t.sectors[i].foundKeyB = true;
        num_of_exploited_keys++;
      }
    }
    // Logic for trying to get Key B by reading the trailer block
    // Because for comercial application, this backdoor is sealed, the success rate is very low
    // Only perform this task if found Key A but not Key B
    // All the tags wrote by this application keep this back door open
    if (just_found_key_a && !t.sectors[i].foundKeyB) {
      if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, current_block, mp)) < 0) {
        if (res != NFC_EMFCAUTHFAIL) {
          nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
          return -1;
        }
        if (!mf_anticollision(t, r))
          return -1;
      } else {
        if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_READ, current_block, &mp_tmp)) >= 0) {
          if (!memcmp(mp_tmp.mpd.abtData + 10, blank_key, sizeof(blank_key)))
            continue;

          memcpy(mp->mpa.abtKey, mp_tmp.mpd.abtData + 10, sizeof(mp_tmp.mpa.abtKey));
          if ((mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, current_block, mp)) < 0) {
            mf_configure(r.pdi);
            if (!mf_anticollision(t, r))
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
          if (!mf_anticollision(t, r))
            return -1;
        }
      }
    }

    // Save position of a trailer block to sector struct
    t.sectors[i].trailer = current_block;
  }
  //printf("Debug! num_of_exploited_keys = %d\n", num_of_exploited_keys);
  return num_of_exploited_keys;
}

bool if_tag_is_blank(nfc_iso14443a_info tag_info)
{
  for (uint8_t i = 0; i < tag_info.szUidLen; i ++)
    if (tag_info.abtUid[i])
      return false;
  return true;
}

uint8_t get_trailer_block_num_from_sector_num(uint8_t sector_num)
{
  if (sector_num < 32)
    return sector_num * 4 + 3;
  else
    return (sector_num - 32) * 16 + 143;
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

static uint16_t get_leading_block(uint16_t block)
{
  // Test if we are in the small or big sectors
  if (block < 128)
    return block / 4 * 4 ;
  else
    return block / 16 * 16;
}

// Calculate if we reached the 1st block that needs authentication
static bool if_need_authenticate(uint16_t current_block)
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
  if (get_leading_block(current_block) == current_block)
    return true;
  // If the current block is not the leading block, we need to check if there's any block before this block is not default
  for (i = current_block - 1; i >= get_leading_block(current_block); i--) {
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

// Write to a MFC tag that has been initialized to factory default
bool write_blank_mfc(bool write_block_zero)
{
  uint32_t current_block = 0;
  uint32_t total_blocks = NR_BLOCKS_1k + 1;
  mifare_param mp;

  if (!write_block_zero)
    current_block = 1;

  // Check to see if we have a success read
  if (last_read_mfc_type == MFC_TYPE_INVALID) {
    printf("Please read your original tag first before write to a new tag\n");
    return false;
  } else if (last_read_mfc_type == MFC_TYPE_C44 || last_read_mfc_type == MFC_TYPE_C47)
    total_blocks = NR_BLOCKS_4k + 1;

  // Sanitize the buffer in case the buffer is not sanitized
  // Failure to do so may brick the tag if loading a dump file not from this application
  sanitize_mfc_buffer();

  mf_configure(r.pdi);

  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) <= 0) {
    printf("Error: tag was removed\n");
    return false;
  }

  // Completely write the card, but skipping block 0 if we don't need to write on it
  for (; current_block < total_blocks; current_block++) {
    // Authenticate everytime we reach new block and need to actually write a data on
    if (if_need_authenticate(current_block)) {
      //printf("Block %u needs authentication\n", current_block);
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
      //printf("Block %u write success.\n", current_block);
    }
  }

  return true;
}

// Changing Block 0 or configuration block may brick some tags
// This function will set Block 0 to all 0s and set all the configuration blocks with the default access bits
void sanitize_mfc_buffer(void)
{
  memset(&mtDump, 0, sizeof(mifare_classic_block));
  for (uint16_t i = 3; i < NR_BLOCKS_4k; i+=4) {
    if (is_trailer_block(i)) {
      memcpy(mtDump.amb[i].mbt.abtAccessBits, default_acl, sizeof(default_acl));
    }
  }
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

  // Array with default Mifare Classic keys
  uint8_t defaultKeys[][6] = {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Default key (first key used by program if no user defined key)
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // NFCForum MAD key
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // NFCForum content key
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Blank key
  };

  static mifare_param mp;

  FILE *pfDump = NULL;

  last_read_mfc_type = MFC_TYPE_INVALID; // Always assume read is failed before performing the read

  mf_configure(r.pdi);

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

  t.authuid = (uint32_t) bytes_to_num(t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);

  // Get Mifare Classic type from SAK
  // see http://www.nxp.com/documents/application_note/AN10833.pdf Section 3.2
  switch (t.nt.nti.nai.btSak)
  {
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

  t.sectors = (void *) calloc(t.num_sectors, sizeof(sector));
  if (t.sectors == NULL) {
    ERR("Cannot allocate memory for t.sectors");
    return false;
  }

  // Initialize t.sectors, keys are not known yet
  for (uint8_t s = 0; s < (t.num_sectors); ++s) {
    t.sectors[s].foundKeyA = t.sectors[s].foundKeyB = false;
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

  print_nfc_target(&t.nt, true);

  // Test the default keys
  remaining_keys_to_be_found = t.num_sectors * 2;
  memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
  printf("\nChecking encryption keys, please wait up to 33s\n");
  for (i = 0; i < sizeof(defaultKeys) / sizeof(defaultKeys[0]); i++) {
    memcpy(mp.mpa.abtKey, defaultKeys[i], sizeof(defaultKeys[i]));
    test_key_res = test_keys(&mp);
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
  
  printf("This tag is encrypted by %u encryption keys.\n", remaining_keys_to_be_found);
  printf("The ETA to crack all the encryption key is %u minutes.\n", (uint16_t)remaining_keys_to_be_found * 8);
  remaining_keys_to_be_found_before_hardnested = remaining_keys_to_be_found;

  // Use hardnested to crack the unknown keys
  uint8_t hardnested_src_block;
  uint8_t hardnested_src_key_type;
  uint8_t hardnested_src_key[6];
  i = t.num_sectors - 1;
  while(true) {
    if (t.sectors[i].foundKeyA) {
      hardnested_src_block = get_trailer_block_num_from_sector_num(i);
      hardnested_src_key_type = MC_AUTH_A;
      memcpy(hardnested_src_key, t.sectors[i].KeyA, sizeof(t.sectors[i].KeyA));
      break;
    }
    if (t.sectors[i].foundKeyB) {
      hardnested_src_block = get_trailer_block_num_from_sector_num(i);
      hardnested_src_key_type = MC_AUTH_B;
      memcpy(hardnested_src_key, t.sectors[i].KeyB, sizeof(t.sectors[i].KeyB));
      break;
    }
    i--;
  }

  for (i = 0; i < t.num_sectors; i++) {
    if (!t.sectors[i].foundKeyA) {
      mf_configure(r.pdi);
      if (!mf_anticollision(t, r))
          goto out;
      if (!mfnestedhard(hardnested_src_block, hardnested_src_key_type, hardnested_src_key, get_trailer_block_num_from_sector_num(i), MC_AUTH_A))
        goto out;
      memcpy(mp.mpa.abtKey, hardnested_broken_key, sizeof(hardnested_broken_key));
      test_key_res = test_keys(&mp);
      if (test_key_res < 0)
        goto out;
      else
        remaining_keys_to_be_found -= test_key_res;
      // Print overall status
      printf("%u/%u keys have been cracked!\n", remaining_keys_to_be_found, remaining_keys_to_be_found_before_hardnested);
    }

    if (!t.sectors[i].foundKeyB) {
      mf_configure(r.pdi);
      if (!mf_anticollision(t, r))
          goto out;
      if (!mfnestedhard(hardnested_src_block, hardnested_src_key_type, hardnested_src_key, get_trailer_block_num_from_sector_num(i), MC_AUTH_B))
        goto out;
      memcpy(mp.mpa.abtKey, hardnested_broken_key, sizeof(hardnested_broken_key));
      test_key_res = test_keys(&mp);
      if (test_key_res < 0)
        goto out;
      else
        remaining_keys_to_be_found -= test_key_res;
      // Print overall status
      printf("%u/%u keys have been cracked!\n", remaining_keys_to_be_found_before_hardnested - remaining_keys_to_be_found, remaining_keys_to_be_found_before_hardnested);
    }

    if (!remaining_keys_to_be_found)
      break;
  }

  printf("All keys found! Reading the tag, please wait up to 10s\n");

read_tag:
  i = t.num_sectors; // Sector counter
  // Read all blocks
  for (block = t.num_blocks; block >= 0; block--) {
    is_trailer_block(block) ? i-- : i;

    // Try A key, auth() + read()
    memcpy(mp.mpa.abtKey, t.sectors[i].KeyA, sizeof(t.sectors[i].KeyA));
    int res;
    if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_A, block, &mp)) < 0) {
      if (res != NFC_EMFCAUTHFAIL) {
        nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
        goto out;
      }
      mf_configure(r.pdi);
      if (!mf_anticollision(t, r))
        goto out;
    } else { // and Read
      if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_READ, block, &mp)) >= 0) {
        fprintf(stdout, "Block %02d, type %c, key %012llx :", block, 'A', bytes_to_num(t.sectors[i].KeyA, 6));
        print_hex(mp.mpd.abtData, 16);
        mf_configure(r.pdi);
        mf_select_tag(r.pdi, &(t.nt));
      } else {
        // Error, now try read() with B key
        if (res != NFC_ERFTRANS) {
          nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
          goto out;
        }
        mf_configure(r.pdi);
        if (!mf_anticollision(t, r))
          goto out;
        memcpy(mp.mpa.abtKey, t.sectors[i].KeyB, sizeof(t.sectors[i].KeyB));
        if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, block, &mp)) < 0) {
          if (res != NFC_EMFCAUTHFAIL) {
            nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
            goto out;
          }
          mf_configure(r.pdi);
          if (!mf_anticollision(t, r))
            goto out;
        } else { // and Read
          if ((res = mfoc_nfc_initiator_mifare_cmd(r.pdi, MC_READ, block, &mp)) >= 0) {
            fprintf(stdout, "Block %02d, type %c, key %012llx :", block, 'B', bytes_to_num(t.sectors[i].KeyB, 6));
            print_hex(mp.mpd.abtData, 16);
            mf_configure(r.pdi);
            mf_select_tag(r.pdi, &(t.nt));
          } else {
            if (res != NFC_ERFTRANS) {
              nfc_perror(r.pdi, "mfoc_nfc_initiator_mifare_cmd");
              return false;
            }
            mf_configure(r.pdi);
            if (!mf_anticollision(t, r))
              goto out;
            // ERR ("Error: Read B");
          }
        }
      }
    }
    if (is_trailer_block(block)) {
      // Copy the keys over from our key dump and store the retrieved access bits
      memcpy(mtDump.amb[block].mbt.abtKeyA, t.sectors[i].KeyA, 6);
      memcpy(mtDump.amb[block].mbt.abtKeyB, t.sectors[i].KeyB, 6);
      memcpy(mtDump.amb[block].mbt.abtAccessBits, default_acl, sizeof(default_acl)); // Never use the source tag's access bit to avoid breaking tags
    } else
      memcpy(mtDump.amb[block].mbd.abtData, mp.mpd.abtData, 16);
    memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
  }

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

  // Make sure to sanitize the buffer before logging it into a file
  sanitize_mfc_buffer();

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
  free(t.sectors);

  // Reset the "advanced" configuration to normal
  nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true);
  nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true);

  if (read_success) {
    printf("Read tag success!\n");
    return true;
  } else {
    printf("Read tag fail!\n");
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
// TODO: Only Gen 3 magic is supported at this moment. Add support for Gen 2 magic
bool write_mfc(bool force, char *file_name)
{
  int tag_count;
  int res;
  uint8_t abtCmd[21]={0x30, 0x00}; // Gen 3 Magic command for reading Block 0
  uint8_t abtRx[16]={0};

  // If the file_name starts with C, that indicates a MIFARE Classic binary file is parsed in
  // Try to load this file into the global buffer, if loading file failed, stop writing the file
  if (file_name[0] == 'C') {
    if (!load_mfc_file(file_name)) {
      printf("Unable to open %s\n", file_name);
      return false;
    }
  }

  mf_configure(r.pdi);
  
  if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    return false;
  } else if (tag_count == 0) {
    ERR("No tag found.");
    return false;
  }

  //Use raw send/receive methods
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
    // As of here, the tag is a blank tag and is ready for writting data on
    // Check if the last read result is successfull
    if (last_read_mfc_type == MFC_TYPE_INVALID) {
      printf("Please read your original tag first before write to a new tag\n");
      return false;
    }
    // Gen3 magic use special command to write Block 0
    memset(abtCmd, 0, sizeof(abtCmd));
    memcpy(abtCmd, "\x90\xf0\xcc\xcc\x10", 5);
    memcpy(abtCmd + 5, last_read_uid, 7);
    memcpy(abtCmd + 5 + 14, "\xe1\xe2", 2);

    mf_configure(r.pdi);
  
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
      if (!write_blank_mfc(false)) {
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
    printf("Non-Magic Gen 3 tag will be supported in the future release of software.");
    return false;
  }
}

// If the force flag is not set, will only clean tags with the Block 0 last 2 bytes with e1 and e2
// TODO: Only Gen 3 magic is supported at this moment. Add support for Gen 2 magic
bool clean_mfc(bool force)
{
  int tag_count;
  int res;
  uint8_t abtCmd[21]={0x30, 0x00}; // Gen 3 Magic command for reading Block 0
  uint8_t abtRx[16]={0};

  mf_configure(r.pdi);
  
  if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    return false;
  } else if (tag_count == 0) {
    ERR("No tag found.");
    return false;
  }

  //Use raw send/receive methods
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

    mf_configure(r.pdi);
  
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
      printf("Clean a MIFARE Classic tag successfully!\n");
      return true;
    } else {
      printf("Clean a MIFARE Classic tag failed. res = %d\n", res);
      return false;
    }
    return true;
  } else {
    printf("Non-Magic Gen 3 tag will be supported in the future release of software.");
    return false;
  }
}

int main(int argc, char *const argv[])
{
  char line[3 + MAX_FILE_LEN]= { 0 }; // Leading command + space + carriage return = need extra 3 bytes

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
    }
    else if (line[0] == 'c' || line[0] == 'C') {
      if (line[2] == 'F' || line[2] == 'f')
        clean_mfc(true);
      else
        clean_mfc(false);
    }
    else if (line[0] == 'E' || line[0] == 'e')
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

void mf_configure(nfc_device *pdi)
{
  if (nfc_initiator_init(pdi) < 0) {
    nfc_perror(pdi, "nfc_initiator_init");
    exit(EXIT_FAILURE);
  }
  // Drop the field for a while, so can be reset
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, false) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool activate field");
    exit(EXIT_FAILURE);
  }
  // Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pdi, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool infinite select");
    exit(EXIT_FAILURE);
  }
  // Configure the CRC and Parity settings
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_CRC, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool crc");
    exit(EXIT_FAILURE);
  }
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_PARITY, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool parity");
    exit(EXIT_FAILURE);
  }
  // Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
  if (nfc_device_set_property_bool(pdi, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool");
    exit(EXIT_FAILURE);
  }
  // Enable the field so more power consuming cards can power themselves up
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool activate field");
    exit(EXIT_FAILURE);
  }
}

void mf_select_tag(nfc_device *pdi, nfc_target *pnt)
{
  if (nfc_initiator_select_passive_target(pdi, nm, NULL, 0, pnt) < 0) {
    ERR("Unable to connect to the MIFARE Classic tag");
    nfc_close(pdi);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
}

// Return position of sector if it is encrypted with the default key otherwise exit..
int find_exploit_sector(mftag t)
{
  int i;
  bool interesting = false;

  for (i = 0; i < t.num_sectors; i++) {
    if (!t.sectors[i].foundKeyA || !t.sectors[i].foundKeyB) {
      interesting = true;
      break;
    }
  }
  if (!interesting) {
    fprintf(stdout, "\nWe have all sectors encrypted with the default keys..\n\n");
    return -1;
  }
  for (i = t.num_sectors-1; i>=0;--i) {
    if (t.sectors[i].foundKeyB) {
      fprintf(stdout, "\n\nUsing sector %02d as an exploit sector\n", i);
      return i;
    }
  }
  for (i = t.num_sectors-1; i>=0;--i) {
    if (t.sectors[i].foundKeyA) {
      fprintf(stdout, "\n\nUsing sector %02d as an exploit sector\n", i);
      return i;
    }
  }
  ERR("\n\nNo sector encrypted with the default key has been found, exiting..");
  exit(EXIT_FAILURE);
}

bool mf_anticollision(mftag t, mfreader r)
{
  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) < 0) {
    printf("Tag has been removed.\n");
    return false;
  }
  return true;
}


bool
get_rats_is_2k(mftag t, mfreader r)
{
  int res;
  uint8_t abtRx[MAX_FRAME_LEN];
  uint8_t  abtRats[2] = { 0xe0, 0x50};
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
    exit(EXIT_FAILURE);
  }
  if (res >= 10) {
    printf("ATS %02X%02X%02X%02X%02X|%02X%02X%02X%02X%02X\n", res, abtRx[0], abtRx[1], abtRx[2], abtRx[3], abtRx[4], abtRx[5], abtRx[6], abtRx[7], abtRx[8]);
    return ((abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
            && (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
            && ((t.nt.nti.nai.abtAtqa[1] & 0x02) == 0x00));
  } else {
    //printf("ATS len = %d\n", res);
    return false;
  }
}


// Return the median value from the nonce distances array
uint32_t median(denonce d)
{
  int middle = (int) d.num_distances / 2;
  qsort(d.distances, d.num_distances, sizeof(uint32_t), compar_int);

  if (d.num_distances % 2 == 1) {
    // Odd number of elements
    return d.distances[middle];
  } else {
    // Even number of elements, return the smaller value
    return (uint32_t)(d.distances[middle - 1]);
  }
}

int compar_int(const void *a, const void *b)
{
  return (*(uint64_t *)b - * (uint64_t *)a);
}

// Compare countKeys structure
int compar_special_int(const void *a, const void *b)
{
  return (((countKeys *)b)->count - ((countKeys *)a)->count);
}

// Return 1 if the nonce is invalid else return 0
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, uint8_t *parity)
{
  return ((odd_parity((Nt >> 24) & 0xFF) == ((parity[0]) ^ odd_parity((NtEnc >> 24) & 0xFF) ^ BIT(Ks1, 16))) & \
          (odd_parity((Nt >> 16) & 0xFF) == ((parity[1]) ^ odd_parity((NtEnc >> 16) & 0xFF) ^ BIT(Ks1, 8))) & \
          (odd_parity((Nt >> 8) & 0xFF) == ((parity[2]) ^ odd_parity((NtEnc >> 8) & 0xFF) ^ BIT(Ks1, 0)))) ? 1 : 0;
}

void num_to_bytes(uint64_t n, uint32_t len, uint8_t *dest)
{
  while (len--) {
    dest[len] = (uint8_t) n;
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
