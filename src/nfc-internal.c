/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2020      Adam Laurie
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/**
* @file nfc-internal.c
* @brief Provide some useful internal functions
*/

#include "nfc.h"
#include "nfc-internal.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define LOG_GROUP    NFC_LOG_GROUP_GENERAL
#define LOG_CATEGORY "libnfc.general"

void string_as_boolean(const char *s, bool *value)
{
  if (s) {
    if (!(*value)) {
      if ((strcmp(s, "yes") == 0) ||
          (strcmp(s, "true") == 0) ||
          (strcmp(s, "1") == 0)) {
        *value = true;
        return;
      }
    } else {
      if ((strcmp(s, "no") == 0) ||
          (strcmp(s, "false") == 0) ||
          (strcmp(s, "0") == 0)) {
        *value = false;
        return;
      }
    }
  }
}

nfc_context *nfc_context_new(void)
{
  nfc_context *res = malloc(sizeof(*res));

  if (!res) {
    return NULL;
  }

  // Set default context values
  res->allow_autoscan = true;
  res->allow_intrusive_scan = true;

  // Clear user defined devices array
  for (int i = 0; i < MAX_USER_DEFINED_DEVICES; i++) {
    strcpy(res->user_defined_devices[i].name, "");
    strcpy(res->user_defined_devices[i].connstring, "");
    res->user_defined_devices[i].optional = false;
  }
  res->user_defined_device_count = 0;

  // Debug context state
  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "%d device(s) defined by user", res->user_defined_device_count);
  for (uint32_t i = 0; i < res->user_defined_device_count; i++) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "  #%d name: \"%s\", connstring: \"%s\"", i, res->user_defined_devices[i].name, res->user_defined_devices[i].connstring);
  }
  return res;
}

void nfc_context_free(nfc_context *context)
{
  log_exit();
  free(context);
}

void prepare_initiator_data(const nfc_modulation nm, uint8_t **ppbtInitiatorData, size_t *pszInitiatorData)
{
  switch (nm.nmt) {
    case NMT_ISO14443B:
      // Application Family Identifier (AFI) must equals 0x00 in order to wakeup all ISO14443-B PICCs (see ISO/IEC 14443-3)
      *ppbtInitiatorData = (uint8_t *) "\x00";
      *pszInitiatorData = 1;
      break;
    case NMT_ISO14443BI:
      // APGEN
      *ppbtInitiatorData = (uint8_t *) "\x01\x0b\x3f\x80";
      *pszInitiatorData = 4;
      break;
    case NMT_FELICA:
      // polling payload must be present (see ISO/IEC 18092 11.2.2.5)
      *ppbtInitiatorData = (uint8_t *) "\x00\xff\xff\x01\x00";
      *pszInitiatorData = 5;
      break;
    case NMT_ISO14443A:
    case NMT_ISO14443B2CT:
    case NMT_ISO14443B2SR:
    case NMT_ISO14443BICLASS:
    case NMT_JEWEL:
    case NMT_BARCODE:
    case NMT_DEP:
      *ppbtInitiatorData = NULL;
      *pszInitiatorData = 0;
      break;
  }
}

int connstring_decode(const nfc_connstring connstring, const char *driver_name, const char *bus_name, char **pparam1, char **pparam2)
{
  if (driver_name == NULL) {
    driver_name = "";
  }
  if (bus_name == NULL) {
    bus_name = "";
  }
  int n = strlen(connstring) + 1;
  char *param0 = malloc(n);
  if (param0 == NULL) {
    perror("malloc");
    return 0;
  }
  char *param1 = malloc(n);
  if (param1 == NULL) {
    perror("malloc");
    free(param0);
    return 0;
  }
  char *param2    = malloc(n);
  if (param2 == NULL) {
    perror("malloc");
    free(param0);
    free(param1);
    return 0;
  }

  char format[32];
  snprintf(format, sizeof(format), "%%%i[^:]:%%%i[^:]:%%%i[^:]", n - 1, n - 1, n - 1);
  int res = sscanf(connstring, format, param0, param1, param2);

  if (res < 1 || ((0 != strcmp(param0, driver_name)) &&
                  (0 != strcmp(param0, bus_name)))) {
    // Driver name does not match.
    res = 0;
  }
  if (pparam1 != NULL) {
    if (res < 2) {
      free(param1);
      *pparam1 = NULL;
    } else {
      *pparam1 = param1;
    }
  } else {
    free(param1);
  }
  if (pparam2 != NULL) {
    if (res < 3) {
      free(param2);
      *pparam2 = NULL;
    } else {
      *pparam2 = param2;
    }
  } else {
    free(param2);
  }
  free(param0);
  return res;
}

