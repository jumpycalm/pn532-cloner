cmake_minimum_required (VERSION 3.22)
project (PN532-Cloner)
set(CMAKE_C_STANDARD 11)

# Static link libries
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static")

# Turn on some compiler flags to detect programming errors
# The following line of code can be commented out while debuging the code
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

set(SOURCES
        src/crapto1.c
        src/crypto1.c
        src/getopt.c
        src/iso14443-subr.c
        src/log.c
        src/main.c
        src/mifare.c
        src/mirror-subr.c
        src/nfc-device.c
        src/nfc-internal.c
        src/nfc-utils.c
        src/nfc.c
        src/parity.c
        src/pn53x.c
        src/pn532_uart.c
        src/slre.c
        src/target-subr.c
        src/uart.c
        src/util_posix.c
        src/util.c
        src/hardnested.c
        src/hardnested/hardnested_bf_core.c
        src/hardnested/hardnested_bitarray_core.c
        src/hardnested/hardnested_bruteforce.c
        src/hardnested/tables.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

find_library(LIBLZMA liblzma HINTS lib_win)
target_link_libraries(${PROJECT_NAME}  PUBLIC ${LIBLZMA})

