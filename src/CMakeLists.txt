cmake_minimum_required (VERSION 3.22)
project (PN532-Cloner)
set(CMAKE_C_STANDARD 11)

# Static link libries
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static")

# Turn on some compiler flags to detect programming errors
# The following line of code can be comented out while debuging the code
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

set(SOURCES
    cmdhfmfhard.c
    crapto1.c
    crypto1.c
    getopt.c
    iso14443-subr.c
    log.c
    main.c
    mifare.c
    mirror-subr.c
    nfc-device.c
    nfc-internal.c
    nfc-utils.c
    nfc.c
    parity.c
    pn53x.c
    pn532_uart.c
    slre.c
    target-subr.c
    uart.c
    util_posix.c
    util.c
    hardnested/hardnested_bf_core.c
    hardnested/hardnested_bitarray_core.c
    hardnested/hardnested_bruteforce.c
    hardnested/tables.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} liblzma.lib)