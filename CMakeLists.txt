cmake_minimum_required (VERSION 3.22)
project (PN532-Cloner)
set (CMAKE_C_STANDARD 11)

# Uncomment the following line to get more verbose output from CMake
#set(CMAKE_VERBOSE_MAKEFILE ON)

# Turn on some compiler flags to detect programming errors
# The following line of code can be commented out while debuging the code
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

if (CMAKE_SYSTEM MATCHES Windows)
    set (PLATFORM_EXTENSION -Win-x64)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static") # Statically link libwinpthread
    find_library (LIBLZMA lzma HINTS lib_win_x64)
    set(SOURCES src/uart_win.c)
elseif (CMAKE_SYSTEM MATCHES Darwin)
    set (PLATFORM_EXTENSION -Mac-x64)
    find_library (LIBLZMA lzma HINTS lib_darwin_x64)
    set (SOURCES src/uart_darwin.c)
else ()
    message(FATAL_ERROR "Unsupported operating system")
endif ()

set (SOURCES
        ${SOURCES}
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
        src/util_posix.c
        src/util.c
        src/hardnested.c
        src/hardnested/hardnested_bf_core.c
        src/hardnested/hardnested_bitarray_core.c
        src/hardnested/hardnested_bruteforce.c
        src/hardnested/tables.c
)

add_executable(${PROJECT_NAME}${PLATFORM_EXTENSION} ${SOURCES})

target_link_libraries(${PROJECT_NAME}${PLATFORM_EXTENSION} PUBLIC ${LIBLZMA})

