cmake_minimum_required(VERSION 3.10)
project(X25519 VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_TESTING "Enable test building" ON)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(FIAT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fiat)
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/source)

# check fiat implementation based on platform
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "Building for 64-bit platform")
    # non 64-bit version，using 32-bit version with -m32
    if(EXISTS ${FIAT_DIR}/curve25519_64.c)
        set(FIAT_SOURCE ${FIAT_DIR}/curve25519_64.c)
        add_compile_definitions(FIAT_64_BIT)
    else()
        message(STATUS "64-bit fiat not found, using 32-bit version with -m32")
        set(FIAT_SOURCE ${FIAT_DIR}/curve25519_32.c)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    endif()
else()
    message(STATUS "Building for 32-bit platform")
    set(FIAT_SOURCE ${FIAT_DIR}/curve25519_32.c)
endif()

# main library target
add_library(fe25519 STATIC
    ${SOURCE_DIR}/fe25519.c
    ${SOURCE_DIR}/x25519.c
    ${FIAT_SOURCE}
)

target_include_directories(fe25519 PUBLIC
    ${INCLUDE_DIR}
    ${FIAT_DIR}
)

# set output directories for library
set_target_properties(fe25519 PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# test
if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

# instal rules
install(TARGETS fe25519
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# print configuration summary
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Testing enabled: ${ENABLE_TESTING}")
