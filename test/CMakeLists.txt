# test/CMakeLists.txt

# test executable for fe25519
add_executable(test_fe25519
    test_fe25519.c
)

#  link with fe25519 library
target_link_libraries(test_fe25519
    fe25519
)

# include directories
target_include_directories(test_fe25519 PRIVATE
    ${INCLUDE_DIR}
    ${FIAT_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# compiler options
target_compile_options(test_fe25519 PRIVATE
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
)

# set debug definition for test executable
target_compile_definitions(test_fe25519 PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
)

# add CTest tests
add_test(NAME test_fe25519_basic COMMAND test_fe25519)
add_test(NAME test_fe25519_stress COMMAND test_fe25519 --stress)
add_test(NAME test_fe25519_vectors COMMAND test_fe25519 --vectors)

# if need to set timeout for stress test
set_tests_properties(test_fe25519_stress PROPERTIES
    TIMEOUT 60
    LABELS "stress"
)

# add benchmark test (optional)
add_test(NAME test_fe25519_benchmark COMMAND test_fe25519 --benchmark)
set_tests_properties(test_fe25519_benchmark PROPERTIES
    TIMEOUT 30
    LABELS "benchmark"
)

# if there are known test vector files, add a test to verify them
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_vectors.txt)
    add_test(NAME test_fe25519_known_vectors
        COMMAND test_fe25519 --verify-vectors ${CMAKE_CURRENT_SOURCE_DIR}/test_vectors.txt
    )
endif()
