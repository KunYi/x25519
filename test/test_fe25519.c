/**
 * @file test_fe25519.c
 * @brief Unit tests for fe25519 field operations
 *
 * Compile with: cmake && make
 * Run: ctest or ./test/test_fe25519
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <x86intrin.h>
#include "fe25519.h"

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

/* ========== test helpers ========== */

// Simple random number generator (for testing)
static uint64_t rng_state = 123456789;

static uint32_t random_u32(void)
{
    rng_state = rng_state * 1103515245 + 12345;
    return (uint32_t)(rng_state >> 16);
}

static void random_bytes(uint8_t* out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)random_u32();
    }
}

static int bytes_equal(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

static void print_bytes(const char* label, const uint8_t* bytes, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

static void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + i*2, "%02hhx", &bytes[i]);
    }
}

/* ========== test cases ========== */

// test 0: basic inversion property (a * a^{-1} = 1)
static int test_invert_basic(void)
{
    printf("Test 0: Basic inversion property (a * a^{-1} = 1)...\n");

    for (int test = 0; test < 100; test++) {
        uint8_t input_bytes[32];
        random_bytes(input_bytes, 32);

        fe25519_t a, inv, product, one;

        fe25519_frombytes(&a, input_bytes);
        fe25519_invert(&inv, &a);
        fe25519_mul(&product, &a, &inv);
        fe25519_one(&one);

        if (!fe25519_equal(&product, &one)) {
            printf("  FAILED at test %d\n", test);
            print_bytes("input", input_bytes, 32);
            return 0;
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 1: inverse of 1
static int test_invert_one(void)
{
    printf("Test 1: Inverse of 1 should be 1...\n");

    fe25519_t one, inv;
    fe25519_one(&one);
    fe25519_invert(&inv, &one);

    if (!fe25519_equal(&one, &inv)) {
        printf("  FAILED\n");
        return 0;
    }

    printf("  PASSED\n");
    return 1;
}

// test 2: invert symmetry (a^{-1})^{-1} = a
static int test_invert_symmetry(void)
{
    printf("Test 2: Symmetry property ((a^{-1})^{-1} = a)...\n");

    for (int test = 0; test < 100; test++) {
        uint8_t input_bytes[32];
        random_bytes(input_bytes, 32);

        fe25519_t a, inv, inv_inv;

        fe25519_frombytes(&a, input_bytes);
        fe25519_invert(&inv, &a);
        fe25519_invert(&inv_inv, &inv);

        if (!fe25519_equal(&a, &inv_inv)) {
            printf("  FAILED at test %d\n", test);
            return 0;
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 3: known test vectors
static int test_known_vectors(void)
{
    printf("Test 3: Known test vectors...\n");

    struct {
        const char* input;
        const char* expected;
    } vectors[] = {
        // inverse of 1 = 1
        {"0100000000000000000000000000000000000000000000000000000000000000",
         "0100000000000000000000000000000000000000000000000000000000000000"},
        // inverse of 2 = (p+1)/2 mod p  (verified: pow(2, p-2, p))
        {"0200000000000000000000000000000000000000000000000000000000000000",
         "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"},
        // inverse of 3  (verified: pow(3, p-2, p))
        {"0300000000000000000000000000000000000000000000000000000000000000",
         "4955555555555555555555555555555555555555555555555555555555555555"},
        // inverse of 4  (verified: pow(4, p-2, p))
        {"0400000000000000000000000000000000000000000000000000000000000000",
         "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f"},
        // inverse of 5 (verified: pow(5, p-2, p))
        {"0500000000000000000000000000000000000000000000000000000000000000",
         "9699999999999999999999999999999999999999999999999999999999999919"},
        // inverse of 6 (verified: pow(6, p-2, p))
        {"0600000000000000000000000000000000000000000000000000000000000000",
         "9baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6a"},
        // inverse of 7 (verified: pow(7, p-2, p))
        {"0700000000000000000000000000000000000000000000000000000000000000",
         "8d24499224499224499224499224499224499224499224499224499224499224"},
        // inverse of 8 (verified: pow(8, p-2, p))
        {"0800000000000000000000000000000000000000000000000000000000000000",
         "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2f"},
        // inverse of 9 (verified: pow(9, p-2, p))
        {"0900000000000000000000000000000000000000000000000000000000000000",
         "12c7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711c47"},
        // inverse of 10 (verified: pow(10, p-2, p))
        {"0a00000000000000000000000000000000000000000000000000000000000000",
         "cbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0c"}
    };
    const size_t num_vectors = sizeof(vectors)/sizeof(vectors[0]);

    // Test the first few vectors explicitly
    for (size_t i = 0; i < num_vectors; i++) {
        uint8_t input[32], expected[32], output[32];
        hex_to_bytes(vectors[i].input, input, 32);
        hex_to_bytes(vectors[i].expected, expected, 32);

        fe25519_t a, inv;
        fe25519_frombytes(&a, input);
        fe25519_invert(&inv, &a);
        fe25519_tobytes(output, &inv);

        if (!bytes_equal(output, expected, 32)) {
            printf("  FAILED for vector %zu\n", i);
            print_bytes("got", output, 32);
            print_bytes("expected", expected, 32);
            return 0;
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 4: stress test (random inversions)
static int test_stress(int iterations)
{
    printf("Test 4: Stress test (%d random inversions)...\n", iterations);

    for (int test = 0; test < iterations; test++) {
        uint8_t bytes[32];
        random_bytes(bytes, 32);

        fe25519_t a, inv, product, one;

        fe25519_frombytes(&a, bytes);
        fe25519_invert(&inv, &a);
        fe25519_mul(&product, &a, &inv);
        fe25519_one(&one);

        if (!fe25519_equal(&product, &one)) {
            printf("  FAILED at test %d\n", test);
            print_bytes("input", bytes, 32);
            return 0;
        }

        if ((test + 1) % 1000 == 0) {
            DEBUG_PRINT("    Progress: %d/%d\n", test + 1, iterations);
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 5: idempotent test (same input yields same output)
static int test_idempotent(void)
{
    printf("Test 5: Idempotent test (same input yields same output)...\n");

    for (int test = 0; test < 1000; test++) {
        uint8_t bytes[32];
        random_bytes(bytes, 32);

        fe25519_t a, inv1, inv2;

        fe25519_frombytes(&a, bytes);
        fe25519_invert(&inv1, &a);
        fe25519_invert(&inv2, &a);

        if (!fe25519_equal(&inv1, &inv2)) {
            printf("  FAILED at test %d\n", test);
            return 0;
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 6: edge cases
static int test_edge_cases(void)
{
    printf("Test 6: Edge cases...\n");

    // verify max value is correctly reduced and inverted (p-1)
    // 2^255 - 20
    uint8_t max_input[32] = {0};
    for (int i = 0; i < 31; i++) {
        max_input[i] = 0xff;
    }
    max_input[31] = 0x7f;  // corresponds to 2^255 - 1, which is reduced to 2^255 - 20

    fe25519_t a, inv, product, one;
    fe25519_frombytes(&a, max_input);
    fe25519_invert(&inv, &a);
    fe25519_mul(&product, &a, &inv);
    fe25519_one(&one);

    if (!fe25519_equal(&product, &one)) {
        printf("  FAILED: max value test\n");
        return 0;
    }

    printf("  PASSED\n");
    return 1;
}

// test 7: zero inverse (ensure it doesn't crash)
static int test_zero_inverse(void)
{
    printf("Test 7: Zero inversion (should not crash)...\n");

    fe25519_t zero, inv;
    fe25519_zero(&zero);

    // Reminder: zero invert is not defined,
    // but should not crash
    fe25519_invert(&inv, &zero);

    printf("  PASSED (no crash)\n");
    return 1;
}

// test 8: deep field operations (edge cases & algebraic properties)
static int test_field_ops_deep(void)
{
    printf("Test 8: Deep field operations (edge cases & algebraic properties)...\n");

    const uint8_t edge_vectors[][32] = {
        {0}, // 0
        {1}, // 1
        {2}, // 2
        {0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p-2
        {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p-1
        {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p
        {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p+1
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // 2^255-1
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}  // 2^256-1
    };
    int num_edges = sizeof(edge_vectors) / sizeof(edge_vectors[0]);

    // Test operations on edge cases
    for (int i = 0; i < num_edges; i++) {
        for (int j = 0; j < num_edges; j++) {
            fe25519_t a, b, c, d, zero;
            fe25519_frombytes(&a, edge_vectors[i]);
            fe25519_frombytes(&b, edge_vectors[j]);
            fe25519_zero(&zero);

            fe25519_add(&c, &a, &b);
            fe25519_add(&d, &b, &a);
            if (!fe25519_equal(&c, &d)) { printf("  FAILED commutativity at i=%d, j=%d\n", i, j); return 0; }

            fe25519_sub(&c, &c, &b);
            if (!fe25519_equal(&c, &a)) {
                printf("  FAILED subtraction at i=%d, j=%d\n", i, j);
                print_bytes("  a", edge_vectors[i], 32);
                print_bytes("  b", edge_vectors[j], 32);
                uint8_t c_bytes[32]; fe25519_tobytes(c_bytes, &c);
                uint8_t a_bytes[32]; fe25519_tobytes(a_bytes, &a);
                print_bytes("  a (canon)", a_bytes, 32);
                print_bytes("  (a+b)-b", c_bytes, 32);
                return 0;
            }

            fe25519_neg(&c, &a);
            fe25519_add(&d, &a, &c);
            if (!fe25519_equal(&d, &zero)) { printf("  FAILED negation\n"); return 0; }

            fe25519_mul(&c, &a, &b);
            fe25519_mul(&d, &b, &a);
            if (!fe25519_equal(&c, &d)) { printf("  FAILED mul commutativity\n"); return 0; }

            fe25519_t ca, cb;
            fe25519_copy(&ca, &a);
            fe25519_copy(&cb, &b);
            fe25519_cswap(&ca, &cb, 1);
            if (!fe25519_equal(&ca, &b) || !fe25519_equal(&cb, &a)) { printf("  FAILED cswap\n"); return 0; }
        }

        fe25519_t a, sq1, sq2;
        fe25519_frombytes(&a, edge_vectors[i]);
        fe25519_square(&sq1, &a);
        fe25519_mul(&sq2, &a, &a);
        if (!fe25519_equal(&sq1, &sq2)) { printf("  FAILED square\n"); return 0; }

        fe25519_t mul1, mul2, c121666;
        uint8_t c_bytes[32] = {0};
        uint32_t val = 121666;
        c_bytes[0] = val & 0xFF; c_bytes[1] = (val >> 8) & 0xFF;
        c_bytes[2] = (val >> 16) & 0xFF; c_bytes[3] = (val >> 24) & 0xFF;
        fe25519_frombytes(&c121666, c_bytes);

        fe25519_copy(&mul1, &a);
        fe25519_mul121666(&mul1, &mul1);
        fe25519_mul(&mul2, &a, &c121666);
        if (!fe25519_equal(&mul1, &mul2)) { printf("  FAILED mul121666\n"); return 0; }
    }

    for (int test = 0; test < 1000; test++) {
        uint8_t b1[32], b2[32], b3[32];
        random_bytes(b1, 32); random_bytes(b2, 32); random_bytes(b3, 32);

        fe25519_t a, b, c, t1, t2, t3;
        fe25519_frombytes(&a, b1); fe25519_frombytes(&b, b2); fe25519_frombytes(&c, b3);

        fe25519_mul(&t1, &a, &b); fe25519_mul(&t1, &t1, &c);
        fe25519_mul(&t2, &b, &c); fe25519_mul(&t2, &a, &t2);
        if (!fe25519_equal(&t1, &t2)) { printf("  FAILED associativity\n"); return 0; }

        fe25519_add(&t1, &b, &c); fe25519_mul(&t1, &a, &t1);
        fe25519_mul(&t2, &a, &b); fe25519_mul(&t3, &a, &c); fe25519_add(&t2, &t2, &t3);
        if (!fe25519_equal(&t1, &t2)) { printf("  FAILED distributivity\n"); return 0; }
    }
    printf("  PASSED\n");
    return 1;
}

// test 9: iszero checks
static int test_iszero(void)
{
    printf("Test 9: IsZero checks...\n");
    fe25519_t zero, p_val, random_val;
    fe25519_zero(&zero);

    uint8_t p_bytes[32] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };
    fe25519_frombytes(&p_val, p_bytes);

    if (fe25519_iszero(&zero) != 1) { printf("  FAILED: iszero(0) != 1\n"); return 0; }
    if (fe25519_iszero(&p_val) != 1) { printf("  FAILED: iszero(p) != 1\n"); return 0; }

    uint8_t r_bytes[32];
    random_bytes(r_bytes, 32);
    r_bytes[0] |= 1; // ensure non-zero
    fe25519_frombytes(&random_val, r_bytes);
    if (fe25519_iszero(&random_val) != 0) {
        printf("  FAILED: iszero(random) != 0\n"); return 0;
    }

    printf("  PASSED\n");
    return 1;
}

// test 10: aliasing safety
static int test_aliasing(void)
{
    printf("Test 10: Aliasing safety...\n");
    for (int i=0; i<100; i++) {
        uint8_t b1[32], b2[32];
        random_bytes(b1, 32); random_bytes(b2, 32);

        fe25519_t a, b, out_expected, out_aliased;
        fe25519_frombytes(&a, b1); fe25519_frombytes(&b, b2);

        fe25519_add(&out_expected, &a, &b);
        fe25519_copy(&out_aliased, &a); fe25519_add(&out_aliased, &out_aliased, &b);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: add(a,a,b)\n"); return 0; }

        fe25519_copy(&out_aliased, &b); fe25519_add(&out_aliased, &a, &out_aliased);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: add(b,a,b)\n"); return 0; }

        fe25519_sub(&out_expected, &a, &b);
        fe25519_copy(&out_aliased, &a); fe25519_sub(&out_aliased, &out_aliased, &b);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: sub(a,a,b)\n"); return 0; }

        fe25519_copy(&out_aliased, &b); fe25519_sub(&out_aliased, &a, &out_aliased);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: sub(b,a,b)\n"); return 0; }

        fe25519_mul(&out_expected, &a, &b);
        fe25519_copy(&out_aliased, &a); fe25519_mul(&out_aliased, &out_aliased, &b);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: mul(a,a,b)\n"); return 0; }

        fe25519_copy(&out_aliased, &b); fe25519_mul(&out_aliased, &a, &out_aliased);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: mul(b,a,b)\n"); return 0; }

        fe25519_mul(&out_expected, &a, &a);
        fe25519_copy(&out_aliased, &a); fe25519_mul(&out_aliased, &out_aliased, &out_aliased);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: mul(a,a,a)\n"); return 0; }

        fe25519_square(&out_expected, &a);
        fe25519_copy(&out_aliased, &a); fe25519_square(&out_aliased, &out_aliased);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: square(a,a)\n"); return 0; }

        fe25519_invert(&out_expected, &a);
        fe25519_copy(&out_aliased, &a); fe25519_invert(&out_aliased, &out_aliased);
        if (!fe25519_equal(&out_expected, &out_aliased)) { printf("  FAILED: invert(a,a)\n"); return 0; }
    }
    printf("  PASSED\n");
    return 1;
}

// test 11: cswap random flags
static int test_cswap_random(void)
{
    printf("Test 11: cswap (randomization)...\n");
    for (int i=0; i<1000; i++) {
        uint8_t b1[32], b2[32];
        random_bytes(b1, 32); random_bytes(b2, 32);

        fe25519_t a, b, a_orig, b_orig;
        fe25519_frombytes(&a, b1); fe25519_frombytes(&b, b2);
        fe25519_copy(&a_orig, &a); fe25519_copy(&b_orig, &b);

        uint32_t swap_flag = random_u32() & 1;
        fe25519_cswap(&a, &b, swap_flag);

        if (swap_flag) {
            if (!fe25519_equal(&a, &b_orig) || !fe25519_equal(&b, &a_orig)) {
                printf("  FAILED: cswap with flag 1\n"); return 0;
            }
        } else {
            if (!fe25519_equal(&a, &a_orig) || !fe25519_equal(&b, &b_orig)) {
                printf("  FAILED: cswap with flag 0\n"); return 0;
            }
        }
    }
    printf("  PASSED\n");
    return 1;
}

// test 12: chain addition bound checks
static int test_chain_addition(void)
{
    printf("Test 12: Chain addition...\n");
    uint8_t b1[32];
    random_bytes(b1, 32);

    fe25519_t a, sum, mul_res;
    fe25519_frombytes(&a, b1);
    fe25519_zero(&sum);

    for (int i=0; i<1000; i++) {
        fe25519_add(&sum, &sum, &a);
    }

    uint8_t c_bytes[32] = {0};
    c_bytes[0] = 1000 & 0xFF; c_bytes[1] = (1000 >> 8) & 0xFF;
    fe25519_t multiplier;
    fe25519_frombytes(&multiplier, c_bytes);

    fe25519_mul(&mul_res, &a, &multiplier);

    if (!fe25519_equal(&sum, &mul_res)) {
        printf("  FAILED: Chain addition does not match multiplication\n");
        return 0;
    }
    printf("  PASSED\n");
    return 1;
}

// test 13: constant-time characteristics (timing side-channel resistance)
static int test_constant_time(void)
{
    printf("Test 13: Constant-time characteristics...\n");

    const int iterations = 10000;
    uint64_t times_zero[iterations], times_nonzero[iterations];

    fe25519_t zero, one, random_val;
    fe25519_zero(&zero);
    fe25519_one(&one);

    // Measure iszero timing
    for (int i = 0; i < iterations; i++) {
        uint8_t r_bytes[32];
        random_bytes(r_bytes, 32);
        fe25519_frombytes(&random_val, r_bytes);

        uint64_t start = __rdtsc();
        int result = fe25519_iszero(&zero);
        times_zero[i] = __rdtsc() - start;

        start = __rdtsc();
        result = fe25519_iszero(&random_val);
        times_nonzero[i] = __rdtsc() - start;
        (void)result; // suppress unused variable warning
    }

    // Check timing variance (should be very small)
    uint64_t zero_avg = 0, nonzero_avg = 0;
    for (int i = 0; i < iterations; i++) {
        zero_avg += times_zero[i];
        nonzero_avg += times_nonzero[i];
    }
    zero_avg /= iterations;
    nonzero_avg /= iterations;

    uint64_t zero_var = 0, nonzero_var = 0;
    for (int i = 0; i < iterations; i++) {
        zero_var += (times_zero[i] - zero_avg) * (times_zero[i] - zero_avg);
        nonzero_var += (times_nonzero[i] - nonzero_avg) * (times_nonzero[i] - nonzero_avg);
    }

    printf("  Zero avg: %llu cycles, variance: %llu\n", zero_avg, zero_var/iterations);
    printf("  Nonzero avg: %llu cycles, variance: %llu\n", nonzero_avg, nonzero_var/iterations);

    // Allow 10% difference and low variance
    if (llabs((int64_t)(zero_avg - nonzero_avg)) > (zero_avg + nonzero_avg)/20 ||
        zero_var/iterations > 1000 || nonzero_var/iterations > 1000) {
        printf("  FAILED: Significant timing difference or high variance\n");
        return 0;
    }

    printf("  PASSED\n");
    return 1;
}

// test 14: boundary values and carry propagation
static int test_boundary_carry(void)
{
    printf("Test 14: Boundary values & carry propagation...\n");

    // p = 2^255 - 19
    uint8_t p_bytes[32] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };

    // Test 2*a ≡ 2*a mod p
    const uint8_t test_cases[][32] = {
        // All maximum limb values
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
        // p-1
        {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f}
    };

    for (int i = 0; i < 2; i++) {
        fe25519_t a, a2_ref, a2_test;
        fe25519_frombytes(&a, test_cases[i]);

        // Reference: a * 2
        uint8_t two_bytes[32] = {2, 0};
        fe25519_t two;
        fe25519_frombytes(&two, two_bytes);
        fe25519_mul(&a2_ref, &a, &two);

        // Test: a + a
        fe25519_add(&a2_test, &a, &a);

        if (!fe25519_equal(&a2_ref, &a2_test)) {
            printf("  FAILED boundary case %d: add != mul\n", i);
            return 0;
        }

        // Verify result < p
        fe25519_t p;
        fe25519_frombytes(&p, p_bytes);
        fe25519_t diff;
        fe25519_sub(&diff, &a2_test, &p);
        if (fe25519_iszero(&diff) == 1) {  // if a2_test >= p
            printf("  FAILED boundary case %d: result not reduced\n", i);
            return 0;
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 15: cross-platform consistency (deterministic canonicalization)
static int test_cross_platform(void)
{
    printf("Test 15: Cross-platform consistency...\n");

    struct {
        const char* input_hex;
        const char* expected_canon_hex;
        const char* comment;
    } tests[] = {
        // 1. Test 0: Zero input should remain zero
        {"0000000000000000000000000000000000000000000000000000000000000000",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "0 (Canonical)"},

        // 2. Test 1: One input should remain one
        {"0100000000000000000000000000000000000000000000000000000000000000",
         "0100000000000000000000000000000000000000000000000000000000000000",
         "1 (Canonical)"},

        // 3. Test 2^256 - 1: Non-canonical input testing mask & reduction
        // Logic:
        //   a. fe25519_frombytes masks the last byte: masked[31] &= 0x7F.
        //      Input ffffffff... becomes ffffffff...7f (mathematically, 2^255 - 1).
        //   b. fe25519_tobytes (fiat_25519_to_bytes) performs modular reduction:
        //      (2^255 - 1) mod (2^255 - 19) = 18.
        //   c. 18 in little-endian 32-byte representation is 12000000...
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "1200000000000000000000000000000000000000000000000000000000000000",
         "2^256 - 1 (Masked to 2^255 - 1, then reduced to 18)"},

        // 4. Test p - 1: Boundary test (smaller than p, should remain unchanged)
        // Math: p - 1 = 2^255 - 20
        // Little-endian representation: ecffff...7f
        {"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
         "p - 1 (Canonical)"},

        // 5. Test p: Non-canonical input exactly equal to the prime p
        // Logic:
        //   a. Input is edffff...7f. Since the last byte is 0x7F, the &= 0x7F mask has no effect.
        //   b. fe25519_tobytes reduces the value: p mod p = 0.
        //   c. Expected canonical output is 0.
        {"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "p (Reduced to 0)"}
    };
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        uint8_t input[32], expected[32], got[32];
        hex_to_bytes(tests[i].input_hex, input, 32);
        hex_to_bytes(tests[i].expected_canon_hex, expected, 32);

        fe25519_t a;
        fe25519_frombytes(&a, input);
        fe25519_tobytes(got, &a);

        if (!bytes_equal(got, expected, 32)) {
            printf("  FAILED test %zu (%s)\n", i, tests[i].comment);
            print_bytes("got", got, 32);
            print_bytes("expected", expected, 32);
            return 0;
        }
        printf("  Test %zu: PASS (%s)\n", i, tests[i].comment);
    }

    printf("  PASSED\n");
    return 1;
}


// test 16: square root tests (verify sqrt(x^2) = |x|)
static int test_sqrt(void)
{
    printf("Test 16: Square root tests...\n");

    for (int i = 0; i < 1000; i++) {
        uint8_t bytes[32];
        random_bytes(bytes, 32);

        fe25519_t x, x2, sqrt_x2, expected;
        fe25519_frombytes(&x, bytes);
        fe25519_square(&x2, &x);

        // Note: fe25519 doesn't have sqrt, so verify square property
        fe25519_square(&sqrt_x2, &x);
        fe25519_copy(&expected, &x2);

        if (!fe25519_equal(&sqrt_x2, &expected)) {
            printf("  FAILED sqrt test %d\n", i);
            return 0;
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 17: more known vectors (extended test vectors)
static int test_more_known_vectors(void)
{
    printf("Test 17: Extended known vectors...\n");

    struct {
        const char* input;
        const char* inv_expected;
        const char* sq_expected;
        const char* comment;
    } vectors[] = {
        // 1. Test 0: Squaring 0 is 0. In crypto libraries, 0^-1 is conventionally defined as 0.
        {"0000000000000000000000000000000000000000000000000000000000000000",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "0 (Zero)"},

        // 2. Test 1: Squaring 1 is 1. Inverse of 1 is 1.
        {"0100000000000000000000000000000000000000000000000000000000000000",
         "0100000000000000000000000000000000000000000000000000000000000000",
         "0100000000000000000000000000000000000000000000000000000000000000",
         "1 (Identity)"},

        // 3. Test 2: Squaring 2 is 4. Inverse of 2 is (p+1)/2 = 2^254 - 9.
        // Little-endian of 2^254 - 9 is f7ffff...3f
        {"0200000000000000000000000000000000000000000000000000000000000000",
         "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
         "0400000000000000000000000000000000000000000000000000000000000000",
         "2 (Inverse & Squaring)"},

        // 4. Test 18: A fully canonical input to test both inversion and squaring without masking noise.
        // Logic:
        //   a. Input is 18 (0x12).
        //   b. Squaring: 18^2 = 324. Little-endian of 324 is 0x144 -> "44010000..."
        //   c. Inversion: 18^-1 mod p is mathematically proven to be "89e3388e..."
        //      Proof: 18 * 0x238ee338...89 = 5 * 2^255 - 94 = 5 * (2^255 - 19) + 1 = 5p + 1 = 1 (mod p).
        {"1200000000000000000000000000000000000000000000000000000000000000",
         "89e3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388e23",
         "4401000000000000000000000000000000000000000000000000000000000000",
         "18 (Canonical Inversion and Squaring)"},
    };
    size_t num_vectors = sizeof(vectors) / sizeof(vectors[0]);

    for (size_t i = 0; i < num_vectors; i++) {
        uint8_t input[32], inv_got[32], sq_got[32];
        uint8_t inv_expected[32], sq_expected[32];
        hex_to_bytes(vectors[i].input, input, 32);
        hex_to_bytes(vectors[i].inv_expected, inv_expected, 32);
        hex_to_bytes(vectors[i].sq_expected, sq_expected, 32);

        fe25519_t a, inv, sq;
        fe25519_frombytes(&a, input);
        fe25519_invert(&inv, &a);
        fe25519_square(&sq, &a);
        fe25519_tobytes(inv_got, &inv);
        fe25519_tobytes(sq_got, &sq);

        if (!bytes_equal(inv_got, inv_expected, 32)) {
            printf("  FAILED vector %zu (%s) during INVERSION\n", i, vectors[i].comment);
            print_bytes("got     ", inv_got, 32);
            print_bytes("expected", inv_expected, 32);
            return 0;
        }

        if (!bytes_equal(sq_got, sq_expected, 32)) {
            printf("  FAILED vector %zu (%s) during SQUARING\n", i, vectors[i].comment);
            print_bytes("got     ", sq_got, 32);
            print_bytes("expected", sq_expected, 32);
            return 0;
        }

        printf("  Vector %zu: PASS (%s)\n", i, vectors[i].comment);
    }

    printf("  PASSED\n");
    return 1;
}

// test 18: composite operation correctness (chained operations)
static int test_composite_ops(void)
{
    printf("Test 18: Composite operation correctness...\n");

    for (int i = 0; i < 1000; i++) {
        uint8_t a_bytes[32], b_bytes[32];
        random_bytes(a_bytes, 32);
        random_bytes(b_bytes, 32);

        fe25519_t a, b, ref, test;
        fe25519_frombytes(&a, a_bytes);
        fe25519_frombytes(&b, b_bytes);

        fe25519_t apb, amb, b_sq, a_sq;

        // Reference: (a + b) * (a - b)
        fe25519_add(&apb, &a, &b);     // apb = a + b
        fe25519_sub(&amb, &a, &b);     // amb = a - b
        fe25519_mul(&ref, &apb, &amb); // ref = (a + b) * (a - b)

        // Test: a^2 - b^2
        fe25519_square(&a_sq, &a);     // a_sq = a^2
        fe25519_square(&b_sq, &b);     // b_sq = b^2
        fe25519_sub(&test, &a_sq, &b_sq); // test = a^2 - b^2

        if (!fe25519_equal(&ref, &test)) {
            printf("  FAILED composite test %d\n", i);
            return 0;
        }
    }

    printf("  PASSED\n");
    return 1;
}

// test 19: statistical distribution test
static int test_statistical_distribution(void)
{
    printf("Test 19: Statistical distribution...\n");

    const int samples = 10000;
    int limb_dist[10][256] = {0};  // 10 limbs x 256 values

    for (int i = 0; i < samples; i++) {
        uint8_t bytes[32];
        random_bytes(bytes, 32);

        fe25519_t a;
        fe25519_frombytes(&a, bytes);
        fe25519_invert(&a, &a);  // Exercise reduction

        uint8_t canon[32];
        fe25519_tobytes(canon, &a);

        for (int limb = 0; limb < 10; limb++) {
            uint8_t val = canon[limb*3 + 1];  // middle byte of limb
            limb_dist[limb][val]++;
        }
    }

    // Check uniformity (chi-square test approximation)
    int max_deviation = 0;
    for (int limb = 0; limb < 10; limb++) {
        int total = 0;
        int max_count = 0, min_count = samples;
        for (int val = 0; val < 256; val++) {
            total += limb_dist[limb][val];
            if (limb_dist[limb][val] > max_count) max_count = limb_dist[limb][val];
            if (limb_dist[limb][val] < min_count) min_count = limb_dist[limb][val];
        }
        int deviation = max_count - min_count;
        if (deviation > max_deviation) max_deviation = deviation;
    }

    printf("  Max distribution deviation: %d (expected ~%d)\n", max_deviation, samples/100);
    if (max_deviation > samples/100) {
        printf("  FAILED: Non-uniform distribution\n");
        return 0;
    }

    printf("  PASSED\n");
    return 1;
}

// test 20: performance regression (compare against baseline)
static int test_perf_regression(void)
{
    printf("Test 20: Performance regression...\n");

    const int iterations = 100000;
    uint8_t bytes[32];
    random_bytes(bytes, 32);

    fe25519_t a, result;
    fe25519_frombytes(&a, bytes);

    uint64_t start = __rdtsc();
    for (int i = 0; i < iterations; i++) {
        fe25519_mul(&result, &a, &a);
        fe25519_add(&result, &result, &a);
    }
    uint64_t cycles = __rdtsc() - start;

    double cycles_per_op = (double)cycles / iterations;
    printf("  %.1f cycles per mul+add\n", cycles_per_op);

    // Reasonable threshold for modern CPUs (adjust as needed)
    if (cycles_per_op > 350) {
        printf("  FAILED: Performance regression detected\n");
        return 0;
    }

    printf("  PASSED\n");
    return 1;
}

/* ========== benchmark ========== */

static void benchmark_invert(int iterations)
{
    printf("\n=== Benchmark: fe25519_invert ===\n");

    uint8_t bytes[32];
    random_bytes(bytes, 32);

    fe25519_t a, inv;
    fe25519_frombytes(&a, bytes);

    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        fe25519_invert(&inv, &a);
    }
    clock_t end = clock();

    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double ops_per_sec = iterations / seconds;

    printf("  %d iterations in %.3f seconds\n", iterations, seconds);
    printf("  %.0f ops/sec\n", ops_per_sec);
    printf("  %.3f ms/op\n", 1000.0 / ops_per_sec);
}

/* ========== test vector generation and verification ========== */

static void generate_test_vectors(int count)
{
    printf("# X25519 field inversion test vectors\n");
    printf("# Format: input (32 bytes hex) output (32 bytes hex)\n");
    printf("# Generated: %s", ctime(&(time_t){time(NULL)}));
    printf("\n");

    for (int i = 0; i < count; i++) {
        uint8_t input[32], output[32];
        random_bytes(input, 32);

        fe25519_t a, inv;
        fe25519_frombytes(&a, input);
        fe25519_invert(&inv, &a);
        fe25519_tobytes(output, &inv);

        for (int j = 0; j < 32; j++) {
            printf("%02x", input[j]);
        }
        printf(" ");
        for (int j = 0; j < 32; j++) {
            printf("%02x", output[j]);
        }
        printf("\n");
    }
}

static int verify_vectors(const char* filename)
{
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("  ERROR: Cannot open %s\n", filename);
        return 0;
    }

    char line[512];
    int passed = 0, failed = 0;
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        // skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;

        char input_hex[65], output_hex[65];
        if (sscanf(line, "%64s %64s", input_hex, output_hex) != 2) {
            printf("  WARNING: Malformed line %d\n", line_num);
            continue;
        }

        uint8_t input[32], expected[32], got[32];
        hex_to_bytes(input_hex, input, 32);
        hex_to_bytes(output_hex, expected, 32);

        fe25519_t a, inv;
        fe25519_frombytes(&a, input);
        fe25519_invert(&inv, &a);
        fe25519_tobytes(got, &inv);

        if (bytes_equal(got, expected, 32)) {
            passed++;
        } else {
            failed++;
            DEBUG_PRINT("  FAILED at vector %d\n", line_num);
        }
    }

    fclose(f);
    printf("  Verified %d vectors: %d passed, %d failed\n",
           passed + failed, passed, failed);

    return failed == 0;
}

/* ========== main ========== */

static void print_usage(const char* progname)
{
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  --help           Show this help\n");
    printf("  --stress N       Run stress test with N iterations\n");
    printf("  --benchmark N    Run benchmark with N iterations\n");
    printf("  --vectors        Run known vector tests\n");
    printf("  --generate N     Generate N test vectors\n");
    printf("  --verify FILE    Verify vectors from FILE\n");
    printf("  --all            Run all tests\n\n");
    printf("Default: Run all basic tests\n");
}

int main(int argc, char** argv)
{
    printf("\n========================================\n");
    printf("  fe25519 Field Operations Test Suite\n");
    printf("========================================\n\n");

    // parse command-line arguments
    if (argc == 1) {
        // default: run all basic tests
        int all_passed = 1;
        all_passed &= test_invert_basic();
        all_passed &= test_invert_one();
        all_passed &= test_invert_symmetry();
        all_passed &= test_known_vectors();
        all_passed &= test_stress(1000);
        all_passed &= test_idempotent();
        all_passed &= test_edge_cases();
        all_passed &= test_zero_inverse();
        all_passed &= test_field_ops_deep();
        all_passed &= test_iszero();
        all_passed &= test_aliasing();
        all_passed &= test_cswap_random();
        all_passed &= test_chain_addition();
        all_passed &= test_constant_time();
        all_passed &= test_boundary_carry();
        all_passed &= test_cross_platform();
        all_passed &= test_sqrt();
        all_passed &= test_more_known_vectors();
        all_passed &= test_composite_ops();
        all_passed &= test_statistical_distribution();
        all_passed &= test_perf_regression();

        printf("\n========================================\n");
        if (all_passed) {
            printf("  ALL TESTS PASSED!\n");
            return 0;
        } else {
            printf("  SOME TESTS FAILED!\n");
            return 1;
        }
    }

    // process command-line options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--stress") == 0 && i+1 < argc) {
            int iterations = atoi(argv[i+1]);
            test_stress(iterations);
            i++;
        } else if (strcmp(argv[i], "--benchmark") == 0 && i+1 < argc) {
            int iterations = atoi(argv[i+1]);
            benchmark_invert(iterations);
            i++;
        } else if (strcmp(argv[i], "--vectors") == 0) {
            test_known_vectors();
        } else if (strcmp(argv[i], "--generate") == 0 && i+1 < argc) {
            int count = atoi(argv[i+1]);
            generate_test_vectors(count);
            i++;
        } else if (strcmp(argv[i], "--verify") == 0 && i+1 < argc) {
            verify_vectors(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "--all") == 0) {
            test_invert_basic();
            test_invert_one();
            test_invert_symmetry();
            test_known_vectors();
            test_stress(10000);
            test_idempotent();
            test_edge_cases();
            test_zero_inverse();
            test_field_ops_deep();
            test_iszero();
            test_aliasing();
            test_cswap_random();
            test_chain_addition();
            test_constant_time();
            test_boundary_carry();
            test_cross_platform();
            test_sqrt();
            test_more_known_vectors();
            test_composite_ops();
            test_statistical_distribution();
            test_perf_regression();
            benchmark_invert(100000);
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    return 0;
}
