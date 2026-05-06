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
#include "fe25519.h"

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

/* ========== test helper ========== */

// simple random number generator (for testing)
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

// test 0: deep field operations (edge cases & algebraic properties)
static int test_field_ops_deep(void)
{
    printf("Test 0: Deep field operations (edge cases & algebraic properties)...\n");

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

// test 1: basic inversion property a * a^{-1} = 1
static int test_invert_basic(void)
{
    printf("Test 1: Basic inversion property (a * a^{-1} = 1)...\n");

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

// test 2: inverse of 1
static int test_invert_one(void)
{
    printf("Test 2: Inverse of 1 should be 1...\n");

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

// test 3: invert symmetry (a^{-1})^{-1} = a
static int test_invert_symmetry(void)
{
    printf("Test 3: Symmetry property ((a^{-1})^{-1} = a)...\n");

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

// test 4: known test vectors
static int test_known_vectors(void)
{
    printf("Test 4: Known test vectors...\n");

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

// test 5: stress test (random inversions)
static int test_stress(int iterations)
{
    printf("Test 5: Stress test (%d random inversions)...\n", iterations);

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

// test 6: idempotent test (same input yields same output)
static int test_idempotent(void)
{
    printf("Test 6: Idempotent test (same input yields same output)...\n");

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

// test 7: edge cases
static int test_edge_cases(void)
{
    printf("Test 7: Edge cases...\n");

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

// test 8: zero inverse (ensure it doesn't crash)
static int test_zero_inverse(void)
{
    printf("Test 8: Zero inversion (should not crash)...\n");

    fe25519_t zero, inv;
    fe25519_zero(&zero);

    // remind: zero invert not defined,
    // but should not crash
    fe25519_invert(&inv, &zero);

    printf("  PASSED (no crash)\n");
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
        all_passed &= test_field_ops_deep();
        all_passed &= test_invert_basic();
        all_passed &= test_invert_one();
        all_passed &= test_invert_symmetry();
        all_passed &= test_known_vectors();
        all_passed &= test_idempotent();
        all_passed &= test_edge_cases();
        all_passed &= test_stress(1000);
        all_passed &= test_zero_inverse();

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
            test_field_ops_deep();
            test_invert_basic();
            test_invert_one();
            test_invert_symmetry();
            test_known_vectors();
            test_idempotent();
            test_edge_cases();
            test_stress(10000);
            test_zero_inverse();
            benchmark_invert(100000);
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    return 0;
}
