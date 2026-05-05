#pragma once

#ifndef _CURVE25519_H_
#define _CURVE25519_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef unsigned char fiat_25519_uint1;
typedef signed char fiat_25519_int1;

/* The type fiat_25519_loose_field_element is a field element with loose bounds. */
/* Bounds: [[0x0 ~> 0xc000000], [0x0 ~> 0x6000000], [0x0 ~> 0xc000000], [0x0 ~> 0x6000000], [0x0 ~> 0xc000000], [0x0 ~> 0x6000000], [0x0 ~> 0xc000000], [0x0 ~> 0x6000000], [0x0 ~> 0xc000000], [0x0 ~> 0x6000000]] */
typedef uint32_t fiat_25519_loose_field_element[10];

/* The type fiat_25519_tight_field_element is a field element with tight bounds. */
/* Bounds: [[0x0 ~> 0x4000000], [0x0 ~> 0x2000000], [0x0 ~> 0x4000000], [0x0 ~> 0x2000000], [0x0 ~> 0x4000000], [0x0 ~> 0x2000000], [0x0 ~> 0x4000000], [0x0 ~> 0x2000000], [0x0 ~> 0x4000000], [0x0 ~> 0x2000000]] */
typedef uint32_t fiat_25519_tight_field_element[10];

/*
 * The function fiat_25519_carry_mul multiplies two field elements and reduces the result.
 *
 * Postconditions:
 *   eval out1 mod m = (eval arg1 * eval arg2) mod m
 *
 */
void fiat_25519_carry_mul(fiat_25519_tight_field_element out1, const fiat_25519_loose_field_element arg1, const fiat_25519_loose_field_element arg2);

/*
 * The function fiat_25519_carry_square squares a field element and reduces the result.
 *
 * Postconditions:
 *   eval out1 mod m = (eval arg1 * eval arg1) mod m
 *
 */
void fiat_25519_carry_square(fiat_25519_tight_field_element out1, const fiat_25519_loose_field_element arg1);

/*
 * The function fiat_25519_carry_scmul_121666 multiplies a field element by 121666 and reduces the result.
 *
 * Postconditions:
 *   eval out1 mod m = (121666 * eval arg1) mod m
 *
 */
void fiat_25519_carry_scmul_121666(fiat_25519_tight_field_element out1, const fiat_25519_loose_field_element arg1);

/*
 * The function fiat_25519_carry reduces a loose field element to a tight field element.
 *
 * Postconditions:
 *   eval out1 mod m = eval arg1 mod m
 *
 */
void fiat_25519_carry(fiat_25519_tight_field_element out1, const fiat_25519_loose_field_element arg1);

/*
 * The function fiat_25519_relax is the identity function converting from tight field elements to loose field elements.
 *
 * Postconditions:
 *   out1 = arg1
 *
 */
void fiat_25519_relax(fiat_25519_loose_field_element out1, const fiat_25519_tight_field_element arg1);

/*
 * The function fiat_25519_add adds two field elements.
 *
 * Postconditions:
 *   eval out1 mod m = (eval arg1 + eval arg2) mod m
 *
 */
void fiat_25519_add(fiat_25519_loose_field_element out1, const fiat_25519_tight_field_element arg1, const fiat_25519_tight_field_element arg2);

/*
 * The function fiat_25519_sub subtracts two field elements.
 *
 * Postconditions:
 *   eval out1 mod m = (eval arg1 - eval arg2) mod m
 *
 */
void fiat_25519_sub(fiat_25519_loose_field_element out1, const fiat_25519_tight_field_element arg1, const fiat_25519_tight_field_element arg2);

/*
 * The function fiat_25519_opp negates a field element.
 *
 * Postconditions:
 *   eval out1 mod m = -eval arg1 mod m
 *
 */
void fiat_25519_opp(fiat_25519_loose_field_element out1, const fiat_25519_tight_field_element arg1);

/*
 * The function fiat_25519_selectznz is a multi-limb conditional select.
 *
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [[0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff]]
 *   arg3: [[0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff], [0x0 ~> 0xffffffff]]
 */
void fiat_25519_selectznz(uint32_t out1[10], fiat_25519_uint1 arg1, const uint32_t arg2[10], const uint32_t arg3[10]);

/*
 * The function fiat_25519_to_bytes serializes a field element to bytes in little-endian order.
 *
 * Postconditions:
 *   out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..31]
 *
 * Output Bounds:
 *   out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 */
void fiat_25519_to_bytes(uint8_t out1[32], const fiat_25519_tight_field_element arg1);

/*
 * The function fiat_25519_from_bytes deserializes a field element from bytes in little-endian order.
 *
 * Postconditions:
 *   eval out1 mod m = bytes_eval arg1 mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 */
void fiat_25519_from_bytes(fiat_25519_tight_field_element out1, const uint8_t arg1[32]);

#ifdef __cplusplus
}
#endif

#endif /* _CURVE25519_H_ */
