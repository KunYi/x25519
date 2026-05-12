/*
 * x25519.c
 */

#include "x25519.h"
#include "fe25519.h"

#include <string.h>

void x25519_scalarmult(
    uint8_t out[32],
    const uint8_t scalar[32],
    const uint8_t point[32])
{
    uint8_t e[32];

    memcpy(e, scalar, 32);
    e[0]  &= 0xF8;
    e[31] &= 0x7F;
    e[31] |= 0x40;

    fe25519_t x1, x2, z2, x3, z3;
    fe25519_t a, aa, b, bb, e1, c, d, da, cb, tmp0, tmp1, z2_inv, result;

    fe25519_frombytes(&x1, point);

    fe25519_one(&x2);  fe25519_zero(&z2);
    fe25519_copy(&x3, &x1);  fe25519_one(&z3);

    uint32_t swap = 0;

    for (int pos = 254; pos >= 0; --pos) {
        uint32_t bit = (e[pos >> 3] >> (pos & 7)) & 1u;

        swap ^= bit;

        fe25519_cswap(&x2, &x3, swap);
        fe25519_cswap(&z2, &z3, swap);

        swap = bit;

        fe25519_add(&a, &x2, &z2);
        fe25519_square(&aa, &a);
        fe25519_sub(&b, &x2, &z2);
        fe25519_square(&bb, &b);

        fe25519_sub(&e1, &aa, &bb);        // E = AA - BB

        fe25519_add(&c, &x3, &z3);
        fe25519_sub(&d, &x3, &z3);

        fe25519_mul(&da, &d, &a);
        fe25519_mul(&cb, &c, &b);

        fe25519_add(&tmp0, &da, &cb);
        fe25519_square(&x3, &tmp0);

        fe25519_sub(&tmp1, &da, &cb);
        fe25519_square(&tmp1, &tmp1);
        fe25519_mul(&z3, &x1, &tmp1);

        fe25519_mul(&x2, &aa, &bb);

        /* z2 = E * (AA + 121665 * E) */
        fe25519_mul121666(&tmp0, &e1);   // 121666 * E
        fe25519_sub(&tmp0, &tmp0, &e1);  // → 121665 * E
        fe25519_add(&tmp0, &aa, &tmp0);
        fe25519_mul(&z2, &e1, &tmp0);
    }

    fe25519_cswap(&x2, &x3, swap);
    fe25519_cswap(&z2, &z3, swap);

    fe25519_invert(&z2_inv, &z2);
    fe25519_mul(&result, &x2, &z2_inv);
    fe25519_tobytes(out, &result);

    /*
     * Clear sensitive data.
     */
    memset(e, 0, sizeof(e));

    memset(&x1, 0, sizeof(x1));
    memset(&x2, 0, sizeof(x2));
    memset(&z2, 0, sizeof(z2));
    memset(&x3, 0, sizeof(x3));
    memset(&z3, 0, sizeof(z3));

    memset(&a, 0, sizeof(a));
    memset(&aa, 0, sizeof(aa));
    memset(&b, 0, sizeof(b));
    memset(&bb, 0, sizeof(bb));
    memset(&e1, 0, sizeof(e1));
    memset(&c, 0, sizeof(c));
    memset(&d, 0, sizeof(d));
    memset(&da, 0, sizeof(da));
    memset(&cb, 0, sizeof(cb));
    memset(&tmp0, 0, sizeof(tmp0));
    memset(&tmp1, 0, sizeof(tmp1));

    memset(&z2_inv, 0, sizeof(z2_inv));
    memset(&result, 0, sizeof(result));
}

void x25519_public_key(
    uint8_t pub[32],
    const uint8_t priv[32])
{
    static const uint8_t x25519_basepoint[32] = { 9 };

    x25519_scalarmult(pub, priv, x25519_basepoint);
}
