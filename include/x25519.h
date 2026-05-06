#pragma once
#ifndef _X25519_H_
#define _X25519_H_
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X25519_KEY_SIZE 32


/**
 * @brief Perform X25519 scalar multiplication.
 *
 * Computes:
 *
 *   out = scalar * point
 *
 * according to RFC7748.
 *
 * @param[out] out     32-byte shared secret/output point.
 * @param[in]  scalar  32-byte scalar/private key.
 * @param[in]  point   32-byte u-coordinate input point.
 */
void x25519_scalarmult(
    uint8_t out[X25519_KEY_SIZE],
    const uint8_t scalar[X25519_KEY_SIZE],
    const uint8_t point[X25519_KEY_SIZE]);

/**
 * @brief Generate X25519 public key from private key.
 *
 * Computes:
 *
 *   pub = priv * basepoint
 *
 * where basepoint = 9.
 *
 * @param[out] pub   32-byte public key.
 * @param[in]  priv  32-byte private key.
 */
void x25519_public_key(
    uint8_t pub[X25519_KEY_SIZE],
    const uint8_t priv[X25519_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* end of _X25519_H_ */
