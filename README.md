# X25519

Portable X25519 implementation for embedded and constrained systems.

## Field Arithmetic Backend

This directory contains generated finite field arithmetic for
Curve25519 (`2^255 - 19`) used by the X25519 implementation.

The backend is generated using
[`fiat-crypto`](https://github.com/mit-plv/fiat-crypto)
v0.1.16 with the following command:

```bash
./fiat-crypto unsaturated-solinas 25519 32 10 '2^255 - 19' \
carry_mul carry_square carry_scmul121666 relax add sub opp selectznz \
to_bytes from_bytes \
--lang C --internal-static --inline-internal \
--output fiat/curve25519_32.c
```

Target configuration:

- 32-bit backend
- 10-limb representation
- portable C implementation

Generated source files should not be manually modified.
