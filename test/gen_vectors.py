#!/usr/bin/env python3
# run this script: python3 gen_vectors.py

p = 2**255 - 19

def to_hex_bytes(n):
    return n.to_bytes(32, 'little').hex()

print("=== fe25519_invert test vectors ===\n")
print("static const struct { int input; const char* expected; } vectors[] = {")

for i in range(1, 11):
    inv = pow(i, p-2, p)
    print(f'    {{ {i:2d}, "{to_hex_bytes(inv)}" }},')
    # verify that the computed inverse is correct
    assert (i * inv) % p == 1

print("};")
print("\n=== Verification ===")
for i in range(1, 11):
    inv = pow(i, p-2, p)
    print(f"{i} * inv({i}) mod p = {(i * inv) % p} (should be 1)")
