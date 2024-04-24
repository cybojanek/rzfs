
SHA 256
=======

Test Case Generation
--------------------

Python script to generate test cases for `checksum::sha256::tests`.

```python
#!/usr/bin/env python3
import hashlib
import struct

test_vector = [
  0xbc, 0x4b, 0x4d, 0x58, 0x43, 0xca, 0x34, 0x35, 0xe4, 0xd0, 0x59, 0xe4, 0xd0, 0x2b, 0x08,
  0xe3, 0x2f, 0xe3, 0x78, 0xe1, 0xe6, 0xf6, 0xf1, 0x34, 0x84, 0xdc, 0x1e, 0x0e, 0x12, 0x28,
  0x2e, 0xbe, 0x53, 0xbd, 0x1a, 0xf9, 0x8a, 0x97, 0x6e, 0xab, 0x7c, 0x06, 0xed, 0x50, 0xa8,
  0xc9, 0xe4, 0x1e, 0xb8, 0xaf, 0xb8, 0x8c, 0x94, 0xb5, 0x15, 0xed, 0xa8, 0x3f, 0x9d, 0x99,
  0x9c, 0x26, 0xe8, 0x1d, 0x87, 0x29, 0x1f, 0x60, 0x64, 0xca, 0xd1, 0xe8, 0x48, 0x7e, 0xe4,
  0xf2, 0x56, 0xf3, 0x59, 0x73, 0x04, 0x39, 0xb2, 0x62, 0x56, 0xea, 0xf1, 0x44, 0xf0, 0x06,
  0x28, 0x2e, 0x56, 0x16, 0xd3, 0x80, 0x0d, 0x47, 0x9e, 0x87, 0x3f, 0x52, 0x64, 0x30, 0x63,
  0x6d, 0x64, 0x58, 0xcb, 0x84, 0x4d, 0xf7, 0x1c, 0x6e, 0xc7, 0x07, 0x86, 0x3d, 0x17, 0xec,
  0x51, 0x8f, 0x51, 0x6e, 0x5a, 0x52, 0x64, 0xee,
]

for size in 0, 4, 8, 16, 32, 64, 128:
    h = hashlib.sha256()

    h.update(bytes(test_vector[0:size]))

    digest = h.digest()
    a, b, c, d = struct.unpack(">QQQQ", digest)[0:4]

    print(f"({size}, [{a:#016x}, {b:#016x}, {c:#016x}, {d:#016x}]), ")


for size in 192, 256, 320, 384, 448, 512, 8192, 16384, 32768, 65536, 131072:
    total = 0

    h = hashlib.sha256()

    while total < size:
        todo = min(size - total, len(test_vector))
        h.update(bytes(test_vector[0:todo]))
        total += todo

    digest = h.digest()
    a, b, c, d = struct.unpack(">QQQQ", digest)[0:4]

    print(f"({size}, [{a:#016x}, {b:#016x}, {c:#016x}, {d:#016x}]), ")
```