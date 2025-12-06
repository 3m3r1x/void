# Envelope v1

Byte offsets, not hex character positions:

| Offset | Size | Contents |
| --- | ---: | --- |
| 0 | 5 | ASCII `VOID`, then `0x01` |
| 5 | 16 | IV |
| 21 | multiple of 16 | CBC ciphertext, at least one block |
| end - 32 | 32 | HMAC-SHA256 tag |

The tag covers everything before it, including the magic and IV. Its key is
SHA-256 of `b"VOID/mac/v1/" + key`. Check it before CBC decryption.

Padding always appends 1–16 bytes, each containing the padding length. An
empty plaintext therefore still produces a ciphertext block; the smallest
complete envelope is 69 bytes. Integers inside cipher blocks are big-endian.

The optional `seal(data, iv=...)` argument exists for repeatable examples.
Normal calls leave it out. Raw CBC output has neither this header nor a tag.
