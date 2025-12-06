# VOID

128-bit blocks. 256-bit keys. 24 rounds. One file.

My cipher, my choices. If your review starts and ends with the fact that you
would have chosen something else, save us both the time. The round function
and key schedule are right there in `void.py`; discuss those.

## Files

Python 3.10 or later, no dependencies. Generate a key, keep it somewhere you
can find again, then pass its 64 hex digits to the CLI:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))'
python3 void.py encrypt message.bin message.void --key YOUR_64_HEX_DIGITS
python3 void.py decrypt message.void restored.bin --key YOUR_64_HEX_DIGITS
```

The output file must not exist. Decryption verifies the envelope tag before
writing anything. This reads the whole input into memory; it's a small file
tool, not a streaming archive format. There is no password-to-key conversion.

## From Python

```python
from void import VOID

cipher = VOID(bytes(range(32)))  # fixed key for this example only
block = bytes(range(16))
assert cipher.decrypt_block(cipher.encrypt_block(block)) == block

sealed = cipher.seal(b"notes for myself")
assert cipher.unseal(sealed) == b"notes for myself"
```

Raw block methods take exactly 16 bytes. `seal()` chooses a fresh IV and adds
an HMAC-SHA256 tag; `unseal()` raises `ValueError` for a bad envelope or key.
All inputs here are `bytes`, not strings or mutable buffers.

`encrypt_cbc(data, iv)` and `decrypt_cbc(data, iv)` are also exposed. They do
padding, not authentication. The [envelope layout](FORMAT.md) describes what
`seal()` adds around them.

No compatibility promises for unpublished experiments. The `VOID` v1 envelope
is the format this checkout reads and writes. If you change it, change the
version byte instead of making everyone else guess.
