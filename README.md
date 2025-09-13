# VOID

My block cipher experiment. The round function is in the source; if you
have an objection, point at an operation. Appeals to popularity bore me.

## Usage

```python
from void import VOID

cipher = VOID(bytes(range(32)))
encrypted = cipher.encrypt_block(bytes(16))
assert cipher.decrypt_block(encrypted) == bytes(16)
assert cipher.unseal(cipher.seal(b"notes for myself")) == b"notes for myself"
```
