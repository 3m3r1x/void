"""VOID: 3m3r1x's 128-bit block cipher with a 256-bit key."""

import argparse
import hashlib
import hmac
from pathlib import Path
import secrets
import sys


BLOCK_SIZE = 16
KEY_SIZE = 32
ROUNDS = 24
MASK = (1 << 64) - 1
MAGIC = b"VOID\x01"
TAG_SIZE = 32


def _bytes(value, name, size=None):
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be bytes")
    if size is not None and len(value) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes")
    return value


def _rol(value, distance):
    return ((value << distance) | (value >> (64 - distance))) & MASK


def _round(value, subkey):
    word = ((value ^ subkey) + _rol(value, 17)) & MASK
    word ^= _rol(word, 23)
    word = (word * 0xD6E8FEB86659FD93) & MASK
    return word ^ _rol(word, 41)


def _expand(key):
    state = [int.from_bytes(key[i:i + 8], "big") for i in range(0, KEY_SIZE, 8)]
    result = []
    for index in range(ROUNDS):
        slot = index % 4
        word = (state[slot] + state[(slot + 1) % 4] + 0x9E3779B97F4A7C15 + index) & MASK
        state[slot] = _rol(word, (11 + index) % 63 + 1)
        result.append(state[slot] ^ _rol(state[(slot + 2) % 4], 29))
    return tuple(result)


def _pad(data):
    amount = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([amount]) * amount


def _unpad(data):
    if not data:
        raise ValueError("invalid padding")
    amount = data[-1]
    if not 1 <= amount <= BLOCK_SIZE or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("invalid padding")
    return data[:-amount]


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


class VOID:
    def __init__(self, key):
        key = _bytes(key, "key", KEY_SIZE)
        self._keys = _expand(key)
        self._mac_key = hashlib.sha256(b"VOID/mac/v1/" + key).digest()

    def encrypt_block(self, block):
        block = _bytes(block, "block", BLOCK_SIZE)
        left = int.from_bytes(block[:8], "big")
        right = int.from_bytes(block[8:], "big")
        for subkey in self._keys:
            left, right = right, left ^ _round(right, subkey)
        return left.to_bytes(8, "big") + right.to_bytes(8, "big")

    def decrypt_block(self, block):
        block = _bytes(block, "block", BLOCK_SIZE)
        left = int.from_bytes(block[:8], "big")
        right = int.from_bytes(block[8:], "big")
        for subkey in reversed(self._keys):
            left, right = right ^ _round(left, subkey), left
        return left.to_bytes(8, "big") + right.to_bytes(8, "big")

    def encrypt_cbc(self, data, iv):
        data = _pad(_bytes(data, "data"))
        previous = _bytes(iv, "iv", BLOCK_SIZE)
        output = []
        for offset in range(0, len(data), BLOCK_SIZE):
            previous = self.encrypt_block(_xor(data[offset:offset + BLOCK_SIZE], previous))
            output.append(previous)
        return b"".join(output)

    def decrypt_cbc(self, data, iv):
        data = _bytes(data, "data")
        previous = _bytes(iv, "iv", BLOCK_SIZE)
        if not data or len(data) % BLOCK_SIZE:
            raise ValueError("ciphertext must contain complete blocks")
        output = []
        for offset in range(0, len(data), BLOCK_SIZE):
            block = data[offset:offset + BLOCK_SIZE]
            output.append(_xor(self.decrypt_block(block), previous))
            previous = block
        return _unpad(b"".join(output))

    def seal(self, data, iv=None):
        if iv is None:
            iv = secrets.token_bytes(BLOCK_SIZE)
        body = MAGIC + _bytes(iv, "iv", BLOCK_SIZE) + self.encrypt_cbc(data, iv)
        tag = hmac.new(self._mac_key, body, hashlib.sha256).digest()
        return body + tag

    def unseal(self, envelope):
        envelope = _bytes(envelope, "envelope")
        minimum = len(MAGIC) + BLOCK_SIZE + BLOCK_SIZE + TAG_SIZE
        if len(envelope) < minimum or not envelope.startswith(MAGIC):
            raise ValueError("invalid VOID envelope")
        body, tag = envelope[:-TAG_SIZE], envelope[-TAG_SIZE:]
        expected = hmac.new(self._mac_key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("authentication failed")
        start = len(MAGIC)
        return self.decrypt_cbc(body[start + BLOCK_SIZE:], body[start:start + BLOCK_SIZE])


def main(argv=None):
    parser = argparse.ArgumentParser(description="VOID file encryption")
    parser.add_argument("action", choices=("encrypt", "decrypt"))
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--key", required=True, help="32-byte key as 64 hexadecimal digits")
    args = parser.parse_args(argv)
    try:
        cipher = VOID(bytes.fromhex(args.key))
        data = args.input.read_bytes()
        result = cipher.seal(data) if args.action == "encrypt" else cipher.unseal(data)
        args.output.write_bytes(result)
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
