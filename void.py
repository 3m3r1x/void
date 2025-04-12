"""VOID: 3m3r1x's 128-bit block cipher with a 256-bit key."""

import argparse
import hashlib
import hmac
from pathlib import Path
import secrets
import sys


BLOCK_SIZE = 16
KEY_SIZE = 32
ROUNDS = 8
MASK = (1 << 64) - 1
MAGIC = b"VOID\x01"
TAG_SIZE = 32


def _bytes(value, name, size=None):
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} must be bytes")
    if size is not None and len(value) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes")
    return bytes(value)


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
