# Pure Python BIP32 + BIP39 (Educational)

This repository implements BIP32 and BIP39 in pure Python, including the underlying cryptographic primitives:

- SHA-256
- SHA-512
- HMAC-SHA512
- PBKDF2-HMAC-SHA512
- RIPEMD-160
- secp256k1 scalar multiplication and point arithmetic
- Base58 + Base58Check

## Structure

- `bip/crypto_primitives.py` — hash and MAC primitives.
- `bip/secp256k1.py` — curve arithmetic.
- `bip/base58.py` — Bitcoin Base58 helpers.
- `bip/bip32.py` — HD key derivation and serialization.
- `bip/bip39.py` — mnemonic and seed handling.

## Note on wordlists

BIP39 operates over a 2048-word list. The implementation enforces that shape and allows loading custom wordlists.

## Quick example

```python
from bip import ExtendedPrivateKey, entropy_to_mnemonic, mnemonic_to_seed, derive_path

entropy = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
mnemonic = entropy_to_mnemonic(entropy)
seed = mnemonic_to_seed(mnemonic, passphrase="TREZOR")

master = ExtendedPrivateKey.from_seed(seed)
account0 = derive_path(master, "m/44'/0'/0'")
print(account0.to_base58())
```

## Tests

```bash
pytest -q
```
