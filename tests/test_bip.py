import hashlib
import hmac

from bip.bip32 import ExtendedPrivateKey, derive_path
from bip.bip39 import entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed
from bip.crypto_primitives import hmac_sha512, pbkdf2_hmac_sha512, ripemd160, sha256, sha512


def test_hashes_match_hashlib():
    msg = b"abc"
    assert sha256(msg).hex() == hashlib.sha256(msg).hexdigest()
    assert sha512(msg).hex() == hashlib.sha512(msg).hexdigest()
    assert ripemd160(msg).hex() == hashlib.new("ripemd160", msg).hexdigest()


def test_hmac_and_pbkdf2_match_stdlib():
    key = b"key"
    msg = b"data"
    assert hmac_sha512(key, msg) == hmac.new(key, msg, hashlib.sha512).digest()
    p = b"password"
    s = b"salt"
    assert pbkdf2_hmac_sha512(p, s, 2048, 64) == hashlib.pbkdf2_hmac("sha512", p, s, 2048, 64)


def test_bip39_roundtrip_and_seed():
    entropy = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    mnemonic = entropy_to_mnemonic(entropy)
    restored = mnemonic_to_entropy(mnemonic)
    assert restored == entropy
    expected = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonicTREZOR", 2048, 64)
    assert mnemonic_to_seed(mnemonic, "TREZOR") == expected


def test_bip32_public_private_nonhardened_agree():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    root = ExtendedPrivateKey.from_seed(seed)
    child_priv = derive_path(root, "m/0/1/2")
    child_pub_from_priv = child_priv.to_public().to_base58()

    root_pub = root.to_public()
    child_pub = root_pub.child(0).child(1).child(2).to_base58()
    assert child_pub == child_pub_from_priv


def test_bip32_hardened_requires_private():
    seed = b"test seed"
    root = ExtendedPrivateKey.from_seed(seed)
    pub = root.to_public()
    try:
        pub.child(0x80000000)
        assert False, "expected ValueError"
    except ValueError:
        pass
