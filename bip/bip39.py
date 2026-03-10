from __future__ import annotations

from pathlib import Path

from .crypto_primitives import pbkdf2_hmac_sha512, sha256


WORDLIST_PATH = Path(__file__).with_name("wordlist_english.txt")


def load_wordlist(path: Path = WORDLIST_PATH) -> list[str]:
    words = [w.strip() for w in path.read_text(encoding="utf-8").splitlines() if w.strip()]
    if len(words) != 2048:
        raise ValueError("BIP39 wordlist must have exactly 2048 entries")
    if len(set(words)) != 2048:
        raise ValueError("BIP39 wordlist must not contain duplicates")
    return words


def entropy_to_mnemonic(entropy: bytes, wordlist: list[str] | None = None) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be one of 128/160/192/224/256 bits")
    words = wordlist or load_wordlist()
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    checksum = sha256(entropy)
    bitstr = "".join(f"{b:08b}" for b in entropy) + "".join(f"{b:08b}" for b in checksum)[:cs_bits]
    indices = [int(bitstr[i : i + 11], 2) for i in range(0, len(bitstr), 11)]
    return " ".join(words[i] for i in indices)


def mnemonic_to_entropy(mnemonic: str, wordlist: list[str] | None = None) -> bytes:
    words = wordlist or load_wordlist()
    selected = mnemonic.strip().split()
    if len(selected) not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic must contain 12/15/18/21/24 words")
    lookup = {w: i for i, w in enumerate(words)}
    try:
        bits = "".join(f"{lookup[w]:011b}" for w in selected)
    except KeyError as exc:
        raise ValueError(f"word not in wordlist: {exc.args[0]}") from exc

    total = len(bits)
    ent_bits = (total * 32) // 33
    cs_bits = total - ent_bits

    entropy = int(bits[:ent_bits], 2).to_bytes(ent_bits // 8, "big")
    checksum_bits = bits[ent_bits:]
    actual_checksum = "".join(f"{b:08b}" for b in sha256(entropy))[:cs_bits]
    if checksum_bits != actual_checksum:
        raise ValueError("invalid mnemonic checksum")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    sentence = " ".join(mnemonic.strip().split())
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return pbkdf2_hmac_sha512(sentence.encode("utf-8"), salt, iterations=2048, dklen=64)
