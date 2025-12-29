import base64
import hashlib
import hmac
import json
import os
import secrets
import math
from typing import Optional

from .paths import DECRYPTED_DIR, ENCRYPTED_DIR
from .utils import (
    calc_doc_hash_bytes,
    log_event,
    now_iso,
    safe_load_data,
    safe_save_data,
)

__all__ = [
    "generate_keys",
    "load_keys",
    "sign_document",
    "verify_signature",
    "generate_imito",
    "xor_cipher",
    "encrypt_file",
    "decrypt_file",
    "mgm_encrypt",
    "mgm_decrypt",
    "encrypt_file_mgm",
    "decrypt_file_mgm",
    "dh_generate_keypair",
    "dh_derive_shared_secret",
    "elgamal_sign",
    "elgamal_verify",
]


def generate_keys(username: str) -> str:
    existing = safe_load_data(f"keys:{username}", None)
    if existing and existing.get("private_key") and existing.get("public_key"):
        log_event(username, "generate_keys", "skip", extra={"reason": "already_exists"})
        raise ValueError("Ключи уже созданы для этого пользователя")

    private_key = secrets.token_bytes(32)
    public_key = hashlib.sha256(private_key).hexdigest()
    key_data = {
        "username": username,
        "private_key": private_key.hex(),
        "public_key": public_key,
    }
    key_id = f"keys:{username}"
    safe_save_data(key_id, key_data)
    log_event(username, "generate_keys", "ok", extra={"key_id": key_id})
    return key_id


def load_keys(username: str):
    key_id = f"keys:{username}"
    data = safe_load_data(key_id, {})
    if not data:
        raise FileNotFoundError(f"Ключи пользователя {username} не найдены")
    return data


def dh_generate_keypair() -> dict:
    """Generate a Diffie–Hellman keypair using a fixed 2048-bit safe prime (RFC 3526 group 14)."""

    prime_hex = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"  # RFC 3526 group 14
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
    )
    p = int(prime_hex, 16)
    g = 2
    private = secrets.randbelow(p - 2) + 1
    public = pow(g, private, p)
    return {"p": p, "g": g, "private": private, "public": public}


def dh_derive_shared_secret(own_private: int, peer_public: int, p: int) -> bytes:
    """Derive a shared secret using Diffie–Hellman."""

    shared = pow(peer_public, own_private, p)
    return hashlib.sha256(shared.to_bytes((shared.bit_length() + 7) // 8, "big")).digest()


def sign_document(username: str, file_path: str, doc_id: Optional[str] = None) -> str:
    keys = load_keys(username)
    if not keys or "private_key" not in keys:
        raise ValueError("Ключи пользователя не найдены/некорректны")

    with open(file_path, "rb") as f:
        data = f.read()

    doc_hash = calc_doc_hash_bytes(data)

    # Если у документа есть ID, проверяем привязанный индекс по doc_id, чтобы не зависеть
    # от совпадений хэшей разных файлов.
    if doc_id:
        existing_sig = safe_load_data(f"signature_doc_index:{doc_id}", None)
        if existing_sig:
            sig_payload = safe_load_data(existing_sig, {})
            # Если документ уже подписан (тем же или другим пользователем), блокируем повтор
            # подписания, так как этап считается пройденным.
            signer_name = sig_payload.get("username", "")
            raise ValueError("Пользователь уже подписывал этот документ" if signer_name == username else "Документ уже подписан")
        index_key = f"signature_index:{doc_id}:{username}"
    else:
        index_key = f"signature_index:{doc_hash}:{username}"
        existing_sig = safe_load_data(index_key, None)
        if existing_sig:
            raise ValueError("Пользователь уже подписывал этот документ")

    private_key_bytes = bytes.fromhex(keys["private_key"])
    signature_raw = hashlib.sha256(bytes.fromhex(doc_hash) + private_key_bytes).hexdigest()

    signature = {
        "doc_hash": doc_hash,
        "username": username,
        "signature": signature_raw,
        "timestamp": now_iso(),
        "doc_id": doc_id,
    }

    sig_id = f"signature:{os.path.basename(file_path)}:{signature['timestamp']}"
    safe_save_data(sig_id, signature)
    if doc_id:
        safe_save_data(f"signature_doc_index:{doc_id}", sig_id)
    safe_save_data(index_key, sig_id)

    log_event(username, "sign", "ok", doc_id=doc_id or os.path.basename(file_path), extra={"sig_id": sig_id})
    return sig_id


def verify_signature(file_path: str, sig_path: str) -> bool:
    sig = safe_load_data(sig_path, {})
    username = sig.get("username")
    if not username:
        return False

    keys = load_keys(username)
    with open(file_path, "rb") as f:
        data = f.read()

    doc_hash = calc_doc_hash_bytes(data)
    if doc_hash != sig.get("doc_hash"):
        return False

    private_key_bytes = bytes.fromhex(keys["private_key"])
    expected_sig = hashlib.sha256(bytes.fromhex(doc_hash) + private_key_bytes).hexdigest()
    return expected_sig == sig.get("signature")


def elgamal_sign(message: bytes, private_key: int, p: int, g: int) -> dict:
    """Sign a message digest with ElGamal (mod p)."""

    m_int = int.from_bytes(hashlib.sha256(message).digest(), "big") % (p - 1)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = ((m_int - private_key * r) * k_inv) % (p - 1)
    return {"r": r, "s": s}


def elgamal_verify(message: bytes, signature: dict, public_key: int, p: int, g: int) -> bool:
    """Verify an ElGamal signature."""

    r = signature.get("r")
    s = signature.get("s")
    if not isinstance(r, int) or not isinstance(s, int) or not (0 < r < p):
        return False
    m_int = int.from_bytes(hashlib.sha256(message).digest(), "big") % (p - 1)
    left = pow(g, m_int, p)
    right = (pow(public_key, r, p) * pow(r, s, p)) % p
    return left == right


def xor_cipher(data: bytes, key: bytes) -> bytes:
    res = bytearray()
    key_len = len(key)
    for i, b in enumerate(data):
        res.append(b ^ key[i % key_len])
    return bytes(res)


def generate_imito(key: bytes, data: bytes, size: int = 16) -> str:
    """Compute an imitovstavka (MAC) for integrity control."""

    mac = hmac.new(key, data, hashlib.blake2b, digest_size=size)
    return mac.hexdigest()


def _mgm_keystream_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    seed = nonce + counter.to_bytes(8, "big")
    return hmac.new(key, seed, hashlib.sha256).digest()


def mgm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"", nonce: Optional[bytes] = None) -> dict:
    """Toy MGM*-style AEAD using HMAC-based keystream and BLAKE2b tag."""

    if nonce is None:
        nonce = secrets.token_bytes(16)
    ciphertext = bytearray()
    counter = 0
    for offset in range(0, len(plaintext), 32):
        block = plaintext[offset : offset + 32]
        stream = _mgm_keystream_block(key, nonce, counter)
        ciphertext.extend(x ^ y for x, y in zip(block, stream))
        counter += 1
    tag_ctx = hashlib.blake2b(key=key, digest_size=16)
    tag_ctx.update(nonce)
    tag_ctx.update(associated_data)
    tag_ctx.update(bytes(ciphertext))
    tag = tag_ctx.hexdigest()
    return {"nonce": base64.b64encode(nonce).decode("ascii"), "ciphertext": base64.b64encode(bytes(ciphertext)).decode("ascii"), "tag": tag}


def mgm_decrypt(key: bytes, packet: dict, associated_data: bytes = b"") -> bytes:
    """Decrypt and verify MGM* packet."""

    nonce = base64.b64decode(packet["nonce"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    tag_expected = packet.get("tag")
    tag_ctx = hashlib.blake2b(key=key, digest_size=16)
    tag_ctx.update(nonce)
    tag_ctx.update(associated_data)
    tag_ctx.update(ciphertext)
    tag_actual = tag_ctx.hexdigest()
    if tag_expected != tag_actual:
        raise ValueError("Нарушена целостность MGM: тэг не совпадает")
    plaintext = bytearray()
    counter = 0
    for offset in range(0, len(ciphertext), 32):
        block = ciphertext[offset : offset + 32]
        stream = _mgm_keystream_block(key, nonce, counter)
        plaintext.extend(x ^ y for x, y in zip(block, stream))
        counter += 1
    return bytes(plaintext)


def encrypt_file(username: str, file_path: str, doc_id: Optional[str] = None) -> str:
    with open(file_path, "rb") as f:
        data = f.read()

    sym_key = secrets.token_bytes(32)
    plain_hash = calc_doc_hash_bytes(data)

    encrypted = xor_cipher(data, sym_key)
    mac = hmac.new(sym_key, encrypted, hashlib.sha256).hexdigest()
    imito = generate_imito(sym_key, data)

    created_at = now_iso()
    safe_ts = created_at.replace(":", "-")
    enc_filename = f"{os.path.basename(file_path)}.{safe_ts}.enc.json"
    enc_path = os.path.join(ENCRYPTED_DIR, enc_filename)

    packet = {
        "sym_key": base64.b64encode(sym_key).decode("ascii"),
        "data": base64.b64encode(encrypted).decode("ascii"),
        "original_name": os.path.basename(file_path),
        "plain_hash": plain_hash,
        "hmac_sha256": mac,
        "imitovstavka": imito,
        "created_at": created_at,
    }

    enc_id = f"encrypted:{os.path.basename(file_path)}:{packet['created_at']}"
    safe_save_data(enc_id, {**packet, "__file_path": enc_path})

    with open(enc_path, "w", encoding="utf-8") as f:
        json.dump(packet, f, ensure_ascii=False, indent=2)

    log_event(
        username,
        "encrypt",
        "ok",
        doc_id=doc_id or os.path.basename(file_path),
        extra={"enc_id": enc_id, "enc_file": enc_path},
    )
    return enc_path


def decrypt_file(username: str, enc_path: str, doc_id: Optional[str] = None) -> str:
    packet = {}
    if os.path.isfile(enc_path):
        with open(enc_path, "r", encoding="utf-8") as f:
            try:
                packet = json.load(f)
            except json.JSONDecodeError:
                packet = {}
    if not packet:
        packet = safe_load_data(enc_path, {})
        if isinstance(packet, dict):
            file_variant = packet.get("__file_path")
            if file_variant and os.path.isfile(file_variant):
                with open(file_variant, "r", encoding="utf-8") as f:
                    try:
                        packet = json.load(f)
                    except json.JSONDecodeError:
                        pass
    if not packet:
        raise ValueError("Некорректный пакет шифрования")

    sym_key = base64.b64decode(packet["sym_key"])
    encrypted = base64.b64decode(packet["data"])

    mac_expected = packet.get("hmac_sha256")
    mac_actual = hmac.new(sym_key, encrypted, hashlib.sha256).hexdigest()
    if mac_expected and mac_actual != mac_expected:
        log_event(
            username,
            "decrypt",
            "fail",
            doc_id=doc_id or packet.get("original_name"),
            extra={"reason": "HMAC mismatch"},
        )
        raise ValueError("Нарушена целостность: HMAC не совпадает")

    decrypted = xor_cipher(encrypted, sym_key)

    imito_expected = packet.get("imitovstavka")
    if imito_expected:
        imito_actual = generate_imito(sym_key, decrypted)
        if imito_actual != imito_expected:
            log_event(
                username,
                "decrypt",
                "fail",
                doc_id=doc_id or packet.get("original_name"),
                extra={"reason": "Imito mismatch"},
            )
            raise ValueError("Нарушена целостность: имитовставка не совпадает")

    plain_hash_expected = packet.get("plain_hash")
    plain_hash_actual = calc_doc_hash_bytes(decrypted)
    if plain_hash_expected and plain_hash_actual != plain_hash_expected:
        log_event(
            username,
            "decrypt",
            "fail",
            doc_id=doc_id or packet.get("original_name"),
            extra={"reason": "Plain hash mismatch"},
        )
        raise ValueError("Нарушена целостность: хэш исходного документа не совпадает")

    original_name = packet.get("original_name", "decrypted.bin")
    out_name = "decrypted_" + original_name
    out_path = os.path.join(DECRYPTED_DIR, out_name)
    with open(out_path, "wb") as f:
        f.write(decrypted)

    log_event(username, "decrypt", "ok", doc_id=doc_id or original_name, extra={"dec_file": out_path})
    return out_path


def encrypt_file_mgm(username: str, file_path: str, associated_data: Optional[bytes] = None) -> str:
    with open(file_path, "rb") as f:
        data = f.read()

    key = secrets.token_bytes(32)
    ad = associated_data or b""
    packet = mgm_encrypt(key, data, ad)
    packet.update(
        {
            "key": base64.b64encode(key).decode("ascii"),
            "associated_data": base64.b64encode(ad).decode("ascii"),
            "original_name": os.path.basename(file_path),
            "created_at": now_iso(),
        }
    )

    safe_ts = packet["created_at"].replace(":", "-")
    enc_filename = f"{os.path.basename(file_path)}.{safe_ts}.mgm.json"
    enc_path = os.path.join(ENCRYPTED_DIR, enc_filename)
    with open(enc_path, "w", encoding="utf-8") as f:
        json.dump(packet, f, ensure_ascii=False, indent=2)
    safe_save_data(f"mgm:{os.path.basename(file_path)}:{packet['created_at']}", {**packet, "__file_path": enc_path})
    log_event(username, "mgm_encrypt", "ok", doc_id=os.path.basename(file_path), extra={"enc_file": enc_path})
    return enc_path


def decrypt_file_mgm(username: str, enc_path: str, associated_data: Optional[bytes] = None) -> str:
    packet = {}
    if os.path.isfile(enc_path):
        with open(enc_path, "r", encoding="utf-8") as f:
            try:
                packet = json.load(f)
            except json.JSONDecodeError:
                packet = {}
    if not packet:
        packet = safe_load_data(enc_path, {})
        if isinstance(packet, dict):
            file_variant = packet.get("__file_path")
            if file_variant and os.path.isfile(file_variant):
                with open(file_variant, "r", encoding="utf-8") as f:
                    try:
                        packet = json.load(f)
                    except json.JSONDecodeError:
                        pass
    if not packet:
        raise ValueError("Некорректный MGM-пакет")

    key = base64.b64decode(packet["key"])
    ad = associated_data if associated_data is not None else base64.b64decode(packet.get("associated_data", ""))
    plaintext = mgm_decrypt(key, packet, ad)

    out_name = "mgm_decrypted_" + packet.get("original_name", "decrypted.bin")
    out_path = os.path.join(DECRYPTED_DIR, out_name)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    log_event(username, "mgm_decrypt", "ok", doc_id=packet.get("original_name"), extra={"dec_file": out_path})
    return out_path
