from fast_stark_crypto.fast_stark_crypto import (
    rs_get_public_key,
    rs_compute_pedersen_hash,
    rs_sign_message,
    rs_verify_signature,
)


def get_public_key(private_key: int) -> int:
    return int(rs_get_public_key(hex(private_key)))


def pedersen_hash(first: int, second: int) -> int:
    return int(rs_compute_pedersen_hash(hex(first), hex(second)))


def sign(private_key: int, msg_hash: int, k: int) -> tuple[int, int]:
    (r, s) = rs_sign_message(hex(private_key), hex(msg_hash), hex(k))
    return (int(r), int(s))


def verify(public_key: int, msg_hash: int, r: int, s: int) -> bool:
    return rs_verify_signature(hex(public_key), hex(msg_hash), hex(r), hex(s))
