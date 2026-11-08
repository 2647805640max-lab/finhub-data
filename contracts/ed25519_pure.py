"""Pure-Python Ed25519 (RFC 8032) — standard library only.

Why this module exists
----------------------
The investment-decision integrity gate must sign ``board.json`` rulings with a
**non-symmetric** signature.  The public key ships inside a public repository,
so a shared secret (HMAC) is readable by every reader of that repository and is
therefore worthless as tamper evidence.  Only asymmetric signatures survive
that threat model, and the private key must never leave the local machine.

Constraint that shapes the whole implementation
-----------------------------------------------
CI runs ``actions/setup-python@v5`` + Python 3.12 with **no ``pip install``
step**.  That rules out ``cryptography`` / ``PyNaCl`` / ``ecdsa`` /
``pycryptodome``.  The standard library gives us exactly what Ed25519 needs:
``hashlib`` (SHA-512), ``json`` (canonical serialisation), ``secrets`` (key
generation).  No other dependency is used or permitted in this file.

What is implemented
-------------------
* Curve ``edwards25519`` (RFC 8032 §5.1):
  ``p = 2**255 - 19``, ``d = -121665 / 121666 (mod p)``,
  group order ``L = 2**252 + 27742317777372353535851937790883648493``.
* Point arithmetic in **extended twisted Edwards coordinates**
  ``(X : Y : Z : T)`` with ``x = X/Z``, ``y = Y/Z`` and ``xy = T/Z``.
* Scalar multiplication by plain double-and-add over the 252-bit scalars.
* RFC 8032 §5.1.6 (sign) and §5.1.7 (verify), byte-for-byte compatible with
  every other Ed25519 implementation (tested against ``cryptography`` and
  ``pycryptodome`` in the test-suite only).

Fail-closed contract
--------------------
``verify()`` is **total**: every malformed input — wrong length, ``s >= L``,
a point that is not on the curve, a tampered signature, a non-bytes argument —
returns ``False``.  It never raises.  For a gate that decides whether a ruling
is authentic, "cannot tell" must mean "not authentic", never "crash the
pipeline" and never "accept".

``sign()`` and ``private_key_to_public_key()`` *do* raise ``ValueError`` on a
malformed private key.  That is a caller bug (a truncated seed), not untrusted
input, and silently signing with a wrong key would be far more dangerous than
a loud failure.

Hex handling is split the same way.  ``verify()`` accepts the public key and
the signature either as raw bytes or as a hex string, and returns ``False``
for malformed hex — so the verification boundary itself can never crash.
``hex_to_key()`` is the explicit-decoding helper and raises ``ValueError`` on
malformed hex, so a truncated key is never silently produced.  Use whichever
matches the call site: ``verify(msg, sig, stored_hex)`` for a fail-closed
path, ``hex_to_key(stored_hex)`` when the caller wants the error message.

Only the standard library is imported here — deliberately.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

__all__ = [
    "generate_private_key",
    "private_key_to_public_key",
    "sign",
    "verify",
    "key_to_hex",
    "hex_to_key",
    "canonical_json",
]

__version__ = "1.0.0"


# --------------------------------------------------------------------------
# Curve constants (RFC 8032 §5.1)
# --------------------------------------------------------------------------

#: Field prime p = 2**255 - 19.
_P = 2**255 - 19

#: Order of the prime-order subgroup: L = 2**252 + 27742317777372353535851937790883648493.
_L = 2**252 + 27742317777372353535851937790883648493

#: Curve constant d = -121665 / 121666 (mod p).
_D = (-121665 * pow(121666, _P - 2, _P)) % _P

#: 2*d, precomputed for the extended-coordinate addition formula.
_D2 = (2 * _D) % _P

#: sqrt(-1) mod p = 2**((p-1)/4); used by point decompression.
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

#: Byte length of a raw Ed25519 seed / public key.
KEY_LEN = 32

#: Byte length of a raw Ed25519 signature (R || S).
SIG_LEN = 64

#: Mask selecting the low 255 bits of a 32-byte little-endian encoding.
_LOW_255 = (1 << 255) - 1

#: The only characters accepted by :func:`hex_to_key`.
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


# --------------------------------------------------------------------------
# Field / group helpers
# --------------------------------------------------------------------------


def _sha512(*chunks: bytes) -> bytes:
    """SHA-512 over the concatenation of ``chunks``."""
    digest = hashlib.sha512()
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def _recover_x(y: int, sign: int) -> int | None:
    """Recover the x-coordinate of the curve point with the given y and sign.

    Solves ``x**2 = (y**2 - 1) / (d*y**2 + 1)`` and returns ``None`` when no
    such point exists (i.e. the encoded value does not decode to a curve
    point).  ``sign`` is 0 for an even x and 1 for an odd x.
    """
    y2 = (y * y) % _P
    u = (y2 - 1) % _P          # numerator
    v = (_D * y2 + 1) % _P      # denominator

    x = (u * pow(v, _P - 2, _P)) % _P
    x = pow(x, (_P + 3) // 8, _P)

    if (x * x % _P * v - u) % _P != 0:
        # Candidate is wrong by a factor of sqrt(-1); try the other root.
        x = (x * _SQRT_M1) % _P
        if (x * x % _P * v - u) % _P != 0:
            return None

    if x == 0 and sign == 1:
        # A zero x-coordinate has only one sign; the encoding is invalid.
        return None

    if (x & 1) != sign:
        x = (_P - x) % _P
    return x


# --------------------------------------------------------------------------
# Extended twisted Edwards coordinates: (X : Y : Z : T), x = X/Z, y = Y/Z, xy = T/Z
# --------------------------------------------------------------------------

#: Neutral element (0 : 1 : 1 : 0).
_IDENTITY = (0, 1, 1, 0)


def _point_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Add two curve points (RFC 8032 §5.1.4 unified addition formula)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2

    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * _D2 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P

    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _point_double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Double a curve point (a = -1 twisted Edwards doubling formula)."""
    x1, y1, z1, _t1 = p

    a = (x1 * x1) % _P
    b = (y1 * y1) % _P
    c = (2 * z1 * z1) % _P
    d = (-a) % _P                              # a_curve * A with a_curve = -1
    e = (((x1 + y1) * (x1 + y1)) - a - b) % _P
    g = (d + b) % _P
    f = (g - c) % _P
    h = (d - b) % _P

    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Compute ``scalar * point`` by double-and-add.

    ``scalar`` must be a non-negative integer; it is reduced modulo the group
    order by the caller where the specification requires it.
    """
    if scalar <= 0:
        return _IDENTITY
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        scalar >>= 1
    return result


def _point_equal(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> bool:
    """Compare two projective points without an expensive inversion."""
    x1, y1, z1, _t1 = p1
    x2, y2, z2, _t2 = p2
    return ((x1 * z2 - x2 * z1) % _P == 0) and ((y1 * z2 - y2 * z1) % _P == 0)


def _point_encode(point: tuple[int, int, int, int]) -> bytes:
    """Encode a point as 32 little-endian bytes: y with the sign of x in bit 255."""
    x, y, z, _t = point
    z_inv = pow(z, _P - 2, _P)
    x_aff = (x * z_inv) % _P
    y_aff = (y * z_inv) % _P
    return (y_aff | ((x_aff & 1) << 255)).to_bytes(32, "little")


def _point_decode(data: bytes) -> tuple[int, int, int, int] | None:
    """Decode 32 little-endian bytes into a curve point, or ``None`` if invalid.

    Rejects (RFC 8032 §5.1.3): wrong length, a y-coordinate >= p, a y that
    does not correspond to any curve point, and the invalid ``x = 0, sign = 1``
    encoding.
    """
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = (value >> 255) & 1
    y = value & _LOW_255
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


# --------------------------------------------------------------------------
# Key handling
# --------------------------------------------------------------------------


def _expand_secret(seed: bytes) -> tuple[int, bytes]:
    """Expand a 32-byte seed into the clamped scalar ``a`` and the nonce prefix.

    Per RFC 8032 §5.1.5: ``h = SHA-512(seed)``; the scalar is the low 255 bits
    of ``h[0:32]`` with the low three bits cleared and bit 254 set; the nonce
    prefix is ``h[32:64]``.
    """
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8          # clear the three low bits (a[0] &= 248)
    a |= 1 << 254                # set bit 254           (a[31] |= 64)
    return a, h[32:]


def generate_private_key() -> bytes:
    """Return a fresh 32-byte Ed25519 private key (the seed).

    Uses ``secrets.token_bytes`` (OS CSPRNG).  The returned value is the raw
    seed — the same bytes RFC 8032 calls the "secret key".
    """
    return secrets.token_bytes(KEY_LEN)


def private_key_to_public_key(sk: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte private key seed.

    Raises ``ValueError`` if ``sk`` is not exactly 32 bytes.
    """
    if not isinstance(sk, (bytes, bytearray)):
        raise ValueError("private key must be bytes, got %r" % type(sk).__name__)
    sk = bytes(sk)
    if len(sk) != KEY_LEN:
        raise ValueError("private key must be %d bytes, got %d" % (KEY_LEN, len(sk)))
    a, _prefix = _expand_secret(sk)
    return _point_encode(_scalar_mult(a, _BASE_POINT))


# --------------------------------------------------------------------------
# Signing / verification
# --------------------------------------------------------------------------


def sign(message: bytes, sk: bytes) -> bytes:
    """Sign ``message`` with the 32-byte private key seed ``sk``.

    Implements RFC 8032 §5.1.6 and returns the 64-byte signature ``R || S``.

    Raises ``ValueError`` if ``sk`` is not exactly 32 bytes or if ``message``
    is not a bytes-like object.
    """
    if not isinstance(sk, (bytes, bytearray)):
        raise ValueError("private key must be bytes, got %r" % type(sk).__name__)
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("message must be bytes, got %r" % type(message).__name__)
    sk = bytes(sk)
    message = bytes(message)
    if len(sk) != KEY_LEN:
        raise ValueError("private key must be %d bytes, got %d" % (KEY_LEN, len(sk)))

    a, prefix = _expand_secret(sk)
    public_key = _point_encode(_scalar_mult(a, _BASE_POINT))

    r = int.from_bytes(_sha512(prefix, message), "little") % _L
    big_r = _point_encode(_scalar_mult(r, _BASE_POINT))

    k = int.from_bytes(_sha512(big_r, public_key, message), "little") % _L
    s = (r + k * a) % _L

    return big_r + s.to_bytes(32, "little")


def verify(message: bytes, signature: bytes, pk: bytes) -> bool:
    """Return ``True`` iff ``signature`` is a valid Ed25519 signature.

    Implements RFC 8032 §5.1.7.  This function is **total**: it never raises
    and never returns ``True`` for malformed input.  It returns ``False`` when

    * ``message`` is not bytes-like,
    * ``signature`` / ``pk`` is neither bytes-like nor a hex string,
    * ``signature`` / ``pk`` is a hex string that is not valid hexadecimal,
    * ``len(signature) != 64`` or ``len(pk) != 32``,
    * the scalar ``S`` encoded in the signature is ``>= L``,
    * the public key or the ``R`` component does not decode to a curve point,
    * the signature does not satisfy ``[S]B == R + [k]A``.

    ``signature`` and ``pk`` may be passed either as raw bytes or as a
    hexadecimal string; a malformed hex string yields ``False`` rather than an
    exception.  ``message`` must be raw bytes — it is never hex-decoded, so
    there is no ambiguity about what is being authenticated.
    """
    try:
        return _verify(message, signature, pk)
    except Exception:  # pragma: no cover - defensive: fail closed on any surprise
        return False


def _as_key_bytes(value: object) -> bytes | None:
    """Coerce a key-ish argument to bytes, or ``None`` when it is unusable.

    Accepts bytes-like objects and hexadecimal strings.  A hex string that is
    not valid hexadecimal yields ``None`` (fail closed) instead of raising.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return hex_to_key(value)
        except ValueError:
            return None
    return None


def _verify(message: bytes, signature: bytes, pk: bytes) -> bool:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        return False

    message = bytes(message)
    signature = _as_key_bytes(signature)
    pk = _as_key_bytes(pk)
    if signature is None or pk is None:
        return False

    if len(signature) != SIG_LEN or len(pk) != KEY_LEN:
        return False

    big_r_bytes = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        # Non-canonical scalar: reject (RFC 8032 §5.1.7).
        return False

    public_point = _point_decode(pk)
    if public_point is None:
        return False

    r_point = _point_decode(big_r_bytes)
    if r_point is None:
        return False

    k = int.from_bytes(_sha512(big_r_bytes, pk, message), "little") % _L

    # [S]B == R + [k]A
    lhs = _scalar_mult(s, _BASE_POINT)
    rhs = _point_add(r_point, _scalar_mult(k, public_point))
    return _point_equal(lhs, rhs)


# --------------------------------------------------------------------------
# Encoding helpers
# --------------------------------------------------------------------------


def key_to_hex(b: bytes) -> str:
    """Return the lowercase hexadecimal representation of ``b``."""
    if not isinstance(b, (bytes, bytearray)):
        raise ValueError("key must be bytes, got %r" % type(b).__name__)
    return bytes(b).hex()


def hex_to_key(s: str) -> bytes:
    """Decode a hexadecimal string into bytes.

    Strict by design: the string must have an even length and contain only
    ``0-9``, ``a-f`` and ``A-F``.  Whitespace is *not* tolerated (unlike
    ``bytes.fromhex``), because a key that decodes differently depending on
    the decoder is a key that will eventually be signed against the wrong
    material.

    Raises ``ValueError`` for a non-string, an odd-length string, or a string
    containing non-hexadecimal characters.  This is a loud, explicit failure
    on purpose: silently returning a truncated or empty key would let a
    signature check run against the wrong key material.

    For a fully fail-closed path, pass the hex string straight to
    :func:`verify`, which decodes it internally and returns ``False`` on
    malformed hex rather than raising.
    """
    if not isinstance(s, str):
        raise ValueError("hex string expected, got %r" % type(s).__name__)
    if len(s) % 2 != 0:
        raise ValueError("hex string must have an even length, got %d" % len(s))
    if not _HEX_DIGITS.issuperset(s):
        raise ValueError("invalid hexadecimal string: contains non-hex characters")
    return bytes.fromhex(s)


def canonical_json(obj: Any) -> bytes:
    """Serialise ``obj`` to deterministic UTF-8 JSON bytes.

    Uses ``sort_keys=True``, ``separators=(',', ':')`` and ``ensure_ascii=False``
    so that the byte string depends only on the *content* of the object — never
    on dict insertion order, and never on an ASCII escape of non-ASCII text.
    Two structurally equal objects therefore always produce the same bytes,
    which is what makes a signature over the JSON reproducible.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# --------------------------------------------------------------------------
# Base point B — derived from y = 4/5 with an even x, so that the constant is
# self-consistent with the decompression routine above.
# --------------------------------------------------------------------------

_BASE_Y = (4 * pow(5, _P - 2, _P)) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
if _BASE_X is None:  # pragma: no cover - mathematically impossible
    raise RuntimeError("failed to derive the Ed25519 base point")
_BASE_POINT = (_BASE_X, _BASE_Y, 1, (_BASE_X * _BASE_Y) % _P)
