#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""完整性裁定的签名/验签（Ed25519，仅标准库）。

为什么必须是非对称
------------------------------------------------------------------
board.json 本身在**公开仓**里（finhub-data）。任何能读公开仓的人都能读到
board.json，也就意味着：

  · 对称密钥（HMAC）放在公开仓 → 等于没有密钥，攻击者能自己签一份 PASS；
  · 对称密钥放在本机 → 公开仓里的验签方拿不到密钥，CI 无法校验。

所以必须是**私钥在仓库外、公钥在仓库内**：公钥公开无害（只能验签，不能签），
私钥留在 `E:\investment-os\contracts\.board-signing-key`（该目录不是 git 仓库）。

被签名的对象
------------------------------------------------------------------
「逐条持仓裁定」verdict 本体（去掉 signature / signedDigest 两个字段后，
按 canonical JSON 序列化）。签名覆盖：

    status / canRecommend / checkedAt / schemaVersion / policy / checks / issues

任何一处被改（包括把 policy 里的阈值改宽、把 status 从 BLOCK 改成 PASS），
签名都验不过 → 闸门 B 直接 BLOCK。

信任边界的诚实说明
------------------------------------------------------------------
board.json 与闸门 B 的代码同在公开仓，理论上「能改 board.json 的人也能改
B 的代码」。本模块解决的是**数据层篡改**（改 board.json 不改代码）与
**意外漂移**（脚本写错、手工编辑、合并冲突）；代码层的信任由仓库外的
`E:\investment-os\tools\verify-board-signature.py` 与本地验收脚本兜底。
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from ed25519_pure import (  # noqa: E402
    canonical_json,
    generate_private_key,
    hex_to_key,
    key_to_hex,
    private_key_to_public_key,
    sign as _ed_sign,
    verify as _ed_verify,
)

__all__ = [
    "SIGNATURE_FIELD",
    "SIGNED_DIGEST_FIELD",
    "KEY_ID_FIELD",
    "ALGORITHM",
    "PUBLIC_KEY_FILENAME",
    "DEFAULT_PRIVATE_KEY_PATH",
    "SigningError",
    "canonical_bytes",
    "signing_body",
    "sign_verdict",
    "verify_verdict",
    "load_public_key",
    "load_private_key",
    "public_key_info",
    "default_public_key_path",
    "default_private_key_path",
]

SIGNATURE_FIELD = "signature"
SIGNED_DIGEST_FIELD = "signedDigest"
KEY_ID_FIELD = "keyId"
ALGORITHM = "ed25519"
PUBLIC_KEY_FILENAME = "signing-key.pub.json"

#: 私钥默认位置（仓库外，绝不入库）
DEFAULT_PRIVATE_KEY_PATH = r"E:\investment-os\contracts\.board-signing-key"


class SigningError(RuntimeError):
    """签名/验签失败。调用方一律 fail-closed。"""


def default_public_key_path() -> str:
    return os.path.join(_HERE, PUBLIC_KEY_FILENAME)


def default_private_key_path() -> str:
    override = os.environ.get("FINWATCH_SIGNING_KEY")
    if override and override.strip():
        return override.strip()
    return DEFAULT_PRIVATE_KEY_PATH


def canonical_bytes(payload) -> bytes:
    """待签名消息 = 规范化 JSON 字节（与 ed25519_pure.canonical_json 同源）。"""
    return canonical_json(payload)


def signing_body(verdict: dict) -> dict:
    """从裁定里剥掉签名相关字段 —— 这就是被签名的内容。"""
    if not isinstance(verdict, dict):
        raise SigningError("裁定必须是 JSON 对象，实际是 %s" % type(verdict).__name__)
    body = dict(verdict)
    body.pop(SIGNATURE_FIELD, None)
    body.pop(SIGNED_DIGEST_FIELD, None)
    body.pop(KEY_ID_FIELD, None)
    return body


def sign_verdict(verdict: dict, private_key: bytes, key_id: str = "board-v1") -> dict:
    """给裁定签名，返回带 signature / signedDigest / keyId 的新裁定。"""
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
        raise SigningError("私钥必须是 32 字节，实际是 %r" % (type(private_key).__name__,))
    body = signing_body(verdict)
    message = canonical_bytes(body)
    digest = hashlib.sha256(message).hexdigest()
    signature = _ed_sign(message, bytes(private_key))
    out = dict(body)
    out[KEY_ID_FIELD] = key_id
    out[SIGNED_DIGEST_FIELD] = digest
    out[SIGNATURE_FIELD] = key_to_hex(signature)
    return out


def load_private_key(path: str | None = None) -> bytes:
    """读取本地私钥（hex）。读不到就抛 —— 不许静默用空密钥。"""
    target = path or default_private_key_path()
    try:
        with open(target, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except FileNotFoundError:
        raise SigningError("私钥文件不存在：%s（签名私钥必须在本机，不得入库）" % target)
    except OSError as exc:
        raise SigningError("私钥文件读取失败：%s（%s）" % (target, exc))
    if not raw:
        raise SigningError("私钥文件是空的：%s" % target)
    try:
        key = hex_to_key(raw)
    except Exception as exc:  # noqa: BLE001
        raise SigningError("私钥不是合法 hex：%s（%s）" % (target, exc))
    if len(key) != 32:
        raise SigningError("私钥长度必须是 32 字节，实际 %d" % len(key))
    return key


def load_public_key(path: str | None = None) -> bytes:
    """读取公钥 JSON → 32 字节公钥。"""
    target = path or default_public_key_path()
    try:
        with open(target, "r", encoding="utf-8") as fh:
            info = json.load(fh)
    except FileNotFoundError:
        raise SigningError("公钥文件不存在：%s" % target)
    except (OSError, ValueError) as exc:
        raise SigningError("公钥文件不可读或不是合法 JSON：%s（%s）" % (target, exc))
    if not isinstance(info, dict):
        raise SigningError("公钥文件必须是 JSON 对象：%s" % target)
    if info.get("algorithm") != ALGORITHM:
        raise SigningError("公钥算法不是 %s：%s（实际 %r）"
                           % (ALGORITHM, target, info.get("algorithm")))
    hex_key = info.get("publicKeyHex")
    if not isinstance(hex_key, str) or not hex_key.strip():
        raise SigningError("公钥文件缺 publicKeyHex：%s" % target)
    try:
        key = hex_to_key(hex_key.strip())
    except Exception as exc:  # noqa: BLE001
        raise SigningError("公钥不是合法 hex：%s（%s）" % (target, exc))
    if len(key) != 32:
        raise SigningError("公钥长度必须是 32 字节，实际 %d" % len(key))
    return key


def public_key_info(path: str | None = None) -> dict:
    """读取公钥 JSON 原样（供展示/校验）。"""
    target = path or default_public_key_path()
    with open(target, "r", encoding="utf-8") as fh:
        return json.load(fh)


def verify_verdict(verdict: dict, public_key: bytes | None = None) -> tuple[bool, str]:
    """验签。返回 (是否通过, 原因)。

    任何异常都归为「不通过」——绝不因为读不到密钥就放行。
    """
    try:
        if not isinstance(verdict, dict):
            return False, "裁定不是 JSON 对象"
        signature_hex = verdict.get(SIGNATURE_FIELD)
        if not isinstance(signature_hex, str) or not signature_hex.strip():
            return False, "裁定未签名（缺 %s 字段）" % SIGNATURE_FIELD
        declared_digest = verdict.get(SIGNED_DIGEST_FIELD)
        body = signing_body(verdict)
        message = canonical_bytes(body)
        actual_digest = hashlib.sha256(message).hexdigest()
        if isinstance(declared_digest, str) and declared_digest.strip():
            if declared_digest.strip() != actual_digest:
                return False, "裁定摘要不符（内容被改动：声明 %s，实际 %s）" % (
                    declared_digest.strip()[:16], actual_digest[:16])
        else:
            return False, "裁定缺 %s 字段" % SIGNED_DIGEST_FIELD
        if public_key is None:
            public_key = load_public_key()
        try:
            signature = hex_to_key(signature_hex.strip())
        except Exception:  # noqa: BLE001
            return False, "签名不是合法 hex"
        if len(signature) != 64:
            return False, "签名长度必须是 64 字节，实际 %d" % len(signature)
        if not _ed_verify(message, signature, bytes(public_key)):
            return False, "签名验不过（内容与签名不匹配，或签名不是本密钥所签）"
        return True, "签名有效"
    except SigningError as exc:
        return False, "验签失败：%s" % exc
    except Exception as exc:  # noqa: BLE001
        return False, "验签异常：%s" % exc


def generate_keypair(private_key_path: str | None = None,
                     public_key_path: str | None = None,
                     key_id: str = "board-v1") -> dict:
    """生成密钥对：私钥写本地文件（仓库外），公钥写 JSON（可入库）。

    私钥文件权限尽力收紧；Windows 下 os.chmod 语义有限，但至少不写进仓库。
    """
    sk = generate_private_key()
    pk = private_key_to_public_key(sk)
    priv_target = private_key_path or default_private_key_path()
    pub_target = public_key_path or default_public_key_path()
    os.makedirs(os.path.dirname(priv_target) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(pub_target) or ".", exist_ok=True)
    with open(priv_target, "w", encoding="utf-8") as fh:
        fh.write(key_to_hex(sk))
    try:
        os.chmod(priv_target, 0o600)
    except OSError:
        pass
    info = {
        "algorithm": ALGORITHM,
        "keyId": key_id,
        "publicKeyHex": key_to_hex(pk),
        "note": "公钥可公开；私钥只在本机 E:\\investment-os\\contracts\\ 下，不得入库",
    }
    with open(pub_target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(info, ensure_ascii=False, indent=2) + "\n")
    return info
