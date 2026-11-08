#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""时效阈值的单一真相源加载器（仅标准库）。

为什么有这个东西
------------------------------------------------------------------
同一组时效阈值此前硬编码在 5 处共 59 处（引擎 decision_integrity.py、
数据仓 board_integrity.py、VPS market_integrity_gate.py、mobile-extras、
export-holdings-integrity.py）。改一处另几处不会跟着变，实测已证明这是
架构缺陷。现在它们统一从 thresholds.json 读。

权威副本（唯一真源）
------------------------------------------------------------------
    E:\\investment-os\\contracts\\thresholds.json
3 个镜像必须与权威副本**逐字节相同**（UTF-8 / LF / 末尾换行）：
    E:\\_work\\finaudit\\eng\\contracts\\thresholds.json
    E:\\_work\\finaudit\\data\\contracts\\thresholds.json
    E:\\_work\\finaudit\\ui\\contracts\\thresholds.json
同步与校验：E:\\_work\\finaudit\\scratch\\sync_thresholds.py

契约
------------------------------------------------------------------
    get_thresholds(path=None) -> dict

· 默认读**本文件所在目录**的 thresholds.json（仓库内自包含，不依赖 CWD）。
· 环境变量 FINWATCH_THRESHOLDS 可指定别的路径（测试/排障用）。
· 读不到 / JSON 非法 / 缺必需键 / 类型不对 → **抛 ThresholdError**。
  绝不静默返回默认值：调用方按 fail-closed 处理（宁可阻断，不可放行）。

本模块**不重新定义任何数字**。数字只有一个来源，就是 thresholds.json。
注意：忠实读取是本加载器的职责；「拒绝被放宽的值」是调用方的职责
（例如闸门侧自己的 policy 校验），两者不要混为一谈。
"""
from __future__ import annotations

import hashlib
import json
import math
import os

__all__ = [
    "ThresholdError",
    "REQUIRED_KEYS",
    "THRESHOLD_DIGEST",
    "DEFAULT_THRESHOLDS",
    "DEFAULT_FILENAME",
    "ENV_VAR",
    "default_path",
    "get_thresholds",
    "validate",
    "canonical_json",
    "digest",
    "assert_digest",
]

# ── 常量 ──────────────────────────────────────────────────────────────────────
DEFAULT_FILENAME = "thresholds.json"
ENV_VAR = "FINWATCH_THRESHOLDS"

#: thresholds.json 必须具备的键（缺任何一个都视为损坏，不是「用默认值补上」）
REQUIRED_KEYS = frozenset({
    "schemaVersion",
    "holdingsMaxAgeHours",
    "marketMaxAgeDays",
    "futureClockSkewMinutes",
    "boardMaxAgeHours",
    "verdictMaxAgeHours",
    "positionMaxAgeDays",
    "hardMaxRiskyPct",
    "requiredIndices",
})

#: 必须是有限数值的键（bool 不算数值：JSON true/false 混进来要报错）
_NUMERIC_KEYS = (
    "holdingsMaxAgeHours",
    "marketMaxAgeDays",
    "futureClockSkewMinutes",
    "boardMaxAgeHours",
    "verdictMaxAgeHours",
    "positionMaxAgeDays",
    "hardMaxRiskyPct",
)


class ThresholdError(RuntimeError):
    """阈值文件缺失/损坏/类型不对。调用方必须 fail-closed，不得吞掉。"""


# ── 路径 ──────────────────────────────────────────────────────────────────────
def default_path() -> str:
    """阈值文件默认路径：环境变量优先，否则取本文件同目录的 thresholds.json。"""
    override = os.environ.get(ENV_VAR)
    if override and override.strip():
        return override.strip()
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_FILENAME)


# ── 规范化与摘要 ──────────────────────────────────────────────────────────────
def canonical_json(thresholds) -> str:
    """规范化 JSON：键排序 + 紧凑分隔符 + 不转义非 ASCII。

    这是 THRESHOLD_DIGEST 的**唯一**输入形式，跨仓交叉校验必须用同一个函数，
    否则摘要不可比。
    """
    return json.dumps(thresholds, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(thresholds) -> str:
    """对规范化 JSON 求 sha256（十六进制小写）。"""
    return hashlib.sha256(canonical_json(thresholds).encode("utf-8")).hexdigest()


def assert_digest(thresholds, expected: str) -> None:
    """交叉校验：摘要不符即抛异常（用于确认两侧读到的是同一份阈值）。"""
    actual = digest(thresholds)
    if actual != expected:
        raise ThresholdError(
            "阈值摘要不一致：期望 %s，实际 %s（两侧读到的不是同一份 thresholds.json）"
            % (expected, actual))


# ── 校验 ──────────────────────────────────────────────────────────────────────
def _reject(message: str) -> None:
    raise ThresholdError(message)


def validate(thresholds) -> dict:
    """校验结构并原样返回（不做任何钳制/修正——忠实读取）。

    失败一律抛 ThresholdError；绝不补默认值、绝不 clamp。
    """
    if not isinstance(thresholds, dict):
        _reject("thresholds 必须是 JSON 对象，实际是 %s" % type(thresholds).__name__)

    missing = sorted(REQUIRED_KEYS - set(thresholds))
    if missing:
        _reject("thresholds 缺必需键：%s" % ", ".join(missing))

    schema = thresholds["schemaVersion"]
    if not isinstance(schema, str) or not schema.strip():
        _reject("schemaVersion 必须是非空字符串，实际是 %r" % (schema,))

    for key in _NUMERIC_KEYS:
        value = thresholds[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            _reject("%s 必须是数值（拒绝 bool/字符串/null），实际是 %r" % (key, value))
        if not math.isfinite(float(value)):
            _reject("%s 必须是有限数值（拒绝 NaN/Infinity），实际是 %r" % (key, value))

    indices = thresholds["requiredIndices"]
    if not isinstance(indices, list) or not indices:
        _reject("requiredIndices 必须是非空数组，实际是 %r" % (indices,))
    for item in indices:
        if not isinstance(item, str) or not item.strip():
            _reject("requiredIndices 的每一项都必须是非空字符串，实际含 %r" % (item,))

    return thresholds


# ── 读取 ──────────────────────────────────────────────────────────────────────
def get_thresholds(path: str | None = None) -> dict:
    """读取并校验阈值。任何异常情况都抛 ThresholdError，绝不返回默认值。"""
    target = path if path is not None else default_path()
    try:
        with open(target, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        _reject("阈值文件不存在：%s（单一真相源缺失，拒绝回退到内置默认值）" % target)
    except OSError as exc:
        _reject("阈值文件读取失败：%s（%s）" % (target, exc))

    if not raw.strip():
        _reject("阈值文件是空的：%s" % target)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _reject("阈值文件不是合法 UTF-8：%s（%s）" % (target, exc))

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        _reject("阈值文件不是合法 JSON：%s（%s）" % (target, exc))

    return validate(document)


# ── 模块级快照（供交叉校验；文件损坏时 import 立刻失败，而不是带着假阈值跑）──────
DEFAULT_THRESHOLDS = get_thresholds()
THRESHOLD_DIGEST = digest(DEFAULT_THRESHOLDS)
