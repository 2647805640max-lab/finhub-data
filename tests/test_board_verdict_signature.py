#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""闸门 B 的签名与交叉校验回归（D6 / D8 / D10）。

每条用例都对应 REPORT-ARCH-ADVERSARIAL-AUDIT-2026-11-08.md 里的一条已证实缺陷。
用一次性测试密钥对（CI 里没有生产私钥，也不该依赖它）。
"""
import json
import os
import sys
import unittest
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from contracts import signing                                  # noqa: E402
from contracts.ed25519_pure import (                          # noqa: E402
    generate_private_key, private_key_to_public_key,
)
from tools import board_integrity                              # noqa: E402
from tools.board_integrity import evaluate_board               # noqa: E402

TZ = ZoneInfo("Asia/Shanghai")
NOW = datetime.fromisoformat("2026-11-07T21:32:00+08:00")
CODES = ["sh000001", "sh000300", "sz399001", "sz399006"]

_SK = generate_private_key()
_PK = private_key_to_public_key(_SK)


def _sign(verdict):
    return signing.sign_verdict(verdict, _SK, key_id="test-v1")


def _fresh_verdict(status="PASS", can_recommend=True, age_hours=12.0, issues=None):
    """与生产链同构的脱敏裁定（字段集合 = board_integrity 的白名单）。

    age_hours 是**小时**，要与 board 的 position.dataAgeDays*24 对得上
    （交叉校验会比对这两个值）。
    """
    return {
        "status": status,
        "canRecommend": can_recommend,
        "checkedAt": (NOW - timedelta(hours=0.03)).isoformat(),
        "schemaVersion": "1.0",
        "issues": issues if issues is not None else [],
        "checks": [{"id": "holdings", "status": status, "maxAgeHours": age_hours},
                   {"id": "market", "status": "PASS"}],
        "policy": {
            "maxHoldingsAgeHours": 36.0,
            "maxMarketAgeDays": 4.0,
            "futureClockSkewMinutes": 5.0,
            "requiredIndices": list(CODES),
        },
    }


def _board(verdict, age_days=0.5):
    indices = [{"code": c, "price": 100.0, "prevClose": 99.0, "changePct": 1.01,
                "asOf": "2026-11-07 15:00:00"} for c in CODES]
    return {
        "generatedAt": "2026-11-07 20:00:00",
        "holdingsIntegrity": verdict,
        "today": {
            "date": "2026-11-07",
            "position": {"currentPct": 10.0, "hardMaxPct": 15.0,
                         "dataAsOf": "2026-11-07", "dataAgeDays": age_days, "stale": False},
            "rebalance": {"action": "HOLD", "bandLowPct": 8.0, "bandHighPct": 15.0},
            "drawdown": {"observable": True, "asOf": "2026-11-07", "valuePct": 1.0},
        },
        "market": {"sources": {"indices": {
            "ok": True, "asOf": "2026-11-07 15:00:00",
            "value": {"asOf": "2026-11-07 15:00:00", "items": indices}}}},
        "_freshness": {"items": [{"id": "holdings", "ageDays": age_days, "stale": False}]},
        "ips": {"items": [{"name": "risk cap", "status": "ok"}]},
    }


def codes(result):
    return {x["code"] for x in result["issues"]}


class VerdictSignatureTests(unittest.TestCase):
    """D10 / D6：裁定必须带有效签名，否则一律 BLOCK。"""

    @classmethod
    def setUpClass(cls):
        cls._orig = signing.load_public_key
        signing.load_public_key = lambda *a, **k: _PK

    @classmethod
    def tearDownClass(cls):
        signing.load_public_key = cls._orig

    def test_signed_fresh_pass_verdict_allows_pass(self):
        board = _board(_sign(_fresh_verdict()))
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "PASS",
                         "合法签名 + 新鲜持仓必须 PASS，实际 %s %s"
                         % (result["status"], codes(result)))
        checks = {c["id"]: c for c in result["checks"]}
        self.assertTrue(checks["holdingsVerdict"]["signatureVerified"])

    def test_unsigned_verdict_is_blocked(self):
        board = _board(_fresh_verdict())          # 未签名
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_UNSIGNED", codes(result))

    def test_tampered_status_breaks_signature(self):
        """攻击 A：把 BLOCK 改成 PASS —— 签名覆盖 status，改了就验不过。"""
        verdict = _sign(_fresh_verdict(status="BLOCK", can_recommend=False,
                                       issues=[{"code": "HOLDINGS_STALE",
                                                "message": "持仓快照超过允许时效"}]))
        verdict["status"] = "PASS"
        verdict["canRecommend"] = True
        result = evaluate_board(_board(verdict), now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_SIGNATURE_INVALID", codes(result))

    def test_tampered_policy_breaks_signature_and_policy_check(self):
        """攻击 B：把 policy 里的阈值改宽 —— 签名与 policy 双重拦。"""
        verdict = _sign(_fresh_verdict())
        verdict["policy"]["maxHoldingsAgeHours"] = 336.0
        result = evaluate_board(_board(verdict), now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_SIGNATURE_INVALID", codes(result))
        self.assertIn("HOLDINGS_VERDICT_POLICY_MISMATCH", codes(result))

    def test_tampered_checked_at_breaks_signature(self):
        """攻击 G：改 checkedAt 冒充刚复检。"""
        verdict = _sign(_fresh_verdict())
        verdict["checkedAt"] = NOW.isoformat()
        result = evaluate_board(_board(verdict), now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_SIGNATURE_INVALID", codes(result))

    def test_zero_signature_is_rejected(self):
        verdict = _sign(_fresh_verdict())
        verdict["signature"] = "00" * 64
        result = evaluate_board(_board(verdict), now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_SIGNATURE_INVALID", codes(result))

    def test_signature_from_other_key_is_rejected(self):
        """换一把钥匙签的 —— 验不过。"""
        other_sk = generate_private_key()
        verdict = signing.sign_verdict(_fresh_verdict(), other_sk, key_id="test-v1")
        result = evaluate_board(_board(verdict), now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_SIGNATURE_INVALID", codes(result))


class CrossFieldConsistencyTests(unittest.TestCase):
    """D6：裁定、decisionIntegrity、position 三者必须互相印证。"""

    @classmethod
    def setUpClass(cls):
        cls._orig = signing.load_public_key
        signing.load_public_key = lambda *a, **k: _PK

    @classmethod
    def tearDownClass(cls):
        signing.load_public_key = cls._orig

    def test_position_age_must_match_verdict_age(self):
        """攻击 C：只把 position 的年龄改新鲜（裁定不动）→ 交叉校验拦。"""
        board = _board(_sign(_fresh_verdict(age_hours=12.0)), age_days=0.5)
        board["today"]["position"]["dataAgeDays"] = 0.01
        board["_freshness"]["items"][0]["ageDays"] = 0.01
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_FIELD_MISMATCH", codes(result))

    def test_decision_integrity_policy_must_match_thresholds(self):
        """攻击 D：伪造 decisionIntegrity 并把 policy 阈值改宽 → 拦。"""
        board = _board(_sign(_fresh_verdict()))
        board["decisionIntegrity"] = {
            "status": "PASS", "canRecommend": True,
            "checkedAt": NOW.isoformat(),
            "policy": {"maxHoldingsAgeHours": 336.0},
            "checks": [{"id": "holdings", "ageHours": 0.24}],
        }
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("DECISION_POLICY_MISMATCH", codes(result))

    def test_decision_integrity_checked_at_must_match_verdict(self):
        board = _board(_sign(_fresh_verdict()))
        board["decisionIntegrity"] = {
            "status": "PASS", "canRecommend": True,
            "checkedAt": "2026-11-07T01:00:00+08:00",
            "policy": {"maxHoldingsAgeHours": 36.0},
            "checks": [{"id": "holdingsVerdict",
                        "checkedAt": "2026-11-07T01:00:00+08:00"}],
        }
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_FIELD_MISMATCH", codes(result))


class ThresholdSingleSourceTests(unittest.TestCase):
    """D7：B 用的阈值必须来自 contracts/thresholds.json，且数值未被放宽。"""

    def test_thresholds_come_from_json(self):
        from contracts.thresholds import get_thresholds
        th = get_thresholds()
        self.assertEqual(board_integrity.MAX_HOLDINGS_AGE_HOURS, th["holdingsMaxAgeHours"])
        self.assertEqual(board_integrity.MAX_MARKET_AGE_DAYS, th["marketMaxAgeDays"])
        self.assertEqual(board_integrity.MAX_BOARD_AGE_HOURS, th["boardMaxAgeHours"])
        self.assertEqual(board_integrity.MAX_FUTURE_SKEW_MINUTES, th["futureClockSkewMinutes"])
        self.assertEqual(board_integrity.EXPECTED_CODES, set(th["requiredIndices"]))

    def test_no_standard_was_loosened(self):
        """守住用户的硬要求：时效标准一个数字都没被改。"""
        self.assertEqual(board_integrity.MAX_HOLDINGS_AGE_HOURS, 36.0)
        self.assertEqual(board_integrity.MAX_MARKET_AGE_DAYS, 4.0)
        self.assertEqual(board_integrity.MAX_BOARD_AGE_HOURS, 24.0)
        self.assertEqual(board_integrity.MAX_VERDICT_AGE_HOURS, 24.0)
        self.assertEqual(board_integrity.MAX_FUTURE_SKEW_MINUTES, 5.0)
        self.assertEqual(board_integrity.POSITION_MAX_AGE_DAYS, 1.5)
        self.assertEqual(board_integrity.HARD_MAX_RISKY_PCT, 15.0)

    def test_source_file_has_no_hardcoded_thresholds(self):
        """源码里不得再出现硬编码的阈值字面量（除了从 JSON 读取那几行）。"""
        src = open(os.path.join(REPO, "tools", "board_integrity.py"),
                   encoding="utf-8").read()
        import re
        bad = []
        for m in re.finditer(r"^\s*(MAX_[A-Z_]+|EXPECTED_CODES|POSITION_MAX_AGE_DAYS|"
                             r"HARD_MAX_RISKY_PCT)\s*=\s*(.+)$", src, re.M):
            name, val = m.group(1), m.group(2).strip()
            if ("_THRESHOLDS" in val or val.startswith("float(")
                    or val.startswith("set(") or val.startswith("MAX_")):
                # 从 JSON 读取，或由另一个阈值派生（MAX_VERDICT_AGE_HOURS = MAX_BOARD_AGE_HOURS）
                continue
            bad.append("%s = %s" % (name, val))
        self.assertEqual(bad, [], "board_integrity.py 里仍有硬编码阈值：%s" % bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
