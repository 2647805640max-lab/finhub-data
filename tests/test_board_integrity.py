#!/usr/bin/env python3
import json
import unittest
from datetime import datetime
from zoneinfo import ZoneInfo

from tools import board_integrity
from tools.board_integrity import evaluate_board, inject_verdict

# 注意：sanitize_holdings_verdict 用模块属性方式调用（board_integrity.sanitize_holdings_verdict），
# 不写成 from ... import。原因是 TDD 红阶段该符号尚不存在，模块级 import 会让整个测试文件
# 加载失败（errors=1），掩盖真实失败项；属性调用让红阶段显示 failures=N，逐条可读。

TZ = ZoneInfo("Asia/Shanghai")
NOW = datetime.fromisoformat("2026-11-07T21:32:00+08:00")
CODES = ["sh000001", "sh000300", "sz399001", "sz399006"]

# 引擎闸门 A（decision_integrity.py）对同一份持仓的裁定，脱敏后由生产链嵌进 board。
# 相对 NOW 只老 2 分钟 → 新鲜。
VERDICT_CHECKED_AT = "2026-11-07T21:30:00+08:00"

# 脱敏用例里用来“试探泄漏”的字面量：真实引擎会把这三类东西放进 issues[].actual
LEAK_PLATFORM = "支付宝-基金黄金"
LEAK_HOLDING = "易方达黄金ETF联接C"
LEAK_AMOUNT = "12785.02"


def _test_keypair():
    """本次运行专用的一次性密钥对。

    为什么不复用生产私钥：生产私钥只在本机（E:\\investment-os\\contracts\\），
    CI 里根本没有。本测试要验的是「**验签逻辑**对不对」，不是「生产那把钥匙
    能不能验」——后者由仓库外的 verify-board-signature.py 与线上验收负责。
    """
    from contracts.ed25519_pure import generate_private_key, private_key_to_public_key
    sk = generate_private_key()
    return sk, private_key_to_public_key(sk)


_TEST_SK, _TEST_PK = _test_keypair()


def _sign(verdict):
    """给假裁定签名（用一次性测试密钥）。"""
    from contracts import signing
    return signing.sign_verdict(verdict, _TEST_SK, key_id="test-v1")


def fresh_verdict():
    """A 判定 PASS 时的脱敏投影（字段集合 = board_integrity 的白名单）。"""
    verdict = {
        "status": "PASS",
        "canRecommend": True,
        "checkedAt": VERDICT_CHECKED_AT,
        "schemaVersion": "1.0",
        "issues": [],
        "checks": [{"id": "holdings", "status": "PASS"},
                   {"id": "market", "status": "PASS"}],
        "policy": {
            "maxHoldingsAgeHours": 36.0,
            "maxMarketAgeDays": 4.0,
            "futureClockSkewMinutes": 5.0,
            "requiredIndices": ["sh000001", "sh000300", "sz399001", "sz399006"],
        },
    }
    # D10（2026-11-08）：裁定必须带有效签名，否则 B 一律 BLOCK。
    # 签名覆盖脱敏后的全部内容 —— 任何改动都会让签名失效。
    return _sign(verdict)


def make_board():
    indices = [{
        "code": code, "price": 100.0, "prevClose": 99.0,
        "changePct": 1.01, "asOf": "2026-11-07 15:00:00",
    } for code in CODES]
    return {
        "generatedAt": "2026-11-07 20:00:00",
        # P0-6 行为改变（预期）：fixture 必须带一个**新鲜 PASS** 的引擎裁定，
        # 否则 board_integrity 会因看不到逐条持仓而 HOLDINGS_VERDICT_MISSING → BLOCK。
        # 这正是本次修复要的语义：数据仓不得背书自己没看过的范围。
        "holdingsIntegrity": fresh_verdict(),
        "today": {
            "date": "2026-11-07",
            "position": {
                "currentPct": 10.0, "hardMaxPct": 15.0,
                "dataAsOf": "2026-11-07", "dataAgeDays": 0.5, "stale": False,
            },
            "rebalance": {"action": "HOLD", "bandLowPct": 8.0, "bandHighPct": 15.0},
            "drawdown": {"observable": True, "asOf": "2026-11-07", "valuePct": 1.0},
        },
        "market": {"sources": {"indices": {
            "ok": True, "asOf": "2026-11-07 15:00:00",
            "value": {"asOf": "2026-11-07 15:00:00", "items": indices},
        }}},
        "_freshness": {"items": [{"id": "holdings", "ageDays": 0.5, "stale": False}]},
        "ips": {"items": [{"name": "risk cap", "status": "ok"}]},
    }


def codes_of(result):
    return {x["code"] for x in result["issues"]}


def issue_by_code(result, code):
    for item in result["issues"]:
        if item.get("code") == code:
            return item
    return None


class BoardIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 让 B 用本次运行的一次性测试公钥验签（生产公钥在 CI 里无从验证，
        # 也不该由 CI 依赖生产私钥）。
        from contracts import signing
        cls._orig_load_public_key = signing.load_public_key
        signing.load_public_key = lambda *a, **k: _TEST_PK

    @classmethod
    def tearDownClass(cls):
        from contracts import signing
        signing.load_public_key = cls._orig_load_public_key

    def test_verdict_injection_preserves_existing_board_fields(self):
        raw = """{
    "schema": "board/v1",
    "today": {"position": {"dataAgeDays": 0.5}}
}
"""
        verdict = {"schema": "decision-integrity/v1", "status": "BLOCK", "canRecommend": False, "issues": []}
        updated = inject_verdict(raw, verdict)
        parsed = json.loads(updated)
        self.assertEqual(parsed["schema"], "board/v1")
        self.assertEqual(parsed["today"]["position"]["dataAgeDays"], 0.5)
        self.assertEqual(parsed["decisionIntegrity"], verdict)
        updated_again = inject_verdict(updated, {**verdict, "status": "PASS", "canRecommend": True})
        parsed_again = json.loads(updated_again)
        self.assertEqual(parsed_again["decisionIntegrity"]["status"], "PASS")
        self.assertEqual(parsed_again["today"], parsed["today"])

    def test_fresh_complete_board_passes(self):
        result = evaluate_board(make_board(), now=NOW)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["canRecommend"])

    def test_current_two_day_holdings_snapshot_blocks(self):
        board = make_board()
        board["today"]["position"]["dataAgeDays"] = 2.0
        board["_freshness"]["items"][0]["ageDays"] = 1.95
        board["today"]["position"]["dataAsOf"] = "2026-11-05"
        board["today"]["drawdown"]["asOf"] = "2026-11-05"
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_STALE", {x["code"] for x in result["issues"]})

    def test_partial_index_data_blocks(self):
        board = make_board()
        board["market"]["sources"]["indices"]["value"]["items"].pop()
        result = evaluate_board(board, now=NOW)
        self.assertIn("MARKET_PARTIAL", {x["code"] for x in result["issues"]})

    def test_unresolved_policy_items_block(self):
        board = make_board()
        board["ips"]["items"].append({"name": "band mismatch", "status": "warn"})
        result = evaluate_board(board, now=NOW)
        self.assertIn("POLICY_UNRESOLVED", {x["code"] for x in result["issues"]})

    def test_band_cannot_exceed_hard_policy_cap(self):
        board = make_board()
        board["today"]["rebalance"]["bandHighPct"] = 22.0
        result = evaluate_board(board, now=NOW)
        self.assertIn("POLICY_BAND_CAP", {x["code"] for x in result["issues"]})

    def test_future_board_timestamp_blocks(self):
        board = make_board()
        board["generatedAt"] = "2026-11-08 21:00:00"
        result = evaluate_board(board, now=NOW)
        self.assertIn("BOARD_FUTURE", {x["code"] for x in result["issues"]})

    # ── P0-6：B 必须 fail-closed 消费引擎闸门 A 的逐条持仓裁定 ──────────────────

    def test_missing_holdings_verdict_blocks(self):
        """缺字段/不是对象 → BLOCK：数据仓不能给没见过的逐条持仓背书。"""
        board = make_board()
        del board["holdingsIntegrity"]
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_MISSING", codes_of(result))

        # 「不是对象」与「缺失」同等对待（空字符串、None、列表都不得被当成 PASS）
        for bogus in ("", None, [], "PASS", 0):
            board2 = make_board()
            board2["holdingsIntegrity"] = bogus
            result2 = evaluate_board(board2, now=NOW)
            self.assertEqual(result2["status"], "BLOCK", msg="holdingsIntegrity=%r 必须 BLOCK" % (bogus,))
            self.assertIn("HOLDINGS_VERDICT_MISSING", codes_of(result2))

    def test_engine_block_verdict_propagates(self):
        """A 判 BLOCK → B 必须 BLOCK，并把引擎的 issue codes 原样带进 actual。"""
        board = make_board()
        board["holdingsIntegrity"] = {
            "status": "BLOCK",
            "canRecommend": False,
            "checkedAt": VERDICT_CHECKED_AT,
            "schemaVersion": "1.0",
            "issues": [
                {"code": "HOLDINGS_ITEM_INVALID",
                 "message": "持仓明细字段无效；拒绝缺失/字符串/NaN/负数市值",
                 "actual": [{"platform": LEAK_PLATFORM, "index": 0,
                             "reason": "缺少 marketValue（不得按 0 处理）"}]},
                {"code": "HOLDINGS_STALE",
                 "message": "持仓快照超过允许时效",
                 "actual": [{"platform": LEAK_PLATFORM, "ageHours": 60.5}]},
            ],
            "checks": [{"id": "holdings", "status": "BLOCK"}],
        }
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertFalse(result["canRecommend"])
        block = issue_by_code(result, "HOLDINGS_VERDICT_BLOCK")
        self.assertIsNotNone(block, "必须给出 HOLDINGS_VERDICT_BLOCK")
        self.assertEqual(block["actual"], ["HOLDINGS_ITEM_INVALID", "HOLDINGS_STALE"])

    def test_can_recommend_must_be_true_even_when_status_says_pass(self):
        """status 声称 PASS 但 canRecommend 不是 True → 仍然 BLOCK（不得只看 status）。"""
        for bogus in (False, "true", 1, None, "PASS"):
            board = make_board()
            board["holdingsIntegrity"]["canRecommend"] = bogus
            result = evaluate_board(board, now=NOW)
            self.assertEqual(result["status"], "BLOCK", msg="canRecommend=%r 必须 BLOCK" % (bogus,))
            self.assertIn("HOLDINGS_VERDICT_BLOCK", codes_of(result))

    def test_stale_verdict_blocks(self):
        """裁定自身的 checkedAt 超过 24h（复用 MAX_BOARD_AGE_HOURS）→ BLOCK。"""
        board = make_board()
        board["holdingsIntegrity"]["checkedAt"] = "2026-11-06T00:00:00+08:00"   # 45.5h 前
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("HOLDINGS_VERDICT_STALE", codes_of(result))

        # 不可解析 / 缺失 → 同一个 code，不得当成「新鲜」
        for bogus in ("not-a-timestamp", "", None, 12345):
            board2 = make_board()
            board2["holdingsIntegrity"]["checkedAt"] = bogus
            result2 = evaluate_board(board2, now=NOW)
            self.assertEqual(result2["status"], "BLOCK", msg="checkedAt=%r 必须 BLOCK" % (bogus,))
            self.assertIn("HOLDINGS_VERDICT_STALE", codes_of(result2))

    def test_fresh_pass_verdict_allows_pass(self):
        """新鲜 PASS 裁定 → 整体仍 PASS（证明不是一刀切 BLOCK）。"""
        result = evaluate_board(make_board(), now=NOW)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["canRecommend"])
        checks = {c["id"]: c for c in result["checks"]}
        self.assertIn("holdingsVerdict", checks)
        self.assertEqual(checks["holdingsVerdict"]["status"], "PASS")
        self.assertTrue(result["policy"]["requiresHoldingsVerdict"])

    def test_verdict_must_not_leak_platform_or_amount(self):
        """进 board 的裁定信息只允许白名单字段；平台名/持仓名/金额不得出现。"""
        board = make_board()
        board["holdingsIntegrity"] = {
            "status": "BLOCK",
            "canRecommend": False,
            "checkedAt": VERDICT_CHECKED_AT,
            "schemaVersion": "1.0",
            "issues": [{
                "code": "HOLDINGS_STALE",
                "message": "持仓快照超过允许时效",
                # 真实引擎在这里放 platform/capturedAt/ageHours；还额外塞金额与持仓名做试探
                "actual": [{"platform": LEAK_PLATFORM, "ageHours": 60.5,
                            "name": LEAK_HOLDING, "marketValue": 12785.02}],
                "threshold": "≤36 小时",
            }],
            "checks": [{
                "id": "holdings", "status": "BLOCK", "platforms": 3, "maxAgeHours": 60.5,
                "details": {LEAK_PLATFORM: 12785.02},
            }],
            "policy": {"maxHoldingsAgeHours": 36.0,
                       "requiredIndices": ["sh000001", "sh000300", "sz399001", "sz399006"],
                       "platformWeights": {LEAK_PLATFORM: 12785.02}},
            # 非白名单的顶层键（引擎调试/平台汇总）必须整体丢弃
            "platformTotals": {LEAK_PLATFORM: 12785.02},
            "engineDebug": {"positions": [{"name": LEAK_HOLDING, "marketValue": 12785.02}]},
        }
        result = evaluate_board(board, now=NOW)
        self.assertEqual(result["status"], "BLOCK")     # 不是因为「丢信息」而变绿

        serialized = json.dumps(result, ensure_ascii=False)
        for token in (LEAK_PLATFORM, LEAK_HOLDING, LEAK_AMOUNT):
            self.assertNotIn(token, serialized, msg="board 裁定泄漏了 %r" % (token,))
        # 引擎 issue code 必须保留（脱敏 ≠ 抹掉可用性）
        self.assertIn("HOLDINGS_STALE", serialized)

        # 直接验证白名单投影本身
        clean = board_integrity.sanitize_holdings_verdict(board["holdingsIntegrity"])
        self.assertEqual(clean["status"], "BLOCK")
        self.assertEqual(clean["canRecommend"], False)
        self.assertEqual(clean["issues"], [{"code": "HOLDINGS_STALE", "message": "持仓快照超过允许时效"}])
        # D7/D10：白名单在 2026-11-08 扩了两处 ——
        #   · checks 里的标量年龄字段（ageHours/maxAgeHours/thresholdHours）：
        #     B 需要它们做「裁定与 position 互相印证」的交叉校验，都是标量、
        #     不含平台名与金额；
        #   · 签名三件套（signature/signedDigest/keyId）：B 要用它们验签，
        #     剥掉就等于没法验。
        # 仍然**不允许** platforms / details 这类带平台名的字段。
        self.assertEqual(clean["checks"],
                         [{"id": "holdings", "status": "BLOCK", "maxAgeHours": 60.5}])
        self.assertNotIn("platforms", clean["checks"][0])
        self.assertNotIn("details", clean["checks"][0])
        self.assertNotIn("platformTotals", clean)
        self.assertNotIn("engineDebug", clean)
        clean_text = json.dumps(clean, ensure_ascii=False)
        for token in (LEAK_PLATFORM, LEAK_HOLDING, LEAK_AMOUNT):
            self.assertNotIn(token, clean_text)


# ── CI 收集入口（2026-11-08）────────────────────────────────────────────────
# 背景：CI 的 path filter 与 discover 模式只覆盖 `test_board_integrity.py`
# （.github/workflows/*.yml 无法修改 —— OAuth token 没有 workflow scope）。
# 因此**新测试必须从这里进入**，否则写了也永远不跑（这正是「假成功」的温床）。
# 下面的 import 把签名/交叉校验回归的用例并入本文件的命名空间，
# `python -m unittest discover -s tests -p "test_board_integrity.py"` 会一并收集。
try:
    from tests.test_board_verdict_signature import *          # noqa: F401,F403
except ImportError:
    from test_board_verdict_signature import *                 # noqa: F401,F403


if __name__ == "__main__":
    unittest.main(verbosity=2)