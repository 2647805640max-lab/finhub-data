#!/usr/bin/env python3
import unittest
from datetime import datetime
from zoneinfo import ZoneInfo

from tools.board_integrity import evaluate_board

TZ = ZoneInfo("Asia/Shanghai")
NOW = datetime.fromisoformat("2026-11-07T21:32:00+08:00")
CODES = ["sh000001", "sh000300", "sz399001", "sz399006"]


def make_board():
    indices = [{
        "code": code, "price": 100.0, "prevClose": 99.0,
        "changePct": 1.01, "asOf": "2026-11-07 15:00:00",
    } for code in CODES]
    return {
        "generatedAt": "2026-11-07 20:00:00",
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


class BoardIntegrityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
