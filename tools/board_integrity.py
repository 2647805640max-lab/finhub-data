#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Derive a fail-closed verdict for the public FinHub board snapshot."""
from __future__ import annotations

import argparse
from datetime import datetime, date, time, timedelta
import json
import math
import re
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Shanghai")
MAX_HOLDINGS_AGE_HOURS = 36.0
MAX_MARKET_AGE_DAYS = 4.0
MAX_BOARD_AGE_HOURS = 24.0
MAX_FUTURE_SKEW_MINUTES = 5.0
EXPECTED_CODES = {"sh000001", "sh000300", "sz399001", "sz399006"}
ALLOWED_ACTIONS = {"ADD", "TRIM", "EXIT", "WAIT", "HOLD"}


def parse_dt(value):
    if value is None or value == "":
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=TZ)
        return parsed.astimezone(TZ)
    except ValueError:
        try:
            d = date.fromisoformat(raw[:10])
            return datetime.combine(d, time(23, 59, 59), tzinfo=TZ)
        except ValueError:
            return None


def finite_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def evaluate_board(board, now=None):
    now = (now or datetime.now(TZ)).astimezone(TZ)
    issues = []
    checks = []

    generated = parse_dt(board.get("generatedAt"))
    if generated is None:
        issues.append({"code": "BOARD_TIMESTAMP", "message": "board.generatedAt 缺失或不可解析"})
    else:
        age_h = (now - generated).total_seconds() / 3600
        if age_h < -MAX_FUTURE_SKEW_MINUTES / 60:
            issues.append({"code": "BOARD_FUTURE", "message": "board.generatedAt 位于未来", "actual": round(age_h, 2)})
        elif age_h > MAX_BOARD_AGE_HOURS:
            issues.append({"code": "BOARD_STALE", "message": "治理看板超过24小时未刷新", "actual": round(age_h, 2)})
    checks.append({"id": "board", "maxAgeHours": MAX_BOARD_AGE_HOURS})

    today = board.get("today") or {}
    position = today.get("position") or {}
    if not position:
        issues.append({"code": "POSITION_MISSING", "message": "today.position 缺失"})
        position_age_h = None
    else:
        age_days = position.get("dataAgeDays")
        if finite_number(age_days):
            position_age_h = float(age_days) * 24
        else:
            captured = parse_dt(position.get("dataAsOf"))
            position_age_h = (now - captured).total_seconds() / 3600 if captured else None
        if position_age_h is None:
            issues.append({"code": "HOLDINGS_TIMESTAMP", "message": "持仓快照年龄缺失"})
        elif position_age_h < -MAX_FUTURE_SKEW_MINUTES / 60:
            issues.append({"code": "HOLDINGS_FUTURE", "message": "持仓快照时间位于未来", "actual": round(position_age_h, 2)})
        elif position_age_h > MAX_HOLDINGS_AGE_HOURS:
            issues.append({"code": "HOLDINGS_STALE", "message": "持仓快照超过36小时", "actual": round(position_age_h, 2)})
        if position.get("stale") is True:
            issues.append({"code": "HOLDINGS_MARKED_STALE", "message": "上游已标记持仓快照过期"})
    freshness = board.get("_freshness") or {}
    for item in freshness.get("items", []):
        if item.get("id") == "holdings" and finite_number(item.get("ageDays")):
            if float(item["ageDays"]) * 24 > MAX_HOLDINGS_AGE_HOURS:
                issues.append({"code": "HOLDINGS_FRESHNESS_STALE", "message": "全局 freshness 中的持仓快照超过36小时",
                               "actual": item.get("ageDays")})
    checks.append({"id": "holdings", "ageHours": round(position_age_h, 2) if position_age_h is not None else None,
                   "maxAgeHours": MAX_HOLDINGS_AGE_HOURS})

    market = board.get("market") or {}
    indices = ((market.get("sources") or {}).get("indices") or {})
    value = indices.get("value") or {}
    items = value.get("items")
    if indices.get("ok") is not True or not isinstance(items, list):
        issues.append({"code": "MARKET_MISSING", "message": "四指数行情源不可用"})
        items = []
    codes = {str(x.get("code")) for x in items if isinstance(x, dict)}
    if codes != EXPECTED_CODES or len(items) != len(EXPECTED_CODES):
        issues.append({"code": "MARKET_PARTIAL", "message": "四个指定指数必须全部有效",
                       "actual": sorted(codes), "expected": sorted(EXPECTED_CODES)})
    dates = set()
    for item in items:
        if not isinstance(item, dict):
            issues.append({"code": "MARKET_SCHEMA", "message": "指数记录不是对象"})
            continue
        for field in ("price", "prevClose", "changePct"):
            if not finite_number(item.get(field)):
                issues.append({"code": "MARKET_METRIC_INVALID", "message": f"指数 {item.get('code')} 的 {field} 缺失或非有限数值"})
        stamp = parse_dt(item.get("asOf"))
        if stamp is None:
            issues.append({"code": "MARKET_ITEM_TIMESTAMP", "message": f"指数 {item.get('code')} 缺少 asOf"})
        else:
            dates.add(stamp.date().isoformat())
    if len(dates) != 1:
        issues.append({"code": "MARKET_DATE_MISMATCH", "message": "四个指数行情日期不一致或缺失", "actual": sorted(dates)})
    market_asof = parse_dt(indices.get("asOf") or value.get("asOf"))
    if market_asof is None:
        issues.append({"code": "MARKET_TIMESTAMP", "message": "指数行情汇总 asOf 缺失"})
    else:
        market_age = (now - market_asof).total_seconds() / 86400
        if market_age < -MAX_FUTURE_SKEW_MINUTES / 60 / 24:
            issues.append({"code": "MARKET_FUTURE", "message": "指数行情日期位于未来", "actual": round(market_age, 2)})
        elif market_age > MAX_MARKET_AGE_DAYS:
            issues.append({"code": "MARKET_STALE", "message": "指数行情超过4天", "actual": round(market_age, 2)})
    checks.append({"id": "market", "indices": len(codes), "expectedIndices": len(EXPECTED_CODES),
                   "maxAgeDays": MAX_MARKET_AGE_DAYS})

    drawdown = today.get("drawdown") or {}
    if drawdown.get("observable") is not True:
        issues.append({"code": "DRAWDOWN_UNOBSERVABLE", "message": "组合回撤当前不可观测，不能把缺失解释为无风险"})
    elif position.get("dataAsOf") and drawdown.get("asOf") and str(position["dataAsOf"])[:10] != str(drawdown["asOf"])[:10]:
        issues.append({"code": "DRAWDOWN_ASOF_MISMATCH", "message": "组合回撤时点与持仓快照时点不一致"})

    rebalance = today.get("rebalance") or {}
    if rebalance.get("action") not in ALLOWED_ACTIONS:
        issues.append({"code": "ACTION_MISSING", "message": "再平衡动作缺失或不在允许枚举中"})
    hard_max = position.get("hardMaxPct")
    band_high = rebalance.get("bandHighPct")
    if not finite_number(hard_max) or float(hard_max) > 15.0:
        issues.append({"code": "POLICY_HARD_CAP", "message": "风险仓硬上限缺失或超过用户15%政策"})
    if not finite_number(band_high) or (finite_number(hard_max) and float(band_high) > float(hard_max)):
        issues.append({"code": "POLICY_BAND_CAP", "message": "无交易带上沿缺失或超过风险仓硬上限"})

    unresolved = [x for x in ((board.get("ips") or {}).get("items") or [])
                  if str(x.get("status", "")).lower() in {"warn", "gap", "error"}]
    if unresolved:
        issues.append({"code": "POLICY_UNRESOLVED", "message": "政策契约仍存在未裁定 warn/gap 项，暂不允许给出动作",
                       "actual": [{"name": x.get("name"), "status": x.get("status")} for x in unresolved]})
    checks.append({"id": "policy", "unresolvedItems": len(unresolved), "status": "BLOCK" if unresolved else "PASS"})

    return {
        "schema": "decision-integrity/v1",
        "status": "BLOCK" if issues else "PASS",
        "canRecommend": not issues,
        "checkedAt": now.isoformat(),
        "policy": {
            "maxHoldingsAgeHours": MAX_HOLDINGS_AGE_HOURS,
            "maxMarketAgeDays": MAX_MARKET_AGE_DAYS,
            "maxBoardAgeHours": MAX_BOARD_AGE_HOURS,
            "requiredIndexCodes": sorted(EXPECTED_CODES),
            "unresolvedPolicyItemsBlock": True,
        },
        "checks": checks,
        "issues": issues,
        "message": ("输入与政策完整性通过" if not issues else
                    "决策已阻断：输入时效、行情完整性或政策口径尚未通过审计"),
    }


def inject_verdict(raw_text, verdict):
    """Update only the top-level verdict field; preserve generated board formatting."""
    json.loads(raw_text)
    serialized = json.dumps(verdict, ensure_ascii=False, indent=4).replace("\n", "\n    ")
    match = re.search(r'(?m)^ {4}"decisionIntegrity"\s*:', raw_text)
    if match:
        brace = raw_text.find("{", match.end())
        if brace < 0:
            raise ValueError("decisionIntegrity value must be an object")
        depth, in_string, escaped, end = 0, False, False, None
        for i in range(brace, len(raw_text)):
            ch = raw_text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end is None:
            raise ValueError("unterminated decisionIntegrity object")
        updated = raw_text[:brace] + serialized + raw_text[end + 1:]
    else:
        end = raw_text.rfind("}")
        if end < 0:
            raise ValueError("board root object is not closed")
        prefix = raw_text[:end].rstrip()
        comma = "" if prefix.endswith("{") else ","
        updated = prefix + comma + "\n    \"decisionIntegrity\": " + serialized + "\n" + raw_text[end:]
    json.loads(updated)
    return updated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--board", default="board.json")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(args.board)
    raw_text = path.read_text(encoding="utf-8")
    board = json.loads(raw_text)
    verdict = evaluate_board(board)
    if args.write:
        path.write_text(inject_verdict(raw_text, verdict), encoding="utf-8")
    else:
        print(json.dumps(verdict, ensure_ascii=False, indent=2))
    if args.check and "decisionIntegrity" not in board and not args.write:
        raise SystemExit("board.json has no decisionIntegrity verdict")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
