#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Derive a fail-closed verdict for the public FinHub board snapshot."""
from __future__ import annotations

import argparse
from datetime import datetime, date, time, timedelta
import json
import math
import os
import re
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

# ── 契约包（contracts/ 在本仓根下） ──────────────────────────────────────────
# 把仓根放进 sys.path，才能 import contracts.thresholds / contracts.signing。
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from contracts.thresholds import get_thresholds, THRESHOLD_DIGEST  # noqa: E402
from contracts import signing  # noqa: E402

TZ = ZoneInfo("Asia/Shanghai")

# ── D7：阈值单一真相源 ────────────────────────────────────────────────────────
# 同一组时效阈值此前在本文件硬编码 30 处（另有 4 个文件共 29 处）。
# 现在一律从 contracts/thresholds.json 读 —— 改阈值只有一个地方要改。
# 数值本身与之前**完全一致**（36h / 4d / 24h / 5min），没有放宽任何标准。
_THRESHOLDS = get_thresholds()
MAX_HOLDINGS_AGE_HOURS = float(_THRESHOLDS["holdingsMaxAgeHours"])
MAX_MARKET_AGE_DAYS = float(_THRESHOLDS["marketMaxAgeDays"])
MAX_BOARD_AGE_HOURS = float(_THRESHOLDS["boardMaxAgeHours"])
MAX_FUTURE_SKEW_MINUTES = float(_THRESHOLDS["futureClockSkewMinutes"])
POSITION_MAX_AGE_DAYS = float(_THRESHOLDS["positionMaxAgeDays"])
HARD_MAX_RISKY_PCT = float(_THRESHOLDS["hardMaxRiskyPct"])
EXPECTED_CODES = set(_THRESHOLDS["requiredIndices"])
ALLOWED_ACTIONS = {"ADD", "TRIM", "EXIT", "WAIT", "HOLD"}

# ── P0-6：数据仓闸门（B）必须 fail-closed 消费引擎闸门（A）的逐条持仓裁定 ──────
# 背景：board.json 只有 today.position 的 8 个摘要字段（真实文件里 "marketValue"/
# "cash" 各出现 0 次），B 结构上无法审计逐条持仓。A（decision_integrity.py）能审，
# 它的裁定脱敏后由生产链写进 board["holdingsIntegrity"]。B 必须消费这份裁定：
# 看不到就 BLOCK，看到 BLOCK 就 BLOCK，裁定过期就 BLOCK。
# 不新增任何阈值：裁定自身时效复用 MAX_BOARD_AGE_HOURS（24h）。
MAX_VERDICT_AGE_HOURS = MAX_BOARD_AGE_HOURS

# 公开件白名单：board.json 会被推到公开仓，A 的裁定里 issues[].actual /
# checks[].details 是平台名、绝对金额、逐条持仓明细的聚集地，绝不许出境。
HOLDINGS_VERDICT_TOP_KEYS = ("status", "canRecommend", "checkedAt", "schemaVersion")
HOLDINGS_VERDICT_ISSUE_KEYS = ("code", "message")
# checks 里额外放行 ageHours / maxAgeHours / thresholdHours —— 都是标量、不含
# 任何平台名或金额，但 B 需要它们做「裁定与 board 自述互相印证」的交叉校验
# （否则伪造者可以把裁定与 position 的年龄改成互不相干的两个值）。
HOLDINGS_VERDICT_CHECK_KEYS = ("id", "status", "ageHours", "maxAgeHours", "thresholdHours")
# 签名相关字段必须原样保留在公开件里 —— B 要用它们验签。
HOLDINGS_VERDICT_SIGNATURE_KEYS = (signing.SIGNATURE_FIELD,
                                   signing.SIGNED_DIGEST_FIELD,
                                   signing.KEY_ID_FIELD)

# ── D8：交叉校验容差 ──────────────────────────────────────────────────────────
# decisionIntegrity.checks[holdings].ageHours 与 today.position.dataAgeDays*24
# 是同一份快照的两次独立计算（引擎侧 / 导出脚本侧），必然有舍入与分钟级差。
# 容差 2 小时足够覆盖 dataAgeDays 的舍入误差，又远小于 36h 的判定尺度。
CROSS_FIELD_TOLERANCE_HOURS = 2.0


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


def _json_scalar(value):
    """只放行 JSON 标量；dict / list 一律丢弃（那正是 actual/details 的位置）。"""
    return value is None or isinstance(value, (str, int, float, bool))


def sanitize_holdings_verdict(verdict):
    """把引擎裁定投影到公开白名单；非对象返回 None。

    只保留 status / canRecommend / checkedAt / schemaVersion、
    issues[].code|message、checks[].id|status、以及 policy 的标量项。
    issues[].actual、checks[].平台/金额明细、任何未知顶层键一律丢弃——
    board.json 是公开件，引擎裁定里的平台名与金额不得随之出去。
    """
    if not isinstance(verdict, dict):
        return None
    clean = {}
    for key in HOLDINGS_VERDICT_TOP_KEYS:
        if key in verdict and _json_scalar(verdict[key]):
            clean[key] = verdict[key]
    # 签名三件套必须原样保留：B 要用它们验签，剥掉就等于没法验了。
    for key in HOLDINGS_VERDICT_SIGNATURE_KEYS:
        if key in verdict and _json_scalar(verdict[key]):
            clean[key] = verdict[key]
    for source, target, allowed in (
        ("issues", "issues", HOLDINGS_VERDICT_ISSUE_KEYS),
        ("checks", "checks", HOLDINGS_VERDICT_CHECK_KEYS),
    ):
        rows = verdict.get(source)
        if isinstance(rows, list):
            clean[target] = [{k: row[k] for k in allowed if k in row and _json_scalar(row[k])}
                             for row in rows if isinstance(row, dict)]
    policy = verdict.get("policy")
    if isinstance(policy, dict):
        kept = {}
        for key, value in policy.items():
            if _json_scalar(value):
                kept[key] = value
            elif isinstance(value, list) and all(_json_scalar(v) for v in value):
                kept[key] = list(value)
        clean["policy"] = kept
    return clean


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

    # ── P0-6：逐条持仓字段的裁定只能来自引擎闸门 A（B 看不到明细，必须 fail-closed）──
    raw_verdict = board.get("holdingsIntegrity")
    verdict_clean = sanitize_holdings_verdict(raw_verdict)
    verdict_issues = []
    engine_status = None
    engine_can_recommend = None
    engine_codes = []
    if not isinstance(raw_verdict, dict):
        verdict_issues.append({
            "code": "HOLDINGS_VERDICT_MISSING",
            "message": "board.holdingsIntegrity 缺失或不是对象：数据仓看不到逐条持仓字段，"
                       "不得给出 PASS（fail-closed）",
        })
    else:
        engine_status = raw_verdict.get("status")
        engine_can_recommend = raw_verdict.get("canRecommend")
        raw_issues = raw_verdict.get("issues")
        if isinstance(raw_issues, list):
            # 只带走 code（原样、保序），绝不带走 actual 里的平台名/金额/持仓名
            engine_codes = [item["code"] for item in raw_issues
                            if isinstance(item, dict) and isinstance(item.get("code"), str)]

        # ── D10 / D6：签名校验（Ed25519，私钥在本机仓库外，公钥在本仓）────────
        # 背景：board.json 在公开仓里，任何人都能编辑它。纯文本字段（status=BLOCK
        # 改成 PASS、policy 里的阈值改宽）没有签名时无法分辨真假。
        # 私钥只在 E:\investment-os\contracts\ 下，公开仓里只有公钥 —— 改 board.json
        # 的人没有私钥，签不出能过验签的 PASS。
        sig_ok, sig_reason = signing.verify_verdict(raw_verdict)
        if not sig_ok:
            code = ("HOLDINGS_VERDICT_UNSIGNED"
                    if not raw_verdict.get(signing.SIGNATURE_FIELD)
                    else "HOLDINGS_VERDICT_SIGNATURE_INVALID")
            verdict_issues.append({
                "code": code,
                "message": "逐条持仓裁定未通过签名校验：%s。board.json 是公开件，"
                           "任何人都能编辑；没有有效签名的裁定一律不采信（fail-closed）" % sig_reason,
            })

        # ── D8：裁定里的 policy 必须与本仓阈值逐项相等 ──────────────────────
        # 这一条挡住「把阈值改宽」类篡改：即便签名有效，policy 与本仓不一致也 BLOCK。
        verdict_policy = raw_verdict.get("policy")
        if not isinstance(verdict_policy, dict):
            verdict_issues.append({
                "code": "HOLDINGS_VERDICT_POLICY_MISMATCH",
                "message": "逐条持仓裁定缺 policy 段，无法确认它用的是哪套时效标准",
            })
        else:
            policy_mismatch = []
            for key, expected in (("maxHoldingsAgeHours", MAX_HOLDINGS_AGE_HOURS),
                                  ("maxMarketAgeDays", MAX_MARKET_AGE_DAYS),
                                  ("futureClockSkewMinutes", MAX_FUTURE_SKEW_MINUTES)):
                actual = verdict_policy.get(key)
                if actual is None:
                    policy_mismatch.append({"key": key, "expected": expected, "actual": None})
                elif not finite_number(actual) or abs(float(actual) - expected) > 1e-9:
                    policy_mismatch.append({"key": key, "expected": expected, "actual": actual})
            if policy_mismatch:
                verdict_issues.append({
                    "code": "HOLDINGS_VERDICT_POLICY_MISMATCH",
                    "message": "逐条持仓裁定的时效标准与本仓不一致，裁定不可采信",
                    "actual": policy_mismatch,
                })

        checked = parse_dt(raw_verdict.get("checkedAt"))
        if checked is None:
            verdict_issues.append({
                "code": "HOLDINGS_VERDICT_STALE",
                "message": "holdingsIntegrity.checkedAt 缺失或不可解析，无法确认裁定时效",
            })
        else:
            verdict_age_h = (now - checked).total_seconds() / 3600
            if verdict_age_h < -MAX_FUTURE_SKEW_MINUTES / 60:
                verdict_issues.append({
                    "code": "HOLDINGS_VERDICT_STALE",
                    "message": "holdingsIntegrity.checkedAt 位于未来，拒绝该裁定",
                    "actual": round(verdict_age_h, 2),
                })
            elif verdict_age_h > MAX_VERDICT_AGE_HOURS:
                verdict_issues.append({
                    "code": "HOLDINGS_VERDICT_STALE",
                    "message": "holdingsIntegrity 裁定超过24小时未复检",
                    "actual": round(verdict_age_h, 2),
                })
        if engine_status != "PASS" or engine_can_recommend is not True:
            verdict_issues.append({
                "code": "HOLDINGS_VERDICT_BLOCK",
                "message": "引擎闸门 A 判定持仓输入不可用于决策，数据仓必须一并阻断",
                "actual": engine_codes,
                "engineStatus": engine_status if _json_scalar(engine_status) else None,
            })
    issues.extend(verdict_issues)
    checks.append({
        "id": "holdingsVerdict",
        "status": "BLOCK" if verdict_issues else "PASS",
        "maxAgeHours": MAX_VERDICT_AGE_HOURS,
        "engineStatus": engine_status if _json_scalar(engine_status) else None,
        "engineIssues": engine_codes,
        "canRecommend": engine_can_recommend if isinstance(engine_can_recommend, bool) else None,
        "checkedAt": verdict_clean.get("checkedAt") if verdict_clean else None,
        "schemaVersion": verdict_clean.get("schemaVersion") if verdict_clean else None,
        "signatureVerified": bool(verdict_clean and signing.SIGNATURE_FIELD in verdict_clean
                                  and not any(x["code"] in ("HOLDINGS_VERDICT_UNSIGNED",
                                                           "HOLDINGS_VERDICT_SIGNATURE_INVALID")
                                              for x in verdict_issues)),
    })

    # ── D6：交叉字段校验 —— 裁定、decisionIntegrity、position 三者必须互相印证 ──
    # 为什么需要：签名只能保证「这份裁定没被改过」，不能保证「这份裁定说的就是
    # 这份 board 的持仓」。篡改者若只改 position.dataAgeDays（把 2.8 天改成 0.1），
    # 签名依然有效（因为裁定本身没动），但 board 自述与裁定就自相矛盾了。
    # 这里把三处独立来源互相比对，任何一处对不上就 BLOCK。
    cross_field_issues = []
    decision_integrity = board.get("decisionIntegrity")
    # ── (c1) 裁定自述的持仓年龄 vs position 自述的年龄 ──────────────────────
    # 这一条**不依赖** decisionIntegrity 是否存在：裁定里 checks[holdings].maxAgeHours
    # 总是有的（引擎按 ts 算出），position.dataAgeDays 也是同一份快照的年龄。
    # 两者对不上，说明有人只改了其中一边 —— 正是 D6 攻击 C 的手法。
    verdict_holdings_check = None
    if isinstance(raw_verdict, dict):
        for item in raw_verdict.get("checks") or []:
            if isinstance(item, dict) and item.get("id") == "holdings":
                verdict_holdings_check = item
                break
    if (verdict_holdings_check is not None and position_age_h is not None
            and finite_number(verdict_holdings_check.get("maxAgeHours"))):
        verdict_age = float(verdict_holdings_check["maxAgeHours"])
        if abs(verdict_age - position_age_h) > CROSS_FIELD_TOLERANCE_HOURS:
            cross_field_issues.append({
                "code": "HOLDINGS_VERDICT_FIELD_MISMATCH",
                "message": "裁定的持仓年龄与 position 自述的年龄对不上"
                           "（容差 %.1f 小时）—— 两处必有一处被单独改过" % CROSS_FIELD_TOLERANCE_HOURS,
                "actual": {"verdictAgeHours": round(verdict_age, 2),
                           "positionAgeHours": round(position_age_h, 2)},
            })

    if isinstance(decision_integrity, dict):
        # (a) 已有 decisionIntegrity 的 policy 必须与本仓阈值一致
        di_policy = decision_integrity.get("policy")
        if isinstance(di_policy, dict):
            di_mismatch = []
            for key, expected in (("maxHoldingsAgeHours", MAX_HOLDINGS_AGE_HOURS),
                                  ("maxMarketAgeDays", MAX_MARKET_AGE_DAYS),
                                  ("maxBoardAgeHours", MAX_BOARD_AGE_HOURS),
                                  ("holdingsVerdictMaxAgeHours", MAX_VERDICT_AGE_HOURS)):
                actual = di_policy.get(key)
                if actual is None:
                    continue
                if not finite_number(actual) or abs(float(actual) - expected) > 1e-9:
                    di_mismatch.append({"key": key, "expected": expected, "actual": actual})
            if di_mismatch:
                cross_field_issues.append({
                    "code": "DECISION_POLICY_MISMATCH",
                    "message": "board.decisionIntegrity 的时效标准与本仓不一致",
                    "actual": di_mismatch,
                })
        # (b) decisionIntegrity 里记录的 holdingsVerdict.checkedAt 必须与裁定一致
        di_checks = decision_integrity.get("checks")
        di_verdict_check = None
        di_holdings_check = None
        if isinstance(di_checks, list):
            for item in di_checks:
                if not isinstance(item, dict):
                    continue
                if item.get("id") == "holdingsVerdict":
                    di_verdict_check = item
                elif item.get("id") == "holdings":
                    di_holdings_check = item
        raw_verdict_checked = raw_verdict.get("checkedAt") if isinstance(raw_verdict, dict) else None
        if (isinstance(di_verdict_check, dict) and raw_verdict_checked
                and di_verdict_check.get("checkedAt")):
            left = parse_dt(di_verdict_check.get("checkedAt"))
            right = parse_dt(raw_verdict_checked)
            if left is not None and right is not None and abs((left - right).total_seconds()) > 60:
                cross_field_issues.append({
                    "code": "HOLDINGS_VERDICT_FIELD_MISMATCH",
                    "message": "decisionIntegrity 记录的裁定时刻与 holdingsIntegrity 不一致",
                    "actual": {"decisionIntegrity": di_verdict_check.get("checkedAt"),
                               "holdingsIntegrity": raw_verdict_checked},
                })
        # (c) decisionIntegrity 里记录的持仓年龄必须与 position 的年龄一致
        if isinstance(di_holdings_check, dict) and position_age_h is not None:
            di_age = di_holdings_check.get("ageHours")
            if finite_number(di_age) and abs(float(di_age) - position_age_h) > CROSS_FIELD_TOLERANCE_HOURS:
                cross_field_issues.append({
                    "code": "HOLDINGS_VERDICT_FIELD_MISMATCH",
                    "message": "decisionIntegrity 记录的持仓年龄与 position 的年龄对不上"
                               "（容差 %.1f 小时）" % CROSS_FIELD_TOLERANCE_HOURS,
                    "actual": {"decisionIntegrityAgeHours": round(float(di_age), 2),
                               "positionAgeHours": round(position_age_h, 2)},
                })
    issues.extend(cross_field_issues)

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
    if market_asof is not None and len(dates) == 1 and market_asof.date().isoformat() not in dates:
        issues.append({"code": "MARKET_ASOF_MISMATCH", "message": "指数行情汇总时点与逐项日期不一致",
                       "actual": market_asof.date().isoformat(), "expected": sorted(dates)})
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
    if not finite_number(hard_max) or float(hard_max) > HARD_MAX_RISKY_PCT:
        issues.append({"code": "POLICY_HARD_CAP",
                       "message": "风险仓硬上限缺失或超过策略契约 %.2f%%" % HARD_MAX_RISKY_PCT})
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
        "source": "finhub-data/tools/board_integrity.py",
        "status": "BLOCK" if issues else "PASS",
        "canRecommend": not issues,
        "checkedAt": now.isoformat(),
        "policy": {
            "maxHoldingsAgeHours": MAX_HOLDINGS_AGE_HOURS,
            "maxMarketAgeDays": MAX_MARKET_AGE_DAYS,
            "maxBoardAgeHours": MAX_BOARD_AGE_HOURS,
            "requiredIndexCodes": sorted(EXPECTED_CODES),
            "unresolvedPolicyItemsBlock": True,
            # P0-6：B 不再对「看不到的逐条持仓」背书，必须消费引擎闸门 A 的裁定
            "requiresHoldingsVerdict": True,
            "holdingsVerdictMaxAgeHours": MAX_VERDICT_AGE_HOURS,
            # D6/D10：裁定必须带可验签的签名
            "requiresHoldingsVerdictSignature": True,
            # D7：阈值来自哪一份文件（跨仓交叉校验用）
            "thresholdSource": "contracts/thresholds.json",
            "thresholdDigest": THRESHOLD_DIGEST,
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
    if args.check:
        stored = board.get("decisionIntegrity") or {}
        stored_codes = [x.get("code") for x in stored.get("issues", [])]
        current_codes = [x.get("code") for x in verdict.get("issues", [])]
        if stored.get("status") != verdict.get("status") or stored_codes != current_codes:
            raise SystemExit("stored decisionIntegrity verdict does not match current board inputs")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
