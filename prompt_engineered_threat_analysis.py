import argparse
import ast
import csv
import json
import os
from collections import Counter, defaultdict
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path
from statistics import mean
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from env_loader import load_local_env


RISK_BANDS = [
    (0, 20, "Normal activity"),
    (20, 40, "Suspicious behavior"),
    (40, 60, "High risk"),
    (60, 80, "Confirmed threat"),
    (80, 101, "Critical threat"),
]

CONFIDENCE_BANDS = [
    (0.0, 0.3, "Low confidence"),
    (0.3, 0.6, "Medium confidence"),
    (0.6, 0.8, "High confidence"),
    (0.8, 1.01, "Very high confidence"),
]

Z_SCORE_BANDS = [
    (-10_000, 1.5, "Normal range"),
    (1.5, 2.0, "Minor anomaly"),
    (2.0, 3.0, "Significant anomaly"),
    (3.0, 10_000, "Extreme outlier"),
]

SEVERITY_WEIGHTS = {
    "info": 1,
    "low": 2,
    "medium": 4,
    "high": 6,
    "critical": 8,
    "emergency": 10,
}

SEVERITY_RESPONSE_WINDOW = {
    "emergency": "Immediate response required",
    "critical": "Respond within hours",
    "high": "Respond within 24 hours",
    "medium": "Address within 1 week",
    "low": "Address when convenient",
    "info": "Trend and monitor",
}

THEME_KEYWORDS = {
    "ai_model_abuse": ["prompt", "poison", "model", "injection"],
    "credential_abuse": ["credential", "phish", "bypass", "locked", "failed"],
    "malware_and_evasion": ["malware", "backdoor", "dns tunneling", "fileless", "domain fronting"],
    "data_theft_and_resource_abuse": ["exfil", "crypto", "api_abuse", "latency_spike"],
}

EVENT_OWNER_MAP = {
    "ai": "AI Security / SOC",
    "auth": "Identity Security / SOC",
    "cloud": "Cloud Security / SOC",
    "endpoint": "Endpoint Security / SOC",
    "firewall": "Network Security / SOC",
    "ids_alert": "SOC / Incident Response",
    "iot": "IoT / OT Security",
    "network": "Network Security / SOC",
    "proxy": "Network Security / SOC",
    "web": "Application Security / SOC",
}


def is_missing(value: Any) -> bool:
    return value in ("", None, "N/A")


def parse_mapping(value: str) -> dict[str, Any]:
    if is_missing(value):
        return {}
    try:
        parsed = ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def to_float(value: Any) -> float | None:
    if is_missing(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def pct(part: int, whole: int) -> float:
    return round((part / whole) * 100, 2) if whole else 0.0


def band_value(value: float, bands: list[tuple[float, float, str]]) -> str:
    for lower, upper, label in bands:
        if lower <= value < upper:
            return label
    return bands[-1][2]


def ordered_counts(counter_obj: Counter, total: int, limit: int | None = None) -> list[dict[str, Any]]:
    items = counter_obj.most_common(limit)
    return [{"label": label, "count": count, "pct": pct(count, total)} for label, count in items]


def load_rows(data_path: str | Path) -> list[dict[str, Any]]:
    path = Path(data_path)
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    for row in rows:
        row["parsed_timestamp"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
        row["advanced_metadata_dict"] = parse_mapping(row["advanced_metadata"])
        row["behavioral_analytics_dict"] = parse_mapping(row["behavioral_analytics"])
        row["src_ip_normalized"] = row["src_ip"] or "unknown"

    return rows


def compute_source_z_scores(source_counts: Counter) -> dict[str, float]:
    counts = list(source_counts.values())
    average = sum(counts) / len(counts)
    variance = sum((count - average) ** 2 for count in counts) / len(counts)
    std_dev = variance ** 0.5
    if std_dev == 0:
        return {source: 0.0 for source in source_counts}
    return {source: (count - average) / std_dev for source, count in source_counts.items()}


def compute_event_pairs(rows: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    events_by_source_minute: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in rows:
        key = (row["src_ip_normalized"], row["parsed_timestamp"].strftime("%Y-%m-%d %H:%M"))
        events_by_source_minute[key].append(row["event_type"])

    pair_counts: Counter = Counter()
    for event_list in events_by_source_minute.values():
        for pair in combinations(sorted(set(event_list)), 2):
            pair_counts[pair] += 1

    return [{"pair": list(pair), "count": count} for pair, count in pair_counts.most_common(limit)]


def compute_theme_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    theme_counts: Counter = Counter()
    for row in rows:
        text = " ".join(
            filter(None, [row.get("event_type"), row.get("action"), row.get("alert_type"), row.get("category")])
        ).lower()
        for theme, keywords in THEME_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                theme_counts[theme] += 1

    return [{"theme": theme, "count": count, "pct": pct(count, len(rows))} for theme, count in theme_counts.most_common()]


def classify_case(risk_score: float, confidence: float, severity: str, z_score: float) -> str:
    if severity == "emergency" or (risk_score >= 80 and confidence >= 0.8):
        return "Critical threat"
    if risk_score >= 60 and confidence >= 0.6:
        return "Confirmed threat"
    if risk_score >= 20 or confidence >= 0.3 or z_score >= 2.0:
        return "Suspicious"
    return "Monitor"


def owner_for_event_type(event_type: str) -> str:
    return EVENT_OWNER_MAP.get((event_type or "").lower(), "SOC")


def build_detailed_classification_reason(case: dict[str, Any]) -> str:
    triggers = []
    risk_score = case["risk_score"]
    confidence = case["confidence"]
    severity = case["severity"]
    z_score = case["source_z_score"]

    if case["classification"] == "Critical threat":
        if severity == "emergency":
            triggers.append(
                f"Severity is emergency, which is treated as an immediate Critical threat under the rubric."
            )
        else:
            triggers.append(
                f"Risk score {risk_score} is in the Critical threat band (>=80) and confidence {confidence} is Very high (>=0.8)."
            )
    elif case["classification"] == "Confirmed threat":
        triggers.append(
            f"Risk score {risk_score} is in the confirmed-threat range (>=60) and confidence {confidence} is high enough (>=0.6) to move beyond suspicion."
        )
    elif case["classification"] == "Suspicious":
        suspicious_conditions = []
        if risk_score >= 20:
            suspicious_conditions.append(f"risk score {risk_score} is above the suspicious threshold (>=20)")
        if confidence >= 0.3:
            suspicious_conditions.append(f"confidence {confidence} is above the investigation threshold (>=0.3)")
        if z_score >= 2.0:
            suspicious_conditions.append(f"source z-score {z_score} is a significant anomaly (>=2.0)")
        triggers.append(
            "The event is categorized as Suspicious because " + ", ".join(suspicious_conditions) + "."
        )
    else:
        triggers.append(
            f"Risk score {risk_score}, confidence {confidence}, and z-score {z_score} stay below the investigation thresholds, so the event remains in Monitor."
        )

    if case["severity"] in {"critical", "emergency", "high"}:
        triggers.append(
            f"Severity={severity} increases urgency and sets the response window to '{case['response_window']}'."
        )
    if case["source_z_score"] >= 3.0:
        triggers.append(
            f"Source z-score {z_score} is an Extreme outlier, which supports escalation and correlation."
        )
    elif case["source_z_score"] >= 2.0:
        triggers.append(
            f"Source z-score {z_score} is a Significant anomaly, which supports investigation."
        )

    if case["frequency_anomaly"] or case["sequence_anomaly"]:
        triggers.append(
            f"Behavioral analytics flags are present: frequency_anomaly={case['frequency_anomaly']}, sequence_anomaly={case['sequence_anomaly']}."
        )

    if case["alert_type"] != "none":
        triggers.append(f"Alert type '{case['alert_type']}' adds direct detection context.")
    if case["category"] != "none":
        triggers.append(f"Category '{case['category']}' adds additional threat context.")
    if case["action"] != "none":
        triggers.append(f"Observed action '{case['action']}' was included in the classification context.")
    if case["src_ip"] == "unknown":
        triggers.append(
            "The normalized source is 'unknown', so missing attribution may be contributing to a concentrated anomaly cluster."
        )

    return " ".join(triggers)


def build_recommendation(case: dict[str, Any]) -> tuple[str, str]:
    actions = []

    if case["classification"] == "Critical threat":
        actions.append("Escalate immediately and validate containment status.")
    elif case["classification"] == "Confirmed threat":
        actions.append("Assign to an analyst for same-day investigation and scoping.")
    elif case["classification"] == "Suspicious":
        actions.append("Queue for analyst review and correlation with adjacent telemetry.")
    else:
        actions.append("Monitor for recurrence and include in trend review.")

    event_type = case["event_type"]
    action = case["action"].lower()
    alert_type = case["alert_type"].lower()

    if event_type == "endpoint":
        actions.append("Inspect the affected host for file, process, and parent-child execution activity.")
    elif event_type == "cloud":
        actions.append("Review cloud API activity, impacted resources, and identity exposure for the session.")
    elif event_type == "auth":
        actions.append("Validate account activity, MFA posture, and recent authentication failures or bypass attempts.")
    elif event_type == "ai":
        actions.append("Review model prompts, inputs, and outputs for abuse, poisoning, or extraction indicators.")
    elif event_type == "iot":
        actions.append("Check device state, firmware, and network isolation controls for the impacted IoT asset.")
    elif event_type in {"ids_alert", "network", "firewall", "proxy"}:
        actions.append("Review network telemetry and block confirmed malicious indicators if validated.")

    if "credential" in alert_type or action in {"login_failed", "mfa_bypass", "credential_stuffing"}:
        actions.append("Check for account takeover patterns and block or challenge the source if warranted.")
    if "dns" in alert_type or "tunnel" in alert_type or action == "dns_tunneling":
        actions.append("Inspect DNS activity for exfiltration or command-and-control behavior.")
    if action in {"powershell_exec", "wmi_exec", "process_start", "process_stop"}:
        actions.append("Capture process lineage and determine whether execution was authorized.")
    if action in {"training_data_poisoning", "prompt_injection", "membership_inference", "model_extraction"}:
        actions.append("Scope AI-service exposure and preserve prompt or model access logs.")
    if action in {"api_abuse", "container_escape"}:
        actions.append("Audit affected identities, tokens, and cloud resource permissions.")

    if case["frequency_anomaly"] or case["sequence_anomaly"] or case["source_z_score"] >= 2.0:
        actions.append("Correlate neighboring events from the same source and time window before closing the case.")
    if case["src_ip"] == "unknown":
        actions.append("Validate whether missing source attribution is a telemetry issue or a real aggregation point.")

    reason_bits = [
        f"severity={case['severity']}",
        f"risk={case['risk_score']} ({case['risk_band']})",
        f"confidence={case['confidence']} ({case['confidence_band']})",
        f"z_score={case['source_z_score']} ({case['z_score_band']})",
    ]
    if case["frequency_anomaly"] or case["sequence_anomaly"]:
        reason_bits.append(
            f"behavioral_flags=frequency:{case['frequency_anomaly']} sequence:{case['sequence_anomaly']}"
        )

    deduped_actions = list(dict.fromkeys(actions))
    return " ".join(deduped_actions), "; ".join(reason_bits)


def build_case_record(row: dict[str, Any], source_z_scores: dict[str, float]) -> dict[str, Any]:
    metadata = row["advanced_metadata_dict"]
    behavior = row["behavioral_analytics_dict"]
    risk_score = to_float(metadata.get("risk_score")) or 0.0
    confidence = to_float(metadata.get("confidence")) or 0.0
    severity = (row["severity"] or "").lower()
    z_score = source_z_scores.get(row["src_ip_normalized"], 0.0)
    anomaly_bonus = 0
    if behavior.get("frequency_anomaly") is True:
        anomaly_bonus += 1
    if behavior.get("sequence_anomaly") is True:
        anomaly_bonus += 1

    composite_score = (
        risk_score * 0.5
        + confidence * 20
        + SEVERITY_WEIGHTS.get(severity, 0) * 3
        + anomaly_bonus * 5
        + min(max(z_score, 0.0), 5.0) * 2
    )

    case = {
        "event_id": row["event_id"],
        "timestamp": row["timestamp"],
        "event_type": row["event_type"],
        "source": row["source"],
        "user": row["user"] or "none",
        "severity": severity,
        "severity_weight": SEVERITY_WEIGHTS.get(severity, 0),
        "action": row["action"] or "none",
        "src_ip": row["src_ip_normalized"],
        "alert_type": row["alert_type"] or "none",
        "category": row["category"] or "none",
        "device_type": row["device_type"] or "none",
        "cloud_service": row["cloud_service"] or "none",
        "model_id": row["model_id"] or "none",
        "risk_score": round(risk_score, 2),
        "risk_band": band_value(risk_score, RISK_BANDS),
        "confidence": round(confidence, 3),
        "confidence_band": band_value(confidence, CONFIDENCE_BANDS),
        "source_z_score": round(z_score, 2),
        "z_score_band": band_value(z_score, Z_SCORE_BANDS),
        "frequency_anomaly": bool(behavior.get("frequency_anomaly")),
        "sequence_anomaly": bool(behavior.get("sequence_anomaly")),
        "classification": classify_case(risk_score, confidence, severity, z_score),
        "response_window": SEVERITY_RESPONSE_WINDOW.get(severity, "Investigate"),
        "composite_score": round(composite_score, 2),
        "recommended_owner": owner_for_event_type(row["event_type"]),
    }
    recommendation, rationale = build_recommendation(case)
    case["recommended_action"] = recommendation
    case["recommendation_rationale"] = rationale
    case["detailed_classification_reason"] = build_detailed_classification_reason(case)
    return case


def compute_case_records(
    rows: list[dict[str, Any]],
    source_z_scores: dict[str, float],
    limit: int | None = None,
    progress_every: int | None = None,
    log_fn: Any | None = None,
) -> list[dict[str, Any]]:
    cases = []
    total_rows = len(rows)
    for index, row in enumerate(rows, start=1):
        cases.append(build_case_record(row, source_z_scores))
        if progress_every and log_fn and (index % progress_every == 0 or index == total_rows):
            log_fn(f"Processed {index:,}/{total_rows:,} SIEM events for row-level recommendations...")

    cases.sort(key=lambda item: item["composite_score"], reverse=True)
    return cases[:limit] if limit is not None else cases


def compute_priority_cases(
    rows: list[dict[str, Any]],
    source_z_scores: dict[str, float],
    limit: int = 12,
) -> list[dict[str, Any]]:
    return compute_case_records(rows, source_z_scores, limit=limit)


def export_all_case_recommendations(
    data_path: str | Path = "advanced_siem.csv",
    output_dir: str | Path = "llm_outputs",
    progress_every: int = 5_000,
    log_fn: Any | None = print,
) -> dict[str, Any]:
    rows = load_rows(data_path)
    source_counts = Counter(row["src_ip_normalized"] for row in rows)
    source_z_scores = compute_source_z_scores(source_counts)
    cases = compute_case_records(
        rows,
        source_z_scores,
        limit=None,
        progress_every=progress_every,
        log_fn=log_fn,
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    csv_path = output_path / "all_siem_incident_recommendations.csv"
    final_csv_path = csv_path

    fieldnames = list(cases[0].keys()) if cases else []
    try:
        with final_csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(cases)
    except PermissionError:
        final_csv_path = output_path / f"all_siem_incident_recommendations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        if log_fn:
            log_fn(f"Primary export file was locked. Writing results to: {final_csv_path}")
        with final_csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(cases)

    classification_counts = Counter(case["classification"] for case in cases)
    owner_counts = Counter(case["recommended_owner"] for case in cases)
    severity_counts = Counter(case["severity"] for case in cases)

    return {
        "csv_path": str(final_csv_path),
        "row_count": len(cases),
        "classification_counts": dict(classification_counts),
        "owner_counts": dict(owner_counts),
        "severity_counts": dict(severity_counts),
        "top_cases": cases[:10],
    }


def build_context(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_rows = len(rows)
    risk_scores = []
    confidence_scores = []
    severity_counts: Counter = Counter()
    event_type_counts: Counter = Counter()
    action_counts: Counter = Counter()
    source_counts: Counter = Counter()
    source_risk_sum: Counter = Counter()
    source_conf_sum: Counter = Counter()
    source_high_severity_counts: Counter = Counter()
    behavioral_rows = 0
    behavioral_flags = Counter()

    for row in rows:
        metadata = row["advanced_metadata_dict"]
        behavior = row["behavioral_analytics_dict"]
        risk_score = to_float(metadata.get("risk_score"))
        confidence = to_float(metadata.get("confidence"))
        severity = (row["severity"] or "").lower()
        src_ip = row["src_ip_normalized"]

        severity_counts[severity] += 1
        event_type_counts[row["event_type"]] += 1
        source_counts[src_ip] += 1

        if not is_missing(row["action"]):
            action_counts[row["action"]] += 1

        if risk_score is not None:
            risk_scores.append(risk_score)
            source_risk_sum[src_ip] += risk_score

        if confidence is not None:
            confidence_scores.append(confidence)
            source_conf_sum[src_ip] += confidence

        if severity in ("critical", "emergency"):
            source_high_severity_counts[src_ip] += 1

        if behavior:
            behavioral_rows += 1
            if behavior.get("frequency_anomaly") is True:
                behavioral_flags["frequency_anomaly_true"] += 1
            if behavior.get("sequence_anomaly") is True:
                behavioral_flags["sequence_anomaly_true"] += 1

    source_z_scores = compute_source_z_scores(source_counts)

    risk_band_counts: Counter = Counter()
    for score in risk_scores:
        risk_band_counts[band_value(score, RISK_BANDS)] += 1

    confidence_band_counts: Counter = Counter()
    for score in confidence_scores:
        confidence_band_counts[band_value(score, CONFIDENCE_BANDS)] += 1

    anomalous_sources = []
    for source, z_score in sorted(source_z_scores.items(), key=lambda item: item[1], reverse=True)[:15]:
        count = source_counts[source]
        anomalous_sources.append(
            {
                "src_ip": source,
                "event_count": count,
                "event_pct": pct(count, total_rows),
                "z_score": round(z_score, 2),
                "z_score_band": band_value(z_score, Z_SCORE_BANDS),
                "avg_risk_score": round(source_risk_sum[source] / count, 2) if count else 0.0,
                "avg_confidence": round(source_conf_sum[source] / count, 3) if count else 0.0,
                "high_severity_count": source_high_severity_counts[source],
                "high_severity_pct": pct(source_high_severity_counts[source], count),
            }
        )

    out_of_2025 = sum(1 for row in rows if row["parsed_timestamp"].year != 2025)
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "dataset": {
            "row_count": total_rows,
            "time_range": {
                "start": min(row["parsed_timestamp"] for row in rows).isoformat(sep=" "),
                "end": max(row["parsed_timestamp"] for row in rows).isoformat(sep=" "),
                "outside_2025_rows": out_of_2025,
                "outside_2025_pct": pct(out_of_2025, total_rows),
            },
            "event_type_counts": ordered_counts(event_type_counts, total_rows),
            "severity_counts": ordered_counts(severity_counts, total_rows),
            "top_actions": ordered_counts(action_counts, total_rows, limit=15),
        },
        "metrics": {
            "risk_score": {
                "average": round(mean(risk_scores), 2),
                "minimum": round(min(risk_scores), 2),
                "maximum": round(max(risk_scores), 2),
                "bands": ordered_counts(risk_band_counts, len(risk_scores)),
            },
            "confidence_score": {
                "average": round(mean(confidence_scores), 3),
                "minimum": round(min(confidence_scores), 2),
                "maximum": round(max(confidence_scores), 2),
                "bands": ordered_counts(confidence_band_counts, len(confidence_scores)),
            },
            "z_score": {
                "significant_anomalies": sum(1 for score in source_z_scores.values() if score > 2.0),
                "extreme_outliers": sum(1 for score in source_z_scores.values() if score > 3.0),
                "top_sources": anomalous_sources,
            },
            "behavioral_analytics": {
                "rows_with_behavioral_data": behavioral_rows,
                "rows_with_behavioral_data_pct": pct(behavioral_rows, total_rows),
                "frequency_anomaly_true": behavioral_flags["frequency_anomaly_true"],
                "sequence_anomaly_true": behavioral_flags["sequence_anomaly_true"],
            },
        },
        "event_pairings": compute_event_pairs(rows),
        "theme_counts": compute_theme_counts(rows),
        "priority_cases": compute_priority_cases(rows, source_z_scores),
        "metric_rubric": {
            "risk_score": {
                "0-20": "Normal activity",
                "20-40": "Suspicious behavior",
                "40-60": "High risk",
                "60-80": "Confirmed threat",
                "80-100": "Critical threat",
            },
            "confidence_score": {
                "0.0-0.3": "Low confidence, likely false positive",
                "0.3-0.6": "Medium confidence, investigate",
                "0.6-0.8": "High confidence, likely threat",
                "0.8-1.0": "Very high confidence, definite threat",
            },
            "severity_categories": {
                "emergency": "System critical, immediate response required",
                "critical": "Major impact, respond within hours",
                "high": "Significant impact, respond within 24 hours",
                "medium": "Notable issue, address within 1 week",
                "low": "Minor issue, address when convenient",
                "info": "Informational, for trending/analytics",
            },
            "z_score": {
                "<1.5": "Normal range",
                "1.5-2.0": "Minor anomaly",
                "2.0-3.0": "Significant anomaly",
                ">3.0": "Extreme outlier (definitely investigate)",
            },
        },
    }


def build_system_prompt() -> str:
    return (
        "You are a senior SOC threat analyst performing structured threat analysis from a SIEM dataset summary. "
        "Use only the supplied evidence. Do not invent incidents, affected assets, threat actors, or CVEs that are not in the data. "
        "Treat the metric rubric as binding: risk score, confidence score, severity, and z-score definitions must drive your reasoning. "
        "When evidence is ambiguous, say so and identify false-positive risk. "
        "Return JSON only and do not wrap it in markdown fences, prose, or commentary. "
        "Return strict JSON only, with these keys: overall_posture, executive_summary, priority_findings, "
        "attack_patterns, false_positive_risks, recommended_actions, triage_sla. "
        "priority_findings must be an array of objects with keys: finding, classification, severity, "
        "confidence_level, evidence, rationale, recommended_action. "
        "attack_patterns must be an array of objects with keys: pattern, supporting_evidence, analyst_judgment. "
        "recommended_actions must contain immediate, next_24_hours, next_7_days arrays. "
        "triage_sla must map emergency, critical, high, medium, low, info to response guidance."
    )


def build_user_prompt(context: dict[str, Any]) -> str:
    return (
        "Analyze the following SIEM dataset context using the provided metric rubric. "
        "Classify threat posture, identify the most important attack patterns, flag false-positive risk, "
        "and recommend triage actions. "
        "The response must be a single valid JSON object matching the required schema exactly.\n\nDataset context JSON:\n"
        f"{json.dumps(context, indent=2)}"
    )


def extract_response_text(response_obj: dict[str, Any]) -> str:
    direct_text = response_obj.get("output_text")
    if isinstance(direct_text, str) and direct_text.strip():
        return direct_text.strip()

    text_parts = []
    for item in response_obj.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text" and content.get("text"):
                text_parts.append(content["text"])
    return "\n".join(text_parts).strip()


def maybe_parse_json(text: str) -> dict[str, Any] | None:
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if len(lines) >= 3:
            candidate = "\n".join(lines[1:-1]).strip()

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(candidate[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def build_gemini_response_schema() -> dict[str, Any]:
    severity_enum = ["emergency", "critical", "high", "medium", "low", "info"]
    confidence_enum = [
        "Low confidence",
        "Medium confidence",
        "High confidence",
        "Very high confidence",
    ]
    classification_enum = ["Critical threat", "Confirmed threat", "Suspicious", "Monitor"]

    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "overall_posture": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "label": {
                        "type": "string",
                        "enum": ["Critical", "High", "Moderate", "Low"],
                        "description": "Overall threat posture label.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Short evidence-based explanation for the overall posture.",
                    },
                },
                "required": ["label", "rationale"],
            },
            "executive_summary": {
                "type": "string",
                "description": "A concise analyst summary grounded only in the supplied data.",
            },
            "priority_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "finding": {"type": "string"},
                        "classification": {"type": "string", "enum": classification_enum},
                        "severity": {"type": "string", "enum": severity_enum},
                        "confidence_level": {"type": "string", "enum": confidence_enum},
                        "evidence": {"type": "array", "items": {"type": "string"}},
                        "rationale": {"type": "string"},
                        "recommended_action": {"type": "string"},
                    },
                    "required": [
                        "finding",
                        "classification",
                        "severity",
                        "confidence_level",
                        "evidence",
                        "rationale",
                        "recommended_action",
                    ],
                },
            },
            "attack_patterns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "pattern": {"type": "string"},
                        "supporting_evidence": {"type": "array", "items": {"type": "string"}},
                        "analyst_judgment": {"type": "string"},
                    },
                    "required": ["pattern", "supporting_evidence", "analyst_judgment"],
                },
            },
            "false_positive_risks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "risk": {"type": "string"},
                        "evidence": {"type": "string"},
                        "impact": {"type": "string"},
                    },
                    "required": ["risk", "evidence", "impact"],
                },
            },
            "recommended_actions": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "immediate": {"type": "array", "items": {"type": "string"}},
                    "next_24_hours": {"type": "array", "items": {"type": "string"}},
                    "next_7_days": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["immediate", "next_24_hours", "next_7_days"],
            },
            "triage_sla": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "emergency": {"type": "string"},
                    "critical": {"type": "string"},
                    "high": {"type": "string"},
                    "medium": {"type": "string"},
                    "low": {"type": "string"},
                    "info": {"type": "string"},
                },
                "required": ["emergency", "critical", "high", "medium", "low", "info"],
            },
        },
        "required": [
            "overall_posture",
            "executive_summary",
            "priority_findings",
            "attack_patterns",
            "false_positive_risks",
            "recommended_actions",
            "triage_sla",
        ],
    }


def normalize_analysis_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None

    required_top_level = [
        "overall_posture",
        "executive_summary",
        "priority_findings",
        "attack_patterns",
        "false_positive_risks",
        "recommended_actions",
        "triage_sla",
    ]
    if any(key not in payload for key in required_top_level):
        return None

    if not isinstance(payload["overall_posture"], dict):
        return None
    if not isinstance(payload["executive_summary"], str):
        return None
    if not isinstance(payload["priority_findings"], list):
        return None
    if not isinstance(payload["attack_patterns"], list):
        return None
    if not isinstance(payload["false_positive_risks"], list):
        return None
    if not isinstance(payload["recommended_actions"], dict):
        return None
    if not isinstance(payload["triage_sla"], dict):
        return None

    recommended_actions = payload["recommended_actions"]
    for phase in ("immediate", "next_24_hours", "next_7_days"):
        if phase not in recommended_actions:
            recommended_actions[phase] = []
        elif not isinstance(recommended_actions[phase], list):
            recommended_actions[phase] = [str(recommended_actions[phase])]

    triage_sla = payload["triage_sla"]
    for severity, guidance in SEVERITY_RESPONSE_WINDOW.items():
        if severity not in triage_sla:
            triage_sla[severity] = guidance

    return payload


def call_gemini_analysis(
    system_prompt: str,
    prompt_text: str,
    model: str | None = None,
    timeout: int = 120,
) -> tuple[dict[str, Any] | None, str | None]:
    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None, "GOOGLE_API_KEY is not set."

    model_name = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"

    request_body = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": prompt_text}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
            "responseJsonSchema": build_gemini_response_schema(),
        },
    }

    request = Request(
        url,
        data=json.dumps(request_body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return None, f"HTTP {exc.code}: {body}"
    except URLError as exc:
        return None, f"Network error: {exc}"
    except TimeoutError:
        return None, "Timed out waiting for Gemini response."

    try:
        candidate = payload["candidates"][0]
        output_text = candidate["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        return None, "Gemini response did not contain text output."

    finish_reason = candidate.get("finishReason")
    if finish_reason and finish_reason not in {"STOP", "MAX_TOKENS"}:
        return None, f"Gemini stopped with finishReason={finish_reason}."

    parsed = maybe_parse_json(output_text)
    if parsed is None:
        return None, "Gemini response was not valid JSON."

    normalized = normalize_analysis_payload(parsed)
    if normalized is None:
        return None, "Gemini response JSON was missing expected keys."
    return normalized, None


def heuristic_synthesis(context: dict[str, Any]) -> dict[str, Any]:
    metrics = context["metrics"]
    dataset = context["dataset"]
    top_anomaly = metrics["z_score"]["top_sources"][0]
    risk_bands = {entry["label"]: entry["count"] for entry in metrics["risk_score"]["bands"]}
    confidence_bands = {entry["label"]: entry["count"] for entry in metrics["confidence_score"]["bands"]}

    confirmed_count = risk_bands.get("Confirmed threat", 0) + risk_bands.get("Critical threat", 0)
    high_risk_count = risk_bands.get("High risk", 0)
    low_confidence_count = confidence_bands.get("Low confidence", 0)

    overall_posture = {
        "label": "Critical",
        "rationale": (
            f"Extreme anomaly concentration on source {top_anomaly['src_ip']} (z-score {top_anomaly['z_score']}) "
            f"combined with {confirmed_count:,} confirmed-or-critical risk events and "
            f"{high_risk_count:,} additional high-risk events."
        ),
    }

    top_event_types = ", ".join(f"{entry['label']} ({entry['count']:,})" for entry in dataset["event_type_counts"][:4])
    top_pair = context["event_pairings"][0] if context["event_pairings"] else {"pair": ["n/a", "n/a"], "count": 0}

    summary = (
        f"The dataset shows a critical threat posture. {confirmed_count:,} events already land in the confirmed or critical "
        f"risk bands, and a further {high_risk_count:,} remain high risk. The strongest single signal is source "
        f"{top_anomaly['src_ip']}, which generates {top_anomaly['event_count']:,} events ({top_anomaly['event_pct']}% of the dataset) "
        f"with z-score {top_anomaly['z_score']}. The activity mix spans {top_event_types}, which suggests broad cross-domain "
        f"attack coverage rather than an isolated alert stream."
    )

    attack_patterns = [
        {
            "pattern": "Cross-domain coordinated attack activity",
            "supporting_evidence": [
                f"Top event families are distributed across {top_event_types}.",
                f"Top same-minute co-occurrence is {top_pair['pair'][0]} + {top_pair['pair'][1]} ({top_pair['count']} pairings).",
            ],
            "analyst_judgment": "Likely multi-stage attack activity or intentionally broad synthetic adversary simulation.",
        },
        {
            "pattern": "AI model abuse and injection activity",
            "supporting_evidence": [
                "Theme counts show repeated matches for ai_model_abuse.",
                "Top actions and analyst keywords include prompt, model, poison, and injection terms.",
            ],
            "analyst_judgment": "Treat AI-facing services as active attack surface, especially for prompt injection and model extraction behaviors.",
        },
        {
            "pattern": "Credential and access control pressure",
            "supporting_evidence": [
                "Authentication actions include frequent failed, bypass, locked, challenge, and timeout outcomes.",
                "Emergency and critical findings include credential-focused IDS alert types.",
            ],
            "analyst_judgment": "This fits account takeover or brute-force style pressure even if some auth noise is synthetic or policy-driven.",
        },
        {
            "pattern": "Evasion, tunneling, and malware-style delivery",
            "supporting_evidence": [
                "Priority cases include DNS tunneling, domain fronting, fileless attack, and zero-day exploit labels.",
                "High-severity IDS alerts dominate the most urgent exemplars.",
            ],
            "analyst_judgment": "Investigation should assume command-and-control or stealthy post-compromise traffic until disproven.",
        },
    ]

    priority_findings = []
    for case in context["priority_cases"][:5]:
        evidence = [
            f"{case['timestamp']} {case['event_type']} event from {case['source']}",
            f"severity={case['severity']}, risk={case['risk_score']} ({case['risk_band']}), confidence={case['confidence']} ({case['confidence_band']})",
            f"src_ip={case['src_ip']}, z_score={case['source_z_score']} ({case['z_score_band']})",
        ]
        if case["alert_type"] != "none":
            evidence.append(f"alert_type={case['alert_type']}")
        if case["category"] != "none":
            evidence.append(f"category={case['category']}")
        if case["frequency_anomaly"] or case["sequence_anomaly"]:
            evidence.append(f"behavioral_flags=frequency:{case['frequency_anomaly']} sequence:{case['sequence_anomaly']}")

        priority_findings.append(
            {
                "finding": f"{case['classification']} in {case['event_type']} telemetry",
                "classification": case["classification"],
                "severity": case["severity"],
                "confidence_level": case["confidence_band"],
                "evidence": evidence,
                "rationale": (
                    "Risk, confidence, and severity align above investigation thresholds. "
                    "Cases with behavioral anomaly flags or exploit-oriented alert labels should be treated as immediate triage candidates."
                ),
                "recommended_action": (
                    f"{case['response_window']}. Validate the asset behind {case['src_ip']}, review adjacent events, "
                    "and confirm whether containment is already in place."
                ),
            }
        )

    false_positive_risks = [
        {
            "risk": "Low-confidence alert volume remains material",
            "evidence": f"{low_confidence_count:,} events fall in the low-confidence band.",
            "impact": "Not every suspicious event is actionable; prioritization must weight confidence alongside severity and anomaly evidence.",
        },
        {
            "risk": "The dominant anomalous source is also labeled unknown",
            "evidence": (
                f"Source {top_anomaly['src_ip']} accounts for {top_anomaly['event_count']:,} events, "
                "which may reflect missing telemetry attribution instead of a single host."
            ),
            "impact": "Investigate pipeline quality before assuming one host generated the entire anomaly cluster.",
        },
        {
            "risk": "Behavioral analytics coverage is partial",
            "evidence": (
                f"Only {metrics['behavioral_analytics']['rows_with_behavioral_data']:,} rows "
                f"({metrics['behavioral_analytics']['rows_with_behavioral_data_pct']}%) carry behavioral analytics."
            ),
            "impact": "Anomaly-driven conclusions are useful, but they do not cover the whole dataset.",
        },
    ]

    recommended_actions = {
        "immediate": [
            f"Triage source {top_anomaly['src_ip']} and determine whether the unknown attribution is a telemetry gap or a real aggregation point.",
            "Escalate the top emergency and critical cases to incident response for containment validation.",
            "Review IDS alerts mentioning DNS tunneling, domain fronting, fileless attack, credential stuffing, and zero-day exploit behavior.",
        ],
        "next_24_hours": [
            "Correlate high-risk auth, endpoint, and network events by user, host, and minute-level time window.",
            "Inspect AI-facing services for prompt injection, model access abuse, and training-data poisoning signals.",
            "Tune or suppress low-confidence patterns only after validating that they are not linked to confirmed high-severity cases.",
        ],
        "next_7_days": [
            "Add dashboards for risk, confidence, and unknown-source attribution drift.",
            "Expand behavioral analytics coverage beyond the current subset of rows.",
            "Build event-chain detections for credential abuse, exfiltration, and stealthy command-and-control patterns.",
        ],
    }

    return {
        "overall_posture": overall_posture,
        "executive_summary": summary,
        "priority_findings": priority_findings,
        "attack_patterns": attack_patterns,
        "false_positive_risks": false_positive_risks,
        "recommended_actions": recommended_actions,
        "triage_sla": SEVERITY_RESPONSE_WINDOW,
    }


def render_markdown_report(
    context: dict[str, Any],
    analysis: dict[str, Any],
    analysis_mode: str,
    llm_error: str | None,
) -> str:
    lines = [
        "# Prompt-Engineered Threat Analysis",
        "",
        f"- Generated at (UTC): {context['generated_at_utc']}",
        f"- Analysis mode: {analysis_mode}",
    ]
    if llm_error:
        lines.append(f"- LLM status: fallback used because {llm_error}")

    lines.extend(
        [
            f"- Rows analyzed: {context['dataset']['row_count']:,}",
            "",
            "## Executive Summary",
            "",
            analysis["executive_summary"],
            "",
            "## Overall Posture",
            "",
            f"- Label: {analysis['overall_posture']['label']}",
            f"- Rationale: {analysis['overall_posture']['rationale']}",
            "",
            "## Priority Findings",
            "",
        ]
    )

    for finding in analysis["priority_findings"]:
        lines.append(f"### {finding['finding']}")
        lines.append("")
        lines.append(f"- Classification: {finding['classification']}")
        lines.append(f"- Severity: {finding['severity']}")
        lines.append(f"- Confidence level: {finding['confidence_level']}")
        lines.append(f"- Rationale: {finding['rationale']}")
        lines.append(f"- Recommended action: {finding['recommended_action']}")
        lines.append("- Evidence:")
        for evidence in finding["evidence"]:
            lines.append(f"  - {evidence}")
        lines.append("")

    lines.extend(["## Attack Patterns", ""])
    for pattern in analysis["attack_patterns"]:
        lines.append(f"### {pattern['pattern']}")
        lines.append("")
        lines.append(f"- Analyst judgment: {pattern['analyst_judgment']}")
        lines.append("- Supporting evidence:")
        for evidence in pattern["supporting_evidence"]:
            lines.append(f"  - {evidence}")
        lines.append("")

    lines.extend(["## False Positive Risks", ""])
    for risk in analysis["false_positive_risks"]:
        lines.append(f"- {risk['risk']}: {risk['evidence']} Impact: {risk['impact']}")

    lines.extend(["", "## Recommended Actions", ""])
    for phase, actions in analysis["recommended_actions"].items():
        lines.append(f"### {phase.replace('_', ' ').title()}")
        lines.append("")
        for action in actions:
            lines.append(f"- {action}")
        lines.append("")

    lines.extend(["## Triage SLA", ""])
    for severity, guidance in analysis["triage_sla"].items():
        lines.append(f"- {severity}: {guidance}")

    return "\n".join(lines) + "\n"


def run_analysis(
    data_path: str | Path = "advanced_siem.csv",
    output_dir: str | Path = ".",
    use_llm: bool = True,
) -> dict[str, Any]:
    load_local_env()
    rows = load_rows(data_path)
    context = build_context(rows)
    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(context)
    analysis_mode = "heuristic_fallback"
    llm_error = None

    llm_analysis = None
    if use_llm:
        llm_analysis, llm_error = call_gemini_analysis(system_prompt, user_prompt)
        if llm_analysis:
            analysis_mode = "gemini"
        elif not llm_error:
            llm_error = "GOOGLE_API_KEY is not set."

    analysis = llm_analysis or heuristic_synthesis(context)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    context_path = output_path / "prompt_engineered_threat_context.json"
    prompt_path = output_path / "prompt_engineered_threat_prompt.txt"
    analysis_json_path = output_path / "prompt_engineered_threat_analysis.json"
    report_path = output_path / "PROMPT_ENGINEERED_THREAT_ANALYSIS.md"

    context_path.write_text(json.dumps(context, indent=2), encoding="utf-8")
    prompt_path.write_text(f"SYSTEM PROMPT\n\n{system_prompt}\n\nUSER PROMPT\n\n{user_prompt}\n", encoding="utf-8")
    analysis_json_path.write_text(
        json.dumps({"analysis_mode": analysis_mode, "llm_error": llm_error, "analysis": analysis}, indent=2),
        encoding="utf-8",
    )
    report_path.write_text(render_markdown_report(context, analysis, analysis_mode, llm_error), encoding="utf-8")

    return {
        "analysis_mode": analysis_mode,
        "llm_error": llm_error,
        "context_path": str(context_path),
        "prompt_path": str(prompt_path),
        "analysis_json_path": str(analysis_json_path),
        "report_path": str(report_path),
        "context": context,
        "analysis": analysis,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run prompt-engineered threat analysis.")
    parser.add_argument("--data-path", default="advanced_siem.csv")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument(
        "--force-heuristic",
        action="store_true",
        help="Skip Gemini and use the offline fallback only.",
    )
    args = parser.parse_args()

    result = run_analysis(
        data_path=args.data_path,
        output_dir=args.output_dir,
        use_llm=not args.force_heuristic,
    )

    print(f"analysis_mode={result['analysis_mode']}")
    if result["llm_error"]:
        print(f"llm_error={result['llm_error']}")
    print(f"report_path={result['report_path']}")
    print(f"prompt_path={result['prompt_path']}")
    print(f"context_path={result['context_path']}")


if __name__ == "__main__":
    main()
