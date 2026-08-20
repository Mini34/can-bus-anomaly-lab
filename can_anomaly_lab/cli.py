"""Run the defensive CAN anomaly demonstration."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .detector import Detector
from .scenarios import DEFAULT_RULES, demo_frames


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect deterministic CAN traffic")
    parser.add_argument("--normal-only", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    detector = Detector(DEFAULT_RULES)
    anomalies = [
        anomaly
        for frame in demo_frames(include_attacks=not args.normal_only)
        for anomaly in detector.inspect(frame)
    ]
    payload = {
        "frames": len(demo_frames(include_attacks=not args.normal_only)),
        "anomalies": [asdict(anomaly) for anomaly in anomalies],
        "counts": dict(Counter(anomaly.category for anomaly in anomalies)),
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

