# CAN Bus Anomaly Lab

[![Tests](https://github.com/Mini34/can-bus-anomaly-lab/actions/workflows/test.yml/badge.svg)](https://github.com/Mini34/can-bus-anomaly-lab/actions/workflows/test.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)

A defensive computer-engineering and cybersecurity lab for explaining how embedded
network behaviour can be monitored with transparent, deterministic rules.

## Detection signals

- Unknown 11-bit arbitration identifiers
- Message rates above an allowlisted maximum
- Payload bytes outside engineering ranges
- Missing payload fields
- Rolling-counter jumps
- Counter values outside the configured modulus
- Timestamp regression
- Non-finite timing/rate values and non-integer protocol bytes

## Run it

```powershell
python -m pip install .
can-anomaly-lab
can-anomaly-lab --normal-only
can-anomaly-lab --report reports/demo.json

# The module form works without installation from the repository root.
python -m can_anomaly_lab.cli
python -m can_anomaly_lab.cli --normal-only
python -m can_anomaly_lab.cli --report reports/demo.json
python -m unittest discover -s tests -v
```

The deterministic demonstration processes 28 frames and reports five explainable
findings: one unknown identifier, one payload-range violation, one rate spike, and two
rolling-counter jumps. `--normal-only` processes the 24-frame benign baseline without
findings.

## Architecture

```mermaid
flowchart LR
    Traffic[CAN frames] --> Parser[Frame validation]
    Parser --> Allowlist[Identifier rules]
    Allowlist --> Rate[Rate checks]
    Rate --> Payload[Range and length checks]
    Payload --> Counter[Rolling-counter checks]
    Counter --> Report[Explainable anomaly report]
```

## Security design

The detector is intentionally explainable: each finding names the violated rule and
the observed value. It does not modify traffic, transmit frames, or provide exploit
functionality. Synthetic attack-like frames are included only to test defensive
detection.

## Limitations and next step

This simulation does not connect to a vehicle or physical CAN adapter. Static rules can
miss slow or context-dependent attacks and may require model-specific calibration. A
hardware extension would use an isolated development bus, a USB-CAN adapter, recorded
benign traffic, and strict safety boundaries—never a live safety-critical system.
