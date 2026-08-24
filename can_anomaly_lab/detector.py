"""Stateful, explainable rules for identifying anomalous CAN frames."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True)
class CanFrame:
    timestamp_s: float
    arbitration_id: int
    data: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isfinite(self.timestamp_s) or self.timestamp_s < 0:
            raise ValueError("timestamp must be finite and non-negative")
        if (
            not isinstance(self.arbitration_id, int)
            or isinstance(self.arbitration_id, bool)
            or not 0 <= self.arbitration_id <= 0x7FF
        ):
            raise ValueError("only 11-bit CAN identifiers are supported")
        if len(self.data) > 8 or any(
            not isinstance(byte, int) or isinstance(byte, bool) or not 0 <= byte <= 255
            for byte in self.data
        ):
            raise ValueError("CAN data must contain zero to eight integer byte values")


@dataclass(frozen=True)
class CanRule:
    max_rate_hz: float
    byte_ranges: dict[int, tuple[int, int]]
    counter_index: int | None = None
    counter_modulus: int = 16

    def __post_init__(self) -> None:
        if not isfinite(self.max_rate_hz) or self.max_rate_hz <= 0:
            raise ValueError("max_rate_hz must be finite and positive")
        if (
            not isinstance(self.counter_modulus, int)
            or isinstance(self.counter_modulus, bool)
            or not 1 <= self.counter_modulus <= 256
        ):
            raise ValueError("counter_modulus must be an integer between one and 256")
        if self.counter_index is not None and (
            not isinstance(self.counter_index, int)
            or isinstance(self.counter_index, bool)
            or not 0 <= self.counter_index <= 7
        ):
            raise ValueError("counter_index must identify a CAN payload byte")
        for index, (minimum, maximum) in self.byte_ranges.items():
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index <= 7
            ):
                raise ValueError("byte range indices must be between zero and seven")
            if (
                not isinstance(minimum, int)
                or not isinstance(maximum, int)
                or isinstance(minimum, bool)
                or isinstance(maximum, bool)
                or not 0 <= minimum <= maximum <= 255
            ):
                raise ValueError(
                    "byte ranges must be ordered integer values between zero and 255"
                )


@dataclass(frozen=True)
class Anomaly:
    timestamp_s: float
    arbitration_id: int
    category: str
    detail: str


class Detector:
    def __init__(self, rules: dict[int, CanRule], rate_tolerance: float = 1.25) -> None:
        if not isfinite(rate_tolerance) or rate_tolerance < 1:
            raise ValueError("rate_tolerance must be finite and at least one")
        self.rules = rules
        self.rate_tolerance = rate_tolerance
        self._last_seen: dict[int, float] = {}
        self._last_counter: dict[int, int] = {}

    def inspect(self, frame: CanFrame) -> list[Anomaly]:
        rule = self.rules.get(frame.arbitration_id)
        if rule is None:
            return [self._event(frame, "unknown_id", "identifier is not in the allowlist")]

        anomalies: list[Anomaly] = []
        timestamp_regressed = False
        previous_time = self._last_seen.get(frame.arbitration_id)
        if previous_time is not None:
            interval = frame.timestamp_s - previous_time
            minimum_interval = 1.0 / (rule.max_rate_hz * self.rate_tolerance)
            if interval < 0:
                timestamp_regressed = True
                anomalies.append(
                    self._event(frame, "timestamp_regression", "timestamp moved backwards")
                )
            elif interval < minimum_interval:
                anomalies.append(
                    self._event(
                        frame,
                        "rate_spike",
                        f"interval {interval:.6f}s is below {minimum_interval:.6f}s",
                    )
                )
        if previous_time is None or frame.timestamp_s >= previous_time:
            self._last_seen[frame.arbitration_id] = frame.timestamp_s

        for index, (minimum, maximum) in rule.byte_ranges.items():
            if index >= len(frame.data):
                anomalies.append(self._event(frame, "short_payload", f"byte {index} is missing"))
            elif not minimum <= frame.data[index] <= maximum:
                anomalies.append(
                    self._event(
                        frame,
                        "payload_range",
                        f"byte {index} value {frame.data[index]} is outside [{minimum}, {maximum}]",
                    )
                )

        if rule.counter_index is not None:
            if rule.counter_index >= len(frame.data):
                anomalies.append(
                    self._event(
                        frame,
                        "short_payload",
                        f"counter byte {rule.counter_index} is missing",
                    )
                )
            else:
                raw_counter = frame.data[rule.counter_index]
                if raw_counter >= rule.counter_modulus:
                    anomalies.append(
                        self._event(
                            frame,
                            "counter_range",
                            (
                                f"counter value {raw_counter} is outside "
                                f"[0, {rule.counter_modulus - 1}]"
                            ),
                        )
                    )
                    return anomalies
                present = raw_counter
                previous = self._last_counter.get(frame.arbitration_id)
                if (
                    not timestamp_regressed
                    and previous is not None
                    and present != (previous + 1) % rule.counter_modulus
                ):
                    anomalies.append(
                        self._event(
                            frame,
                            "counter_jump",
                            f"counter moved from {previous} to {present}",
                        )
                    )
                if not timestamp_regressed:
                    self._last_counter[frame.arbitration_id] = present
        return anomalies

    @staticmethod
    def _event(frame: CanFrame, category: str, detail: str) -> Anomaly:
        return Anomaly(frame.timestamp_s, frame.arbitration_id, category, detail)
