"""Deterministic normal and attack-like traffic for the defensive lab."""

from __future__ import annotations

from .detector import CanFrame, CanRule

DEFAULT_RULES = {
    0x100: CanRule(max_rate_hz=20.0, byte_ranges={0: (0, 200)}, counter_index=1),
    0x220: CanRule(max_rate_hz=10.0, byte_ranges={0: (0, 120), 1: (0, 120)}, counter_index=2),
}


def demo_frames(include_attacks: bool = True) -> list[CanFrame]:
    frames: list[CanFrame] = []
    for index in range(12):
        timestamp = index * 0.10
        frames.append(CanFrame(timestamp, 0x100, (80 + index, index % 16)))
        frames.append(CanFrame(timestamp + 0.02, 0x220, (40, 45, index % 16)))
    if include_attacks:
        frames.extend(
            [
                CanFrame(1.25, 0x666, (1, 2, 3)),
                CanFrame(1.30, 0x100, (250, 13)),
                CanFrame(1.301, 0x100, (90, 14)),
                CanFrame(1.50, 0x220, (40, 45, 1)),
            ]
        )
    return sorted(frames, key=lambda frame: frame.timestamp_s)

