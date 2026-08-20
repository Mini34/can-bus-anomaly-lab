import unittest

from can_anomaly_lab.detector import CanFrame, CanRule, Detector
from can_anomaly_lab.scenarios import DEFAULT_RULES, demo_frames


class CanDetectorTests(unittest.TestCase):
    def test_normal_traffic_has_no_anomalies(self) -> None:
        detector = Detector(DEFAULT_RULES)
        anomalies = [event for frame in demo_frames(False) for event in detector.inspect(frame)]
        self.assertEqual(anomalies, [])

    def test_unknown_identifier(self) -> None:
        detector = Detector(DEFAULT_RULES)
        events = detector.inspect(CanFrame(0.0, 0x777, (1,)))
        self.assertEqual(events[0].category, "unknown_id")

    def test_payload_range_violation(self) -> None:
        detector = Detector({0x100: CanRule(10.0, {0: (0, 10)})})
        events = detector.inspect(CanFrame(0.0, 0x100, (20,)))
        self.assertEqual(events[0].category, "payload_range")

    def test_rate_spike(self) -> None:
        detector = Detector({0x100: CanRule(10.0, {})})
        detector.inspect(CanFrame(0.0, 0x100, ()))
        events = detector.inspect(CanFrame(0.01, 0x100, ()))
        self.assertIn("rate_spike", {event.category for event in events})

    def test_counter_jump(self) -> None:
        detector = Detector({0x100: CanRule(10.0, {}, counter_index=0)})
        detector.inspect(CanFrame(0.0, 0x100, (1,)))
        events = detector.inspect(CanFrame(0.2, 0x100, (7,)))
        self.assertIn("counter_jump", {event.category for event in events})


if __name__ == "__main__":
    unittest.main()

