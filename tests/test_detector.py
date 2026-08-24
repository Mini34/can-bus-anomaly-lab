import unittest
from math import nan

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

    def test_invalid_rules_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CanRule(0.0, {})
        with self.assertRaises(ValueError):
            CanRule(10.0, {8: (0, 10)})
        with self.assertRaises(ValueError):
            CanRule(10.0, {0: (20, 10)})
        with self.assertRaises(ValueError):
            CanRule(10.0, {}, counter_modulus=0)
        with self.assertRaises(ValueError):
            CanRule(10.0, {}, counter_modulus=257)

    def test_non_finite_and_non_integer_protocol_values_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "finite"):
            CanFrame(nan, 0x100, (1,))
        with self.assertRaisesRegex(ValueError, "integer byte"):
            CanFrame(0.0, 0x100, (1.5,))
        with self.assertRaises(ValueError):
            CanFrame(0.0, 1.5, (1,))
        with self.assertRaisesRegex(ValueError, "finite"):
            CanRule(nan, {})
        with self.assertRaisesRegex(ValueError, "integer"):
            CanRule(10.0, {}, counter_modulus=16.5)
        with self.assertRaisesRegex(ValueError, "finite"):
            Detector({}, rate_tolerance=nan)

    def test_timestamp_regression_does_not_replace_last_good_timestamp(self) -> None:
        detector = Detector({0x100: CanRule(10.0, {})})
        detector.inspect(CanFrame(1.0, 0x100, ()))
        regression = detector.inspect(CanFrame(0.5, 0x100, ()))
        following = detector.inspect(CanFrame(0.56, 0x100, ()))
        self.assertIn("timestamp_regression", {event.category for event in regression})
        self.assertIn("timestamp_regression", {event.category for event in following})

    def test_timestamp_regression_does_not_corrupt_counter_state(self) -> None:
        detector = Detector({0x100: CanRule(10.0, {}, counter_index=0)})
        detector.inspect(CanFrame(1.0, 0x100, (5,)))
        regression = detector.inspect(CanFrame(0.5, 0x100, (2,)))
        following = detector.inspect(CanFrame(1.2, 0x100, (6,)))
        self.assertEqual(
            {event.category for event in regression},
            {"timestamp_regression"},
        )
        self.assertEqual(following, [])

    def test_counter_value_must_fit_configured_modulus(self) -> None:
        detector = Detector(
            {0x100: CanRule(10.0, {}, counter_index=0, counter_modulus=16)}
        )
        events = detector.inspect(CanFrame(0.0, 0x100, (31,)))
        self.assertEqual({event.category for event in events}, {"counter_range"})


if __name__ == "__main__":
    unittest.main()
