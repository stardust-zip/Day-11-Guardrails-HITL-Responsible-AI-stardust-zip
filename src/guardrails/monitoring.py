"""
Assignment - Monitoring & Alerts Component
Tracks security metrics and fires alerts when thresholds are exceeded.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable


@dataclass
class Alert:
    """Alert generated when threshold is exceeded."""

    timestamp: str
    alert_type: str
    message: str
    metric_name: str
    current_value: float
    threshold: float
    severity: str


@dataclass
class MetricsSnapshot:
    """Snapshot of current metrics."""

    timestamp: str
    rate_limit_hits: int
    input_guardrail_blocks: int
    output_guardrail_blocks: int
    judge_failures: int
    total_requests: int
    blocked_requests: int
    block_rate: float


class MonitoringService:
    """Tracks security metrics and generates alerts.

    Monitors block rates, rate-limit hits, judge fail rates,
    and fires alerts when thresholds are exceeded.

    Usage:
        monitor = MonitoringService()
        monitor.increment("rate_limit_hits")
        if monitor.check_thresholds():
            print("ALERT: Block rate too high!")
        monitor.print_status()
    """

    def __init__(
        self,
        block_rate_threshold: float = 0.5,
        rate_limit_threshold: int = 10,
        judge_failure_threshold: int = 5,
    ):
        self.block_rate_threshold = block_rate_threshold
        self.rate_limit_threshold = rate_limit_threshold
        self.judge_failure_threshold = judge_failure_threshold

        self.metrics = defaultdict(int)
        self.alert_history: deque = deque(maxlen=100)
        self.start_time = time.time()

        self.alert_callbacks: list[Callable[[Alert], None]] = []

    def increment(self, metric_name: str, count: int = 1) -> None:
        """Increment a metric counter."""
        self.metrics[metric_name] += count

    def increment_rate_limit_hits(self) -> None:
        self.increment("rate_limit_hits")

    def increment_input_blocks(self) -> None:
        self.increment("input_guardrail_blocks")

    def increment_output_blocks(self) -> None:
        self.increment("output_guardrail_blocks")

    def increment_judge_failures(self) -> None:
        self.increment("judge_failures")

    def increment_total_requests(self) -> None:
        self.increment("total_requests")

    def increment_blocked_requests(self) -> None:
        self.increment("blocked_requests")

    def get_block_rate(self) -> float:
        """Calculate current block rate."""
        total = self.metrics.get("total_requests", 0)
        if total == 0:
            return 0.0
        blocked = self.metrics.get("blocked_requests", 0)
        return blocked / total

    def check_thresholds(self) -> list[Alert]:
        """Check if any metrics exceed thresholds and generate alerts.

        Returns:
            List of new alerts generated
        """
        alerts = []

        block_rate = self.get_block_rate()
        if block_rate > self.block_rate_threshold:
            alert = Alert(
                timestamp=datetime.now().isoformat(),
                alert_type="high_block_rate",
                message=f"Block rate {block_rate:.1%} exceeds threshold {self.block_rate_threshold:.1%}",
                metric_name="block_rate",
                current_value=block_rate,
                threshold=self.block_rate_threshold,
                severity="warning" if block_rate < 0.8 else "critical",
            )
            alerts.append(alert)
            self.alert_history.append(alert)

        rate_limit_hits = self.metrics.get("rate_limit_hits", 0)
        if rate_limit_hits > self.rate_limit_threshold:
            alert = Alert(
                timestamp=datetime.now().isoformat(),
                alert_type="rate_limit_abuse",
                message=f"Rate limit hits {rate_limit_hits} exceeds threshold {self.rate_limit_threshold}",
                metric_name="rate_limit_hits",
                current_value=rate_limit_hits,
                threshold=self.rate_limit_threshold,
                severity="warning",
            )
            alerts.append(alert)
            self.alert_history.append(alert)

        judge_failures = self.metrics.get("judge_failures", 0)
        if judge_failures > self.judge_failure_threshold:
            alert = Alert(
                timestamp=datetime.now().isoformat(),
                alert_type="judge_safety_concerns",
                message=f"Judge safety failures {judge_failures} exceeds threshold {self.judge_failure_threshold}",
                metric_name="judge_failures",
                current_value=judge_failures,
                threshold=self.judge_failure_threshold,
                severity="warning",
            )
            alerts.append(alert)
            self.alert_history.append(alert)

        for alert in alerts:
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    print(f"Alert callback error: {e}")

        return alerts

    def register_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register a callback to be called when alerts fire."""
        self.alert_callbacks.append(callback)

    def get_snapshot(self) -> MetricsSnapshot:
        """Get current metrics snapshot."""
        total = self.metrics.get("total_requests", 0)
        blocked = self.metrics.get("blocked_requests", 0)

        return MetricsSnapshot(
            timestamp=datetime.now().isoformat(),
            rate_limit_hits=self.metrics.get("rate_limit_hits", 0),
            input_guardrail_blocks=self.metrics.get("input_guardrail_blocks", 0),
            output_guardrail_blocks=self.metrics.get("output_guardrail_blocks", 0),
            judge_failures=self.metrics.get("judge_failures", 0),
            total_requests=total,
            blocked_requests=blocked,
            block_rate=self.get_block_rate(),
        )

    def print_status(self) -> None:
        """Print current monitoring status."""
        snapshot = self.get_snapshot()

        print("\n" + "=" * 60)
        print("MONITORING STATUS")
        print("=" * 60)
        print(f"Runtime: {int(time.time() - self.start_time)}s")
        print(f"Total Requests: {snapshot.total_requests}")
        print(f"Blocked Requests: {snapshot.blocked_requests}")
        print(f"Block Rate: {snapshot.block_rate:.1%}")
        print("-" * 60)
        print(f"Rate Limit Hits: {snapshot.rate_limit_hits}")
        print(f"Input Guardrail Blocks: {snapshot.input_guardrail_blocks}")
        print(f"Output Guardrail Blocks: {snapshot.output_guardrail_blocks}")
        print(f"Judge Failures: {snapshot.judge_failures}")

        if self.alert_history:
            print("-" * 60)
            print(f"Recent Alerts ({len(self.alert_history)}):")
            for alert in list(self.alert_history)[-5:]:
                print(f"  [{alert.severity.upper()}] {alert.message}")

        print("=" * 60)

    def reset(self) -> None:
        """Reset all metrics and alerts."""
        self.metrics.clear()
        self.alert_history.clear()
        self.start_time = time.time()

    def get_all_metrics(self) -> dict:
        """Get all metrics as a dictionary."""
        return dict(self.metrics)


def print_alert(alert: Alert) -> None:
    """Example alert callback that prints alerts."""
    print(f"\n🚨 ALERT [{alert.severity.upper()}]: {alert.message}")


def test_monitoring():
    """Test MonitoringService with sample scenarios."""
    monitor = MonitoringService(
        block_rate_threshold=0.3,
        rate_limit_threshold=5,
        judge_failure_threshold=3,
    )
    monitor.register_alert_callback(print_alert)

    print("Testing MonitoringService:")
    print("=" * 50)

    for i in range(20):
        monitor.increment_total_requests()

        if i < 5:
            monitor.increment_rate_limit_hits()
            monitor.increment_blocked_requests()
        elif i < 10:
            monitor.increment_input_blocks()
            monitor.increment_blocked_requests()
        elif i < 12:
            monitor.increment_judge_failures()

        if i % 5 == 4:
            print(f"\n--- After {i + 1} requests ---")
            alerts = monitor.check_thresholds()

    monitor.print_status()


if __name__ == "__main__":
    test_monitoring()
