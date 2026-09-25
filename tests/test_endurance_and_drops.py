"""Endurance and sustained high-volume packet-drop measurement test suite."""
import gc
import sys
import time
import unittest
from collections import deque

from core.delta_core import DeltaCore
from core.packet_capture import _raw_ip_to_info
from core.detection_engine import DetectionEngine


class RecordingManager:
    session = None

    def __init__(self):
        self.alerts = []
        self.traffic = []

    def log_traffic(self, packet):
        self.traffic.append(packet)
        return len(self.traffic)

    def log_alert(self, alert):
        self.alerts.append(alert)


class EnduranceAndDropTests(unittest.TestCase):
    def test_sustained_high_volume_throughput_and_drop_measurement(self):
        """Simulate high-volume packet ingestion and measure throughput and drop rates."""
        recorder = RecordingManager()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, scan_window=15.0, port_threshold=10)

        # Buffer queue modeling capture ring buffer
        ring_buffer_capacity = 1000
        ring_buffer = deque(maxlen=ring_buffer_capacity)
        packets_offered = 50000
        packets_dropped = 0
        packets_processed = 0

        start_time = time.perf_counter()

        # Generate sustained stream
        for i in range(packets_offered):
            packet = {
                "src_ip": f"10.0.{(i >> 8) % 250}.{i % 250 + 1}",
                "dst_ip": "192.168.1.100",
                "protocol": "TCP",
                "src_port": 10000 + (i % 20000),
                "dst_port": 80,
                "tcp_flags": "PA",
                "length": 1460,
                "payload": b"GET /load HTTP/1.1\r\nHost: target\r\n\r\n",
                "_monotonic": i * 0.001  # Millisecond timestamps
            }

            # Simulating ring buffer push
            if len(ring_buffer) == ring_buffer_capacity:
                # Buffer full under burst condition
                packets_dropped += 1
            else:
                ring_buffer.append(packet)

            # Processing drained from ring buffer
            if ring_buffer and (i % 2 == 0 or len(ring_buffer) > 100):
                item = ring_buffer.popleft()
                core.process_packet(item)
                packets_processed += 1

        # Drain remaining
        while ring_buffer:
            item = ring_buffer.popleft()
            core.process_packet(item)
            packets_processed += 1

        elapsed = time.perf_counter() - start_time
        pps = packets_processed / elapsed if elapsed > 0 else 0
        drop_rate = (packets_dropped / packets_offered) * 100

        print(f"\n[Throughput] Processed: {packets_processed} packets in {elapsed:.3f}s ({pps:,.0f} pkts/sec)")
        print(f"[Packet Drops] Offered: {packets_offered}, Dropped: {packets_dropped} ({drop_rate:.2f}% drop rate)")

        self.assertGreater(packets_processed, 0)
        self.assertEqual(core.packets_sniffed, packets_processed)

    def test_accelerated_multi_hour_endurance_timeline(self):
        """Simulate 1-hour, 6-hour, and 24-hour timeline endurance progression."""
        recorder = RecordingManager()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, scan_window=15.0, port_threshold=10)

        # Durations in simulated seconds: 1 hour (3,600s), 6 hours (21,600s), 24 hours (86,400s)
        test_hours = [1, 6, 24]
        for hours in test_hours:
            simulated_seconds = hours * 3600
            step = 30  # Step every 30 simulated seconds
            gc.collect()

            start_t = time.perf_counter()
            for current_t in range(0, simulated_seconds, step):
                # Send periodic background traffic
                core.process_packet({
                    "src_ip": "10.0.1.10",
                    "dst_ip": "192.168.1.5",
                    "protocol": "TCP",
                    "src_port": 45000,
                    "dst_port": 443,
                    "tcp_flags": "A",
                    "length": 100,
                    "payload": b"",
                    "_monotonic": float(current_t)
                })

            duration = time.perf_counter() - start_t
            print(f"[Endurance Simulation] {hours}-Hour Timeline ({simulated_seconds}s simulated) completed in {duration:.3f}s wall-clock")
            # Verify memory state remains bounded (sliding windows pruned)
            self.assertLessEqual(len(core._ports), 10)
            self.assertLessEqual(len(core._pings), 10)


if __name__ == "__main__":
    unittest.main()
