from scapy.all import IP, TCP
from ids import IntrusionDetectionSystem


def _packets(src, dst, sport, dport, flags, count):
    return [IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
            for _ in range(count)]


def test_ids():
    """
    Each attack scenario sends multiple packets within a single flow
    so that flow duration > 0 and packet_rate accumulates, satisfying
    the signature rule thresholds.

    Flow A — normal web browsing (ACK/PSH, low rate)
    Flow B — normal HTTPS (ACK/PSH)
    Flow C — SYN flood: many SYNs to one destination
    Flow D — Port scan: many small SYNs to one port
    """

    test_packets = (
        # Flow A: normal web (3 packets)
        _packets("192.168.1.1", "192.168.1.2", 1234, 80,  "A", 1) +
        _packets("192.168.1.1", "192.168.1.2", 1234, 80,  "P", 2) +
        # Flow B: normal HTTPS (2 packets)
        _packets("192.168.1.3", "192.168.1.4", 1235, 443, "A", 1) +
        _packets("192.168.1.3", "192.168.1.4", 1235, 443, "P", 1) +
        # Flow C: SYN flood (12 rapid SYNs)
        _packets("10.0.0.1", "192.168.1.2", 5678, 80, "S", 12) +
        # Flow D: Port scan (12 small SYNs)
        _packets("192.168.1.100", "192.168.1.2", 4321, 22, "S", 12)
    )

    ids = IntrusionDetectionSystem()

    print("Starting IDS Test...")
    counts = {"normal": 0, "syn_flood": 0, "port_scan": 0, "anomaly": 0}

    for i, packet in enumerate(test_packets, 1):
        print(f"\n[{i:2d}] {packet.summary()}", end="")
        features = ids.traffic_analyzer.analyze_packet(packet)
        if not features:
            print("  — skipped (no IP/TCP)")
            continue

        threats = ids.detection_engine.detect_threats(features)
        if threats:
            for t in threats:
                tag = t.get("rule") or t.get("type", "?")
                counts[tag] = counts.get(tag, 0) + 1
            print(f"  >>> {[t.get('rule') or t.get('type') for t in threats]}")
        else:
            counts["normal"] += 1
            print("  ✓ OK")

    print("\n" + "=" * 50)
    print("  SUMMARY")
    print("=" * 50)
    for k in ("normal", "syn_flood", "port_scan", "anomaly"):
        print(f"    {k:12s} : {counts.get(k, 0)}")
    print("=" * 50)
    print("Done.")


if __name__ == "__main__":
    test_ids()
