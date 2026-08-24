"""
Module 6 — C2 Beaconing & Periodic Jitter Detection
Single-pass per-flow inter-arrival time extraction and statistical jitter analysis
(Coefficient of Variation on delta intervals) to identify beaconing pattern indicators.
"""

import math
import statistics
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

def analyze_traffic_beaconing(
    packets_timeline: List[Dict[str, Any]],
    min_packets: int = 4,
    cv_threshold: float = 0.25
) -> List[Dict[str, Any]]:
    """
    Groups packets by flow tuple (src_ip, dst_ip, dst_port, proto),
    computes inter-arrival deltas, mean interval, standard deviation, and CV.
    Returns detected beaconing pattern indicators.
    """
    if not packets_timeline or len(packets_timeline) < min_packets:
        return []

    # Single-pass flow grouping: flow_key -> list of float timestamps
    flow_timestamps: Dict[str, List[float]] = {}
    flow_meta: Dict[str, Dict[str, Any]] = {}

    for pkt in packets_timeline:
        src = pkt.get("src_ip", "0.0.0.0")
        dst = pkt.get("dst_ip", "0.0.0.0")
        port = pkt.get("dst_port", 0)
        proto = pkt.get("protocol", "TCP")
        ts_val = pkt.get("timestamp")

        if ts_val is None:
            continue

        # Convert timestamp to float epoch seconds
        if isinstance(ts_val, (int, float)):
            epoch_sec = float(ts_val)
        else:
            try:
                # ISO string or date
                dt = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                epoch_sec = dt.timestamp()
            except Exception:
                continue

        flow_key = f"{src}->{dst}:{port}:{proto}"
        if flow_key not in flow_timestamps:
            flow_timestamps[flow_key] = []
            flow_meta[flow_key] = {
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "protocol": proto
            }
        flow_timestamps[flow_key].append(epoch_sec)

    indicators: List[Dict[str, Any]] = []

    # Vectorized statistical computation per flow
    for flow_key, times in flow_timestamps.items():
        if len(times) < min_packets:
            continue

        sorted_times = sorted(times)
        # Calculate inter-arrival deltas
        deltas = [
            round(sorted_times[i] - sorted_times[i - 1], 4)
            for i in range(1, len(sorted_times))
        ]

        # Filter out zero or negative deltas from burst duplicates
        valid_deltas = [d for d in deltas if d > 0.05]
        if len(valid_deltas) < 3:
            continue

        mean_interval = statistics.mean(valid_deltas)
        std_dev = statistics.stdev(valid_deltas) if len(valid_deltas) > 1 else 0.0
        
        # Coefficient of Variation (CV) = std_dev / mean
        cv = (std_dev / mean_interval) if mean_interval > 0 else 1.0

        # Heuristic scoring: low CV (< 0.25) represents strong rhythmic periodicity
        if cv <= cv_threshold:
            jitter_percent = round(cv * 100, 1)
            confidence = "High" if cv < 0.12 else "Medium"
            
            meta = flow_meta[flow_key]
            indicators.append({
                "flow": flow_key,
                "src_ip": meta["src_ip"],
                "dst_ip": meta["dst_ip"],
                "dst_port": meta["dst_port"],
                "protocol": meta["protocol"],
                "packet_count": len(sorted_times),
                "mean_interval_seconds": round(mean_interval, 2),
                "std_deviation": round(std_dev, 3),
                "coefficient_of_variation": round(cv, 4),
                "jitter_percentage": f"{jitter_percent}%",
                "periodicity_confidence": confidence,
                "finding_label": "Beaconing-Pattern Indicator (Requires Analyst Verification)",
                "explanation": (
                    f"Flow exhibited highly rhythmic periodic packet departures every ~{round(mean_interval, 1)}s "
                    f"with {jitter_percent}% interval variance. This pattern is characteristic of automated bot check-ins "
                    f"or C2 reverse beaconing, though legitimate heartbeat polling should be ruled out."
                ),
                "sample_intervals": valid_deltas[:10]
            })

    return sorted(indicators, key=lambda x: x["coefficient_of_variation"])
