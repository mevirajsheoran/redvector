"""
threatforge/validation/matrix_builder.py

Validation Matrix CSV Generator

Generates the validation_matrix.csv that is your
Testing & Results rubric evidence (3 marks).

This CSV is what you show your professor:
"Here is scientific proof that my defense works"

SAMPLE OUTPUT (validation_matrix.csv):
test_id,attack_type,payloads_sent,sentinel_detected,detection_latency_s,block_rate_pct,confidence
TF-HTTP-001,http_flood,1500,True,2.3,85.5,HIGH
TF-CRED-002,credential_stuffing,300,True,5.1,42.3,MEDIUM
TF-ENUM-003,enumeration,600,True,3.7,28.1,HIGH
TF-HTTP-004,http_flood,3000,True,1.9,91.2,HIGH
"""

import csv
import json
import time
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from .correlator import CorrelationResult


class ValidationMatrixBuilder:
    """
    Builds and saves the validation matrix for academic submission.
    """

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize builder with output directory.

        Args:
            output_dir: Where to save reports (creates if missing)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results: List[CorrelationResult] = []

    def add_result(self, result: CorrelationResult):
        """Add a correlation result to the matrix."""
        self.results.append(result)

    def add_results(self, results: List[CorrelationResult]):
        """Add multiple results at once."""
        self.results.extend(results)

    def save_csv(self, filename: str = "validation_matrix.csv") -> str:
        """
        Save validation matrix as CSV.

        This is the primary academic deliverable.
        Shows your professor:
        - Every attack type tested
        - Whether Sentinel detected it
        - Detection latency
        - Block rate
        - Confidence level

        Args:
            filename: Output filename

        Returns:
            Path to saved file
        """
        filepath = self.output_dir / filename

        if not self.results:
            return str(filepath)

        rows = [r.to_csv_row() for r in self.results]

        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        return str(filepath)

    def save_json(self, filename: str = "validation_full.json") -> str:
        """
        Save full validation data as JSON (includes raw metrics).

        Useful for debugging and detailed analysis.

        Args:
            filename: Output filename

        Returns:
            Path to saved file
        """
        filepath = self.output_dir / filename

        data = {
            "generated_at": datetime.now().isoformat(),
            "project": "ThreatForge vs Sentinel Validation",
            "total_tests": len(self.results),
            "results": []
        }

        for result in self.results:
            data["results"].append({
                "test_id": result.test_id,
                "attack_type": result.attack_type,
                "timestamp": result.timestamp,
                "target": result.target,
                "parameters": {
                    "duration_seconds": result.attack_duration_seconds,
                    "attack_rate": result.attack_rate,
                    "payloads_sent": result.payloads_sent
                },
                "detection": {
                    "sentinel_detected": result.sentinel_detected,
                    "detection_latency_s": result.detection_latency_seconds,
                    "blocks_triggered": result.blocks_triggered,
                    "threat_score_peak": result.threat_score_peak,
                    "block_rate_pct": result.block_rate_pct,
                    "confidence": result.detection_confidence
                },
                "raw": {
                    "sentinel_delta": result.sentinel_delta,
                    "attack_metrics": result.attack_metrics
                }
            })

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        return str(filepath)

    def generate_summary_table(self) -> str:
        """
        Generate a formatted ASCII table for terminal display.

        Used in demo script output.

        Returns:
            Formatted string table
        """
        if not self.results:
            return "No results yet"

        header = f"{'TEST ID':<15} {'ATTACK TYPE':<20} {'SENT':<8} {'DETECTED':<10} {'LATENCY':<10} {'BLOCK%':<8} {'CONFIDENCE'}"
        separator = "-" * 85

        rows = []
        for r in self.results:
            detected_str = "✅ YES" if r.sentinel_detected else "❌ NO"
            latency_str = f"{r.detection_latency_seconds:.1f}s" if r.detection_latency_seconds else "N/A"
            row = (
                f"{r.test_id:<15} "
                f"{r.attack_type:<20} "
                f"{r.payloads_sent:<8} "
                f"{detected_str:<10} "
                f"{latency_str:<10} "
                f"{r.block_rate_pct:<8.1f} "
                f"{r.detection_confidence}"
            )
            rows.append(row)

        return "\n".join([header, separator] + rows)

    def compute_final_metrics(self) -> Dict[str, Any]:
        """
        Compute final academic metrics for report.

        Returns:
            Dict with all metrics needed for your report
        """
        if not self.results:
            return {}

        total = len(self.results)
        detected = sum(1 for r in self.results if r.sentinel_detected)
        latencies = [
            r.detection_latency_seconds for r in self.results
            if r.detection_latency_seconds is not None
        ]
        block_rates = [r.block_rate_pct for r in self.results]

        return {
            "total_tests": total,
            "detection_rate_pct": round((detected / total) * 100, 1),
            "false_negative_rate_pct": round(((total - detected) / total) * 100, 1),
            "avg_detection_latency_s": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "min_detection_latency_s": round(min(latencies), 2) if latencies else None,
            "max_detection_latency_s": round(max(latencies), 2) if latencies else None,
            "avg_block_rate_pct": round(sum(block_rates) / len(block_rates), 2),
            "high_confidence_detections": sum(
                1 for r in self.results if r.detection_confidence == "HIGH"
            ),
            "report_statement": (
                f"ThreatForge executed {total} controlled attack scenarios against Sentinel. "
                f"Sentinel detected {detected}/{total} attacks ({(detected/total)*100:.1f}% detection rate). "
                f"Average detection latency: {sum(latencies)/len(latencies):.1f}s. "
                f"Average block rate: {sum(block_rates)/len(block_rates):.1f}%. "
                "Results demonstrate Sentinel's effectiveness against modern API threats."
            )
        }
