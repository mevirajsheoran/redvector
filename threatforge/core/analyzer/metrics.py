"""
threatforge/core/analyzer/metrics.py

Security Metrics Computation Engine

This module computes measurable results for every attack module.
Without this, your Testing & Results rubric section (3 marks) is empty.

METRICS PRODUCED:
1. Crypto attacks: success rate, time taken, key found
2. Recon: precision/recall vs nmap ground truth
3. DoS: packets per second, success rate, drop rate
4. Overall: validation matrix for academic report
"""

import time
import json
import csv
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime


class CryptoMetrics:
    """Tracks metrics for cryptanalysis attacks"""

    def __init__(self):
        self.results: List[Dict] = []

    def record_attack(
        self,
        cipher: str,
        attack_method: str,
        success: bool,
        time_taken_ms: float,
        ciphertext_length: int,
        key_found: Optional[str] = None,
        confidence: str = "UNKNOWN"
    ) -> Dict[str, Any]:
        """
        Record a single crypto attack result.

        Args:
            cipher: Name of cipher attacked (caesar, vigenere, etc.)
            attack_method: Method used (brute_force, frequency, kasiski)
            success: Whether correct plaintext was recovered
            time_taken_ms: Time in milliseconds
            ciphertext_length: Length of ciphertext attacked
            key_found: The key that was recovered (if any)
            confidence: Confidence level (HIGH, MEDIUM, LOW)

        Returns:
            Recorded result dictionary
        """
        record = {
            "timestamp": datetime.now().isoformat(),
            "cipher": cipher,
            "attack_method": attack_method,
            "success": success,
            "time_taken_ms": time_taken_ms,
            "ciphertext_length": ciphertext_length,
            "key_found": key_found,
            "confidence": confidence
        }
        self.results.append(record)
        return record

    def compute_success_rate(self, cipher: Optional[str] = None) -> float:
        """
        Compute success rate across all recorded attacks.

        Args:
            cipher: If specified, only compute for this cipher type

        Returns:
            Success rate as percentage (0-100)
        """
        relevant = self.results
        if cipher:
            relevant = [r for r in self.results if r["cipher"] == cipher]

        if not relevant:
            return 0.0

        successes = sum(1 for r in relevant if r["success"])
        return round((successes / len(relevant)) * 100, 2)

    def average_time(self, cipher: Optional[str] = None) -> float:
        """Average time taken for attacks in ms"""
        relevant = self.results
        if cipher:
            relevant = [r for r in self.results if r["cipher"] == cipher]

        if not relevant:
            return 0.0

        return round(sum(r["time_taken_ms"] for r in relevant) / len(relevant), 3)

    def summary_table(self) -> List[Dict]:
        """
        Generate summary table for academic report.

        Returns data like:
        | Cipher  | Method        | Success Rate | Avg Time | Samples |
        | Caesar  | Brute Force   | 100%         | 0.2ms    | 10      |
        | Vigenere| Kasiski       | 85%          | 45ms     | 10      |
        """
        ciphers = set(r["cipher"] for r in self.results)
        summary = []

        for cipher in ciphers:
            cipher_results = [r for r in self.results if r["cipher"] == cipher]
            methods = set(r["attack_method"] for r in cipher_results)

            for method in methods:
                method_results = [r for r in cipher_results if r["attack_method"] == method]
                successes = sum(1 for r in method_results if r["success"])

                summary.append({
                    "cipher": cipher,
                    "method": method,
                    "total_attempts": len(method_results),
                    "successful": successes,
                    "success_rate_pct": round((successes / len(method_results)) * 100, 1),
                    "avg_time_ms": round(sum(r["time_taken_ms"] for r in method_results) / len(method_results), 3),
                    "min_time_ms": min(r["time_taken_ms"] for r in method_results),
                    "max_time_ms": max(r["time_taken_ms"] for r in method_results)
                })

        return summary


class ScanMetrics:
    """Tracks metrics for network reconnaissance"""

    @staticmethod
    def compare_with_nmap(
        threatforge_ports: List[int],
        nmap_ports: List[int]
    ) -> Dict[str, Any]:
        """
        Compare ThreatForge scanner results with nmap ground truth.

        PRECISION: Of ports we said are open, what fraction actually are?
        RECALL: Of ports actually open, what fraction did we find?
        F1: Harmonic mean of precision and recall

        Args:
            threatforge_ports: Ports found by our scanner
            nmap_ports: Ports found by nmap (ground truth)

        Returns:
            Precision, recall, F1, and detailed breakdown
        """
        tf_set = set(threatforge_ports)
        nmap_set = set(nmap_ports)

        true_positives = tf_set & nmap_set          # Found by both
        false_positives = tf_set - nmap_set          # We found, nmap didn't
        false_negatives = nmap_set - tf_set          # nmap found, we didn't
        true_negatives = set()                        # Not applicable for port scanning

        tp = len(true_positives)
        fp = len(false_positives)
        fn = len(false_negatives)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "threatforge_ports": sorted(threatforge_ports),
            "nmap_ports": sorted(nmap_ports),
            "true_positives": sorted(true_positives),
            "false_positives": sorted(false_positives),
            "false_negatives": sorted(false_negatives),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy_summary": f"Precision: {precision:.1%}, Recall: {recall:.1%}, F1: {f1:.1%}"
        }


class DoSMetrics:
    """Tracks metrics for DoS/DDoS simulation"""

    @staticmethod
    def compute_attack_metrics(
        start_time: float,
        end_time: float,
        packets_sent: int,
        successful_responses: int,
        target_rps: int
    ) -> Dict[str, Any]:
        """
        Compute comprehensive DoS attack metrics.

        Args:
            start_time: Unix timestamp when attack started
            end_time: Unix timestamp when attack ended
            packets_sent: Total packets/requests sent
            successful_responses: Responses received (2xx, 4xx, etc.)
            target_rps: Requested rate (requests per second)

        Returns:
            Metrics dictionary with all computed values
        """
        duration = end_time - start_time
        actual_rps = packets_sent / duration if duration > 0 else 0
        success_rate = successful_responses / packets_sent if packets_sent > 0 else 0
        drop_rate = 1 - success_rate
        rate_achievement = actual_rps / target_rps if target_rps > 0 else 0

        return {
            "duration_seconds": round(duration, 2),
            "packets_sent": packets_sent,
            "successful_responses": successful_responses,
            "failed_requests": packets_sent - successful_responses,
            "actual_rps": round(actual_rps, 2),
            "target_rps": target_rps,
            "rate_achievement_pct": round(rate_achievement * 100, 1),
            "success_rate_pct": round(success_rate * 100, 2),
            "drop_rate_pct": round(drop_rate * 100, 2)
        }


class ReportGenerator:
    """Generates academic-quality reports from attack metrics"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def save_validation_matrix(
        self,
        data: List[Dict],
        filename: str = "validation_matrix.csv"
    ) -> str:
        """
        Save validation matrix as CSV for academic report.

        This CSV is your Testing & Results rubric evidence.
        """
        filepath = self.output_dir / filename

        if not data:
            return str(filepath)

        with open(filepath, 'w', newline='') as csvfile:
            fieldnames = data[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

        return str(filepath)

    def generate_summary_report(
        self,
        crypto_metrics: CryptoMetrics,
        scan_metrics: Optional[Dict] = None,
        dos_metrics: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Generate complete summary report combining all module metrics.

        This is what you present to your professor.
        """
        report = {
            "generated_at": datetime.now().isoformat(),
            "project": "ThreatForge - Offensive Security Testing Framework",
            "modules_tested": [],
            "results": {}
        }

        # Crypto results
        if crypto_metrics.results:
            report["modules_tested"].append("cryptanalysis")
            report["results"]["cryptanalysis"] = {
                "summary_table": crypto_metrics.summary_table(),
                "overall_success_rate": crypto_metrics.compute_success_rate(),
                "total_attacks": len(crypto_metrics.results)
            }

        # Scan results
        if scan_metrics:
            report["modules_tested"].append("reconnaissance")
            report["results"]["reconnaissance"] = scan_metrics

        # DoS results
        if dos_metrics:
            report["modules_tested"].append("dos_simulation")
            report["results"]["dos_simulation"] = dos_metrics

        return report
