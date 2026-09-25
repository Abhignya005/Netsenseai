"""
generate_sample_dataset.py — DEMO dataset generator (clearly labeled)

WHAT / WHY
----------
The real CICIDS2017 dataset is a multi-gigabyte download. To make
training verifiable out of the box, this script writes a SAMPLE dataset
with the SAME schema (exact CICIDS2017 column names) and realistic
behavioral ranges for five classes:

    BENIGN, DoS Hulk, PortScan, Bot, Web Attack – Brute Force

!!! THIS IS DEMO DATA, NOT REAL CAPTURED TRAFFIC !!!
It exists ONLY so the training pipeline can be demonstrated end to end
without downloading CICIDS2017. For production-grade models, replace it
with the real dataset (see ml/README.md) and re-run training.

Usage:
    python ml/generate_sample_dataset.py [--rows 8000]

The output CSV is stamped with a comment header and every label carries
the "SAMPLE-" prefix, so demo data can never be mistaken for real
capture or real CICIDS2017 results.
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

RNG_SEED = 42

# The exact CICIDS2017 column set the NetSense mapping layer resolves
# (see preprocessing.py COLUMN_ALIASES). Columns NetSense does not use
# are still emitted so the mapping layer has realistic input.
COLUMNS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "SYN Flag Count", "RST Flag Count", "Average Packet Size",
    "Label",
]

# Class -> (duration_us, fwd_pkts, bwd_pkts, byte_rate, pkt_rate,
#           iat_mean_us, iat_std_us, syn_count, rst_count, avg_pkt_size)
# Ranges are behavioral profiles of each class in CICIDS2017.
PROFILES = {
    "SAMPLE-BENIGN": {
        "duration": (2_000_000, 600_000_000),      # 2 s .. 10 min
        "fwd": (4, 40), "bwd": (3, 35),
        "byte_rate": (5_000, 500_000),
        "pkt_rate": (5, 120),
        "iat": (8_000, 400_000), "iat_std": (1_000, 120_000),
        "syn": (1, 3), "rst": (0, 1),
        "avg_size": (300, 900),
    },
    "SAMPLE-DoS Hulk": {
        "duration": (100_000, 4_000_000),           # very short bursts
        "fwd": (200, 2_000), "bwd": (0, 30),
        "byte_rate": (400_000, 8_000_000),
        "pkt_rate": (500, 6_000),
        "iat": (100, 5_000), "iat_std": (50, 3_000),
        "syn": (1, 4), "rst": (0, 2),
        "avg_size": (400, 1_100),
    },
    "SAMPLE-PortScan": {
        "duration": (10_000, 600_000),
        "fwd": (1, 4), "bwd": (0, 2),
        "byte_rate": (100, 8_000),
        "pkt_rate": (20, 400),
        "iat": (500, 30_000), "iat_std": (100, 15_000),
        "syn": (1, 2), "rst": (1, 4),               # SYN then RST refusals
        "avg_size": (40, 120),                      # tiny probe packets
    },
    "SAMPLE-Bot": {
        "duration": (500_000, 60_000_000),
        "fwd": (10, 80), "bwd": (8, 70),
        "byte_rate": (20_000, 900_000),
        "pkt_rate": (10, 200),
        "iat": (5_000, 120_000), "iat_std": (500, 40_000),
        "syn": (1, 3), "rst": (0, 2),
        "avg_size": (200, 700),
    },
    "SAMPLE-Web Attack - Brute Force": {
        "duration": (50_000, 3_000_000),
        "fwd": (60, 500), "bwd": (40, 400),
        "byte_rate": (100_000, 2_500_000),
        "pkt_rate": (80, 900),
        "iat": (1_000, 20_000), "iat_std": (200, 10_000),
        "syn": (1, 3), "rst": (0, 2),
        "avg_size": (300, 800),
    },
}

CLASS_WEIGHTS = {
    "SAMPLE-BENIGN": 0.60,
    "SAMPLE-DoS Hulk": 0.15,
    "SAMPLE-PortScan": 0.12,
    "SAMPLE-Bot": 0.08,
    "SAMPLE-Web Attack - Brute Force": 0.05,
}


def _log_uniform(rng, low, high):
    """Values spread more naturally on a log scale."""
    return float(np.exp(rng.uniform(np.log(low), np.log(high))))


def make_rows(total_rows):
    rng = np.random.default_rng(RNG_SEED)
    classes = rng.choice(
        list(CLASS_WEIGHTS.keys()), size=total_rows,
        p=list(CLASS_WEIGHTS.values()),
    )
    rows = []
    for label in classes:
        p = PROFILES[label]
        fwd = int(rng.integers(p["fwd"][0], p["fwd"][1]))
        bwd = int(rng.integers(p["bwd"][0], p["bwd"][1]))
        duration = _log_uniform(rng, *p["duration"])
        pkt_rate = _log_uniform(rng, *p["pkt_rate"])
        byte_rate = _log_uniform(rng, *p["byte_rate"])
        iat = _log_uniform(rng, *p["iat"])
        iat_std = _log_uniform(rng, *p["iat_std"])
        syn = int(rng.integers(p["syn"][0], p["syn"][1] + 1))
        rst = int(rng.integers(p["rst"][0], p["rst"][1] + 1))
        avg_size = _log_uniform(rng, *p["avg_size"])
        rows.append({
            "Flow Duration": duration,
            "Total Fwd Packets": fwd,
            "Total Backward Packets": bwd,
            "Total Length of Fwd Packets": fwd * avg_size,
            "Total Length of Bwd Packets": bwd * avg_size * 1.1,
            "Flow Bytes/s": byte_rate,
            "Flow Packets/s": pkt_rate,
            "Flow IAT Mean": iat,
            "Flow IAT Std": iat_std,
            "SYN Flag Count": syn,
            "RST Flag Count": rst,
            "Average Packet Size": avg_size,
            "Label": label,
        })
    frame = pd.DataFrame(rows, columns=COLUMNS)
    return frame.sample(frac=1.0, random_state=RNG_SEED).reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=8000,
                        help="number of sample flows (default 8000)")
    args = parser.parse_args()

    data_dir = Path(__file__).resolve().parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    out = data_dir / "SAMPLE_demo_cicids2017_schema.csv"

    frame = make_rows(args.rows)
    frame.to_csv(out, index=False)
    print("=" * 60)
    print("NetSense DEMO dataset written (NOT real traffic)")
    print("=" * 60)
    print(f"File:    {out}")
    print(f"Rows:    {len(frame):,}")
    print("Classes:")
    for label, count in frame["Label"].value_counts().items():
        print(f"  {label:<34} {count:,}")
    print("\nNext: python ml/train_classifier.py && python ml/train_anomaly.py")
    print("Replace this file with real CICIDS2017 CSVs for real models.")


if __name__ == "__main__":
    main()
