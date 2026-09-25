# NetSense — Machine Learning Module (Phase 8)

This folder contains NetSense's ML intelligence layer. It sits **on top** of
the packet/flow analysis (Phases 2–4) — it never touches raw packets or
payloads, only behavioral flow features.

```
ml/
├── data/                 <- YOU place the dataset here (see below)
├── models/               <- trained models are saved here (created on demand)
├── preprocessing.py      <- reusable load/clean/map/split pipeline
├── train_classifier.py   <- explicit Random Forest training
├── train_anomaly.py      <- explicit Isolation Forest training
└── inference.py          <- loads models, answers per-flow questions
```

## 1. Dataset (where to put it)

Preferred dataset: **CICIDS2017** — the machine-learning-ready CSV files
("MachineLearningCVE") from the Canadian Institute for Cybersecurity:
https://www.unb.ca/cic/datasets/ids-2017.html

1. Download the CSV files (e.g. `Monday-WorkingHours.pcap_ISCX.csv`, …).
2. Place them into this folder: `netsense/ml/data/`.
3. Do **not** rename them — the loader accepts any name and any subset.

The app NEVER downloads data by itself; training is a manual, explicit step.
If the folder is empty, training prints instructions and the API honestly
reports `classifier_available: false`.

## 2. Data-leakage prevention (important design decision)

The models deliberately **exclude** these columns as features:

- Source/Destination IP addresses
- Source/Destination ports (incl. ephemeral ports)
- Timestamps / Flow ID

Why: identifiers let a model memorize one capture environment (that router,
that laptop) instead of learning traffic **behavior**. Such models look
brilliant on the training capture and fail on any other network. NetSense
uses only behavioral flow features; identifier-like columns are dropped in
`preprocessing.clean_dataframe()`.

## 3. Feature list (10 behavioral features)

| Feature | Meaning | Live flow source |
|---|---|---|
| Flow_Duration | flow duration (µs) | Phase 4 `flow.duration` (s → µs) |
| Pkt_Count_Fwd | forward packets | `flow.forward_packets` |
| Pkt_Count_Bwd | backward packets | `flow.backward_packets` |
| Byte_Rate | bytes/second | `flow.byte_rate` |
| Pkt_Rate | packets/second | `flow.packet_rate` |
| IAT_Mean | mean inter-arrival time (µs) | `flow.iat_mean_ms` (ms → µs) |
| IAT_Std | IAT standard deviation (µs) | `flow.iat_std_ms` (ms → µs) |
| SYN_Ratio | SYN packets / total packets | Phase 4 flag counters |
| RST_Ratio | RST packets / total packets | Phase 4 flag counters |
| Avg_Pkt_Size | bytes / packets | `flow.average_packet_size` |

Dataset columns are mapped through `COLUMN_ALIASES` in `preprocessing.py`
(CICIDS2017 name variants included). Every one of the 10 features IS
producible from live traffic — nothing is missing.

**Units matter**: CICIDS2017 durations/IATs are in **microseconds**; NetSense
flows use seconds/milliseconds. `ml_service.flow_to_features()` performs the
conversion — never connect features by name similarity alone.

## 4. Training (explicit, never automatic)

```bash
cd netsense/backend
venv\Scripts\activate          # Windows

python ../ml/train_classifier.py    # Random Forest + metrics + importances
python ../ml/train_anomaly.py       # Isolation Forest on BENIGN rows
```

Each script prints a real training report (accuracy/precision/recall/F1,
confusion matrix, feature importances — actual values only, never hardcoded)
and saves to `ml/models/`:

- `classifier.joblib`, `label_encoder.joblib`, `training_metrics.json`
- `isolation_forest.joblib`
- `feature_config.json` (the feature contract shared by training + inference)

Models are loaded lazily at first use. After retraining, the backend picks
them up on the next request.

## 5. Inference

`inference.py` answers, for ONE flow's behavioral features:

- `classify_flow(features)` → `{label, confidence}` — confidence comes only
  from real `predict_proba` values
- `detect_anomaly(features)` → `{status: "normal" | "potentially anomalous", score}`
  — careful wording, never "attack"
- `analyze_flow(features)` → both

Missing model? `{..., "available": false}` — the UI shows "Not available".
Incomplete features? Inference is **skipped honestly**, never padded with
invented numbers.

## 6. Live-flow integration

Background thread (5 s cadence) in `backend/ml_service.py`:
completed Phase 4 flows → `flow_to_features()` → models → SQLite
`ml_predictions` (flow-level results only; no payloads). The capture thread
only does O(1) counter updates, so ML never slows packet capture.

## 7. Explainability

Random Forest **feature importance** is implemented (model-derived).
**SHAP** is documented as unavailable in this build — the API reports it
honestly rather than adding heavy dependencies (spec §21).

## 8. Limitations (honesty first)

- An anomaly score is NOT proof of malicious activity.
- Class names come strictly from the training dataset (e.g. BENIGN, DoS…).
- Metrics are real test-set numbers; never claimed to be 100%.
- `n_jobs=1` in trainers: Windows-safe (parallel loky workers can hang in
  captured consoles); datasets are small enough that this is fine.
- The anomaly threshold (0.0 on the negated Isolation Forest score) is
  conservative and configurable in `inference.py`.
