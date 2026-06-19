"""
AI-IDS Model Training Pipeline
────────────────────────────────
Trains binary + multi-class Random Forest classifiers.

Data priority:
  1. data/processed/train.parquet (from prep_cic2017.py OR mock_data.py)
  2. data/processed/train.csv     (fallback)
  3. Auto-runs mock_data.py if nothing found

Output:
  models/rf_binary.joblib   - binary classifier (benign vs attack)
  models/rf_multi.joblib    - multi-class classifier (8 attack types)
  models/rf.joblib           - copy of binary (backward compat with original API)
  models/rf_cic_binary.joblib - CIC-trained binary (if CIC data used)
  models/rf_cic_multi.joblib  - CIC-trained multi-class (if CIC data used)
  models/model_meta.json    - feature names + class mapping
  models/threshold.txt      - optimal threshold from precision-recall curve

Usage:
    python src/models/train.py
"""

import joblib
import json
import subprocess
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    f1_score, precision_score, recall_score, accuracy_score,
    average_precision_score, classification_report,
    confusion_matrix, roc_auc_score, precision_recall_curve
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

# ── Paths ────────────────────────────────────────────────────
_p = Path(__file__).resolve().parent
while _p != _p.parent:
    if (_p / "env" / "requirements.txt").exists():
        break
    _p = _p.parent
else:
    _p = Path.cwd()
PROJECT_ROOT = _p
DATA_DIR   = PROJECT_ROOT / "data" / "processed"
MODEL_DIR  = PROJECT_ROOT / "models";     MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR = PROJECT_ROOT / "reports";    REPORT_DIR.mkdir(parents=True, exist_ok=True)
EVAL_DIR   = PROJECT_ROOT / "evaluation"; EVAL_DIR.mkdir(parents=True, exist_ok=True)

EXCLUDE_COLS = ["label", "label_multi", "attack_type"]


def detect_data_source():
    """Check if data is from CIC-IDS2017 or mock generator."""
    info_path = DATA_DIR / "data_info.json"
    if info_path.exists():
        try:
            with open(info_path, encoding="utf-8") as f:
                info = json.load(f)
            return info.get("source", "unknown")
        except Exception:
            pass
    return "mock"


# ── Data Loading ─────────────────────────────────────────────
def load_dataset():
    """
    Load training data. Priority:
      1. train.parquet/csv (from prep_cic2017.py or mock_data.py — both produce same format)
      2. Auto-generate mock data if nothing exists
    """
    # Try parquet first, then csv
    for ext, reader in [("parquet", pd.read_parquet), ("csv", pd.read_csv)]:
        path = DATA_DIR / f"train.{ext}"
        if path.exists():
            print(f"  Loading {path}")
            df = reader(path)

            # Validate required columns
            if "label" not in df.columns:
                print(f"  WARNING: 'label' column missing in {path}")
                continue

            if "label_multi" not in df.columns and "attack_type" in df.columns:
                # Build label_multi from attack_type
                classes = sorted(df["attack_type"].unique().tolist())
                cmap = {c: i for i, c in enumerate(classes)}
                df["label_multi"] = df["attack_type"].map(cmap)
                print(f"  Built label_multi from attack_type ({len(classes)} classes)")

            if "label_multi" not in df.columns:
                # Binary-only dataset (e.g. old format) — still usable
                print("  NOTE: No multi-class labels. Will train binary only.")
                df["label_multi"] = df["label"]
                df["attack_type"] = df["label"].map({0: "Benign", 1: "Attack"})

            return df

    # Nothing found → auto-generate mock data
    print("  No training data found. Generating mock data...")
    mock_script = PROJECT_ROOT / "src" / "data" / "mock_data.py"
    if mock_script.exists():
        subprocess.run([sys.executable, str(mock_script)], check=True)
        # Retry loading
        for ext, reader in [("parquet", pd.read_parquet), ("csv", pd.read_csv)]:
            path = DATA_DIR / f"train.{ext}"
            if path.exists():
                return reader(path)

    raise FileNotFoundError(
        "Could not load or generate training data.\n"
        "  Option A: python src/data/mock_data.py        (quick demo data)\n"
        "  Option B: python src/data/prep_cic2017.py     (real CIC-IDS2017 data)"
    )


# ── Training Functions ───────────────────────────────────────
def train_binary(X_train, X_val, y_train, y_val, is_cic=False):
    """Train binary classifier (benign vs attack)."""
    print("\n" + "=" * 60)
    print("BINARY CLASSIFIER (Benign vs Attack)")
    print("=" * 60)

    # Use more estimators for CIC data (larger dataset)
    n_est = 500 if is_cic else 400
    max_d = 30 if is_cic else 25

    pipe = Pipeline([
        ("scale", RobustScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=n_est, max_depth=max_d, min_samples_leaf=3,
            n_jobs=-1, class_weight="balanced_subsample", random_state=42,
        )),
    ])
    pipe.fit(X_train, y_train)

    preds = pipe.predict(X_val)
    proba = pipe.predict_proba(X_val)[:, 1]

    metrics = {
        "accuracy":  round(accuracy_score(y_val, preds), 4),
        "f1":        round(f1_score(y_val, preds), 4),
        "precision": round(precision_score(y_val, preds), 4),
        "recall":    round(recall_score(y_val, preds), 4),
        "auc_roc":   round(roc_auc_score(y_val, proba), 4),
        "ap":        round(average_precision_score(y_val, proba), 4),
    }
    cm = confusion_matrix(y_val, preds)
    cr = classification_report(y_val, preds, digits=4, target_names=["Benign", "Attack"])

    print(f"  Accuracy:  {metrics['accuracy']}")
    print(f"  F1 Score:  {metrics['f1']}")
    print(f"  Precision: {metrics['precision']}")
    print(f"  Recall:    {metrics['recall']}")
    print(f"  AUC-ROC:   {metrics['auc_roc']}")
    print(f"\n{cr}")

    # Save models
    joblib.dump(pipe, MODEL_DIR / "rf_binary.joblib")
    joblib.dump(pipe, MODEL_DIR / "rf.joblib")  # backward compat
    print(f"  Saved: models/rf_binary.joblib")
    print(f"  Saved: models/rf.joblib (backward compatible)")

    # Save CIC-specific copy if trained on CIC data
    if is_cic:
        joblib.dump(pipe, MODEL_DIR / "rf_cic_binary.joblib")
        print(f"  Saved: models/rf_cic_binary.joblib (CIC-IDS2017)")

    # Optimal threshold via precision-recall curve
    threshold = find_optimal_threshold(y_val, proba)

    return pipe, metrics, cm, cr, threshold


def train_multiclass(X_train, X_val, y_train, y_val, class_names, is_cic=False):
    """Train multi-class classifier."""
    print("\n" + "=" * 60)
    print("MULTI-CLASS CLASSIFIER")
    print("=" * 60)

    n_est = 600 if is_cic else 500
    max_d = 35 if is_cic else 30

    pipe = Pipeline([
        ("scale", RobustScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=n_est, max_depth=max_d, min_samples_leaf=2,
            n_jobs=-1, class_weight="balanced_subsample", random_state=42,
        )),
    ])
    pipe.fit(X_train, y_train)

    preds = pipe.predict(X_val)

    accuracy = round(accuracy_score(y_val, preds), 4)
    f1_macro = round(f1_score(y_val, preds, average="macro"), 4)
    f1_weighted = round(f1_score(y_val, preds, average="weighted"), 4)
    cr = classification_report(y_val, preds, digits=4, target_names=class_names)
    cm = confusion_matrix(y_val, preds)

    # Per-class F1 scores
    per_class_f1 = f1_score(y_val, preds, average=None)
    per_class_dict = {class_names[i]: round(float(per_class_f1[i]), 4)
                      for i in range(len(class_names))}

    metrics = {
        "accuracy": accuracy,
        "f1_macro": f1_macro,
        "f1_weighted": f1_weighted,
        "per_class_f1": per_class_dict,
    }

    print(f"  Accuracy:    {accuracy}")
    print(f"  F1 (macro):  {f1_macro}")
    print(f"  F1 (weight): {f1_weighted}")
    print(f"\n  Per-class F1:")
    for cls, f1 in per_class_dict.items():
        bar = "#" * int(f1 * 30)
        print(f"    {cls:15s}  {f1:.4f}  {bar}")
    print(f"\n{cr}")

    joblib.dump(pipe, MODEL_DIR / "rf_multi.joblib")
    print(f"  Saved: models/rf_multi.joblib")

    if is_cic:
        joblib.dump(pipe, MODEL_DIR / "rf_cic_multi.joblib")
        print(f"  Saved: models/rf_cic_multi.joblib (CIC-IDS2017)")

    # Save confusion matrix heatmap
    save_confusion_matrix(cm, class_names)

    return pipe, metrics, cm, cr


def find_optimal_threshold(y_true, proba):
    """Find the threshold that maximizes F1 score."""
    prec, rec, thr = precision_recall_curve(y_true, proba)
    f1s = (2 * prec[:-1] * rec[:-1]) / (prec[:-1] + rec[:-1] + 1e-9)
    best_idx = int(np.argmax(f1s))
    best_thr = float(thr[best_idx])
    best_f1 = float(f1s[best_idx])

    print(f"\n  Optimal threshold: {best_thr:.4f} (F1 = {best_f1:.4f})")

    # Save for API to use
    with open(MODEL_DIR / "threshold.txt", "w", encoding="utf-8") as f:
        f.write(f"{best_thr:.6f}\n")
    print(f"  Saved: models/threshold.txt")

    # Save threshold plot if matplotlib available
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(thr, f1s, color="#22d3ee", linewidth=2, label="F1 vs Threshold")
        ax.axvline(best_thr, color="#f43f5e", linestyle="--",
                   label=f"Best = {best_thr:.3f}")
        ax.set_xlabel("Threshold")
        ax.set_ylabel("F1 Score")
        ax.set_title("Threshold Optimization")
        ax.legend()
        ax.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(REPORT_DIR / "threshold_tuning.png", dpi=150)
        plt.close()
        print(f"  Saved: reports/threshold_tuning.png")
    except ImportError:
        pass  # matplotlib optional for training

    return best_thr


def save_confusion_matrix(cm, class_names):
    """Save confusion matrix as PNG heatmap."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(10, 8))
        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.set_title("Multi-Class Confusion Matrix", fontsize=14, fontweight="bold")
        fig.colorbar(im, ax=ax)

        ax.set_xticks(range(len(class_names)))
        ax.set_yticks(range(len(class_names)))
        ax.set_xticklabels(class_names, rotation=45, ha="right", fontsize=9)
        ax.set_yticklabels(class_names, fontsize=9)
        ax.set_xlabel("Predicted", fontsize=11)
        ax.set_ylabel("True", fontsize=11)

        # Annotate cells
        thresh = cm.max() / 2
        for i in range(len(class_names)):
            for j in range(len(class_names)):
                color = "white" if cm[i, j] > thresh else "black"
                ax.text(j, i, format(cm[i, j], ","),
                        ha="center", va="center", color=color, fontsize=8)

        plt.tight_layout()
        plt.savefig(REPORT_DIR / "confusion_matrix.png", dpi=150)
        plt.close()
        print(f"  Saved: reports/confusion_matrix.png")
    except ImportError:
        pass


# ── Evaluation Report ────────────────────────────────────────
def save_evaluation(bin_metrics, bin_cm, bin_cr, multi_metrics, multi_cm, multi_cr,
                    class_names, feature_names, n_samples, threshold, data_source):
    """Save comprehensive evaluation report."""
    ts = datetime.now().isoformat(timespec="seconds")

    # JSON metrics
    eval_data = {
        "timestamp": ts,
        "data_source": data_source,
        "dataset_size": n_samples,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "binary": bin_metrics,
        "multiclass": multi_metrics,
        "class_names": class_names,
        "optimal_threshold": threshold,
    }
    with open(EVAL_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(eval_data, f, indent=2)

    # Text report
    report = []
    report.append("=" * 70)
    report.append("AI-IDS EVALUATION REPORT")
    report.append(f"Generated: {ts}")
    report.append(f"Data source: {data_source}")
    report.append("=" * 70)
    report.append(f"\nDataset: {n_samples:,} samples, {len(feature_names)} features")
    report.append(f"Classes: {class_names}")
    report.append(f"Optimal threshold: {threshold:.4f}")

    report.append(f"\n{'-' * 70}")
    report.append("BINARY CLASSIFICATION (Benign vs Attack)")
    report.append(f"{'-' * 70}")
    for k, v in bin_metrics.items():
        report.append(f"  {k:15s}: {v}")
    report.append(f"\nConfusion Matrix:")
    report.append(f"  {'':>12s} Pred:Benign  Pred:Attack")
    report.append(f"  {'True:Benign':>12s}  {bin_cm[0][0]:>8}     {bin_cm[0][1]:>8}")
    report.append(f"  {'True:Attack':>12s}  {bin_cm[1][0]:>8}     {bin_cm[1][1]:>8}")
    report.append(f"\n{bin_cr}")

    report.append(f"\n{'-' * 70}")
    report.append("MULTI-CLASS CLASSIFICATION")
    report.append(f"{'-' * 70}")
    for k, v in multi_metrics.items():
        if k == "per_class_f1":
            report.append(f"\n  Per-class F1 scores:")
            for cls, f1 in v.items():
                report.append(f"    {cls:15s}: {f1}")
        else:
            report.append(f"  {k:15s}: {v}")
    report.append(f"\nConfusion Matrix:")
    header = f"  {'':>15s}" + "".join(f"{c[:8]:>10s}" for c in class_names)
    report.append(header)
    for i, row in enumerate(multi_cm):
        line = f"  {class_names[i][:15]:>15s}" + "".join(f"{v:>10}" for v in row)
        report.append(line)
    report.append(f"\n{multi_cr}")

    report_text = "\n".join(report)
    with open(EVAL_DIR / "evaluation_report.txt", "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"\n  Saved: evaluation/metrics.json")
    print(f"  Saved: evaluation/evaluation_report.txt")


def save_model_metadata(feature_names, class_names, bin_metrics, multi_metrics,
                        threshold, data_source):
    """Save metadata used by the API."""
    meta = {
        "feature_names": feature_names,
        "class_names": class_names,
        "class_map": {c: i for i, c in enumerate(class_names)},
        "reverse_class_map": {i: c for i, c in enumerate(class_names)},
        "trained_at": datetime.now().isoformat(),
        "data_source": data_source,
        "threshold": threshold,
        "binary_f1": bin_metrics["f1"],
        "binary_accuracy": bin_metrics["accuracy"],
        "binary_auc_roc": bin_metrics.get("auc_roc", 0),
        "multi_f1_macro": multi_metrics["f1_macro"],
        "multi_accuracy": multi_metrics["accuracy"],
        "per_class_f1": multi_metrics.get("per_class_f1", {}),
    }
    with open(MODEL_DIR / "model_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"  Saved: models/model_meta.json")


# ── Main ─────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("AI-IDS Model Training Pipeline")
    print("=" * 60)

    df = load_dataset()
    data_source = detect_data_source()
    is_cic = data_source == "CIC-IDS2017"
    print(f"  Loaded {len(df):,} rows")
    print(f"  Data source: {data_source}")

    # Extract features and labels
    feature_cols = [c for c in df.columns if c not in EXCLUDE_COLS]
    X = df[feature_cols].fillna(0).replace([np.inf, -np.inf], 0).copy()
    y_bin = df["label"].values
    y_multi = df["label_multi"].values

    # Get class names
    class_map_path = DATA_DIR / "class_map.json"
    if class_map_path.exists():
        with open(class_map_path, encoding="utf-8") as f:
            class_map = json.load(f)
        class_names = [k for k, v in sorted(class_map.items(), key=lambda x: x[1])]
    elif "attack_type" in df.columns:
        class_names = sorted(df["attack_type"].unique().tolist())
    else:
        class_names = [str(i) for i in sorted(df["label_multi"].unique())]

    print(f"  Features: {len(feature_cols)}")
    print(f"  Classes:  {class_names}")

    # Show class distribution
    if "attack_type" in df.columns:
        print(f"\n  Training data distribution:")
        for cls, count in df["attack_type"].value_counts().sort_index().items():
            pct = count / len(df) * 100
            print(f"    {cls:15s} {count:>8,}  ({pct:5.1f}%)")

    # Single stratified split for both models (consistent evaluation)
    X_train, X_val, yb_tr, yb_va, ym_tr, ym_va = train_test_split(
        X, y_bin, y_multi, test_size=0.2, random_state=42, stratify=y_multi
    )

    # Train binary
    bin_pipe, bin_metrics, bin_cm, bin_cr, threshold = train_binary(
        X_train, X_val, yb_tr, yb_va, is_cic=is_cic
    )

    # Train multi-class
    multi_pipe, multi_metrics, multi_cm, multi_cr = train_multiclass(
        X_train, X_val, ym_tr, ym_va, class_names, is_cic=is_cic
    )

    # Save evaluation and metadata
    save_evaluation(bin_metrics, bin_cm, bin_cr, multi_metrics, multi_cm, multi_cr,
                    class_names, feature_cols, len(df), threshold, data_source)
    save_model_metadata(feature_cols, class_names, bin_metrics, multi_metrics,
                        threshold, data_source)

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print(f"  Source:    {data_source}")
    print(f"  Binary  -> F1: {bin_metrics['f1']}  | Acc: {bin_metrics['accuracy']}  | AUC: {bin_metrics['auc_roc']}")
    print(f"  Multi   -> F1: {multi_metrics['f1_macro']}  | Acc: {multi_metrics['accuracy']}")
    print(f"  Threshold: {threshold:.4f}")
    if is_cic:
        print(f"  CIC models: rf_cic_binary.joblib, rf_cic_multi.joblib")
    print("=" * 60)


if __name__ == "__main__":
    main()
