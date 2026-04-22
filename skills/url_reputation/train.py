"""
Train URL reputation classifier on dataset/processed/normalized_dataset.csv.
Target: binary phishing detector tuned for low false positives with usable recall.
Saves: skills/url_reputation/model/model.pkl, meta.pkl
"""
from __future__ import annotations

import pickle
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

DATA = Path(__file__).parents[2] / "dataset" / "processed" / "normalized_dataset.csv"
MODEL_DIR = Path(__file__).parent / "model"
TARGET_FPR = 0.01

FEATURES = [
    "num_urls",
    "has_ip_url",
    "email_length",
    "num_exclamation_marks",
    "num_links_in_body",
    "is_html_email",
    "url_length_max",
    "url_length_avg",
    "url_subdom_max",
    "url_subdom_avg",
    "attachment_count",
    "has_attachments",
]

TEXT_COLS = ["subject", "email_text", "sender", "sender_domain"]


def choose_threshold(y_true: np.ndarray, probs: np.ndarray) -> tuple[float, dict[str, float]]:
    candidates: list[tuple[float, dict[str, float]]] = []
    for t in np.arange(0.20, 0.991, 0.01):
        pred = (probs >= t).astype(int)
        tn = int(((pred == 0) & (y_true == 0)).sum())
        fp = int(((pred == 1) & (y_true == 0)).sum())
        fn = int(((pred == 0) & (y_true == 1)).sum())
        tp = int(((pred == 1) & (y_true == 1)).sum())
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, pred, average="binary", zero_division=0
        )
        fpr = fp / (fp + tn + 1e-9)
        metrics = {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "fpr": float(fpr),
        }
        candidates.append((float(t), metrics))

    viable = [item for item in candidates if item[1]["fpr"] <= TARGET_FPR]
    if viable:
        viable.sort(
            key=lambda item: (
                item[1]["recall"],
                item[1]["precision"],
                -item[1]["fpr"],
                item[1]["f1"],
            ),
            reverse=True,
        )
        return viable[0]

    candidates.sort(
        key=lambda item: (
            -item[1]["fpr"],
            item[1]["recall"],
            item[1]["precision"],
        )
    )
    return candidates[0]


def parse_url_domains(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    return [item.strip().lower() for item in text.split("|") if item.strip()]


def derive_missing_features(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    domain_lists = frame["url_domains"].fillna("").astype(str).apply(parse_url_domains)
    frame["url_length_max"] = domain_lists.apply(
        lambda items: max((len(item) for item in items), default=0)
    )
    frame["url_length_avg"] = domain_lists.apply(
        lambda items: float(sum(len(item) for item in items) / len(items)) if items else 0.0
    )
    frame["url_subdom_max"] = domain_lists.apply(
        lambda items: max((urlparse("https://" + item).netloc.count(".") for item in items), default=0)
    )
    frame["url_subdom_avg"] = domain_lists.apply(
        lambda items: (
            float(sum(urlparse("https://" + item).netloc.count(".") for item in items) / len(items))
            if items
            else 0.0
        )
    )
    return frame


def main() -> None:
    print("Loading data...")
    cols = FEATURES + TEXT_COLS + ["label_id"]
    df = pd.read_csv(
        DATA,
        usecols=lambda col: col in set(cols + ["normalized_label", "url_domains"]),
        low_memory=False,
    )
    df = derive_missing_features(df)

    print(f"Dataset size: {len(df)}")
    print("Label distribution:\n", df["normalized_label"].value_counts())

    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    y = (df["normalized_label"].astype(str).str.lower() == "phishing").astype(int).values
    X = df[FEATURES].values

    print(f"Phishing: {y.sum()} / {len(y)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )

    print("Training GradientBoostingClassifier...")
    clf = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\nClassification report (default 0.5 threshold):")
    print(classification_report(y_test, y_pred, target_names=["not phishing", "phishing"]))

    probs = clf.predict_proba(X_test)[:, 1]
    best_thresh, metrics = choose_threshold(y_test, probs)

    print(
        f"\nChosen phishing threshold: {best_thresh:.2f}  "
        f"(fpr={metrics['fpr']:.4f}, recall={metrics['recall']:.4f}, precision={metrics['precision']:.4f})"
    )

    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR / "model.pkl", "wb") as handle:
        pickle.dump(clf, handle)
    with open(MODEL_DIR / "meta.pkl", "wb") as handle:
        pickle.dump(
            {
                "features": FEATURES,
                "phishing_threshold": best_thresh,
                "label": "phishing_binary",
                "optimised_for": "max_recall_under_fpr_cap",
                "target_fpr": TARGET_FPR,
                "test_metrics": metrics,
            },
            handle,
        )

    print("Saved to", MODEL_DIR)


if __name__ == "__main__":
    main()
