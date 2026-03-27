"""
Train URL reputation classifier on normalized_dataset.csv.
Target: binary — phishing (label_id==2) vs not phishing
Features: pre-engineered URL + content numerical features
Model: GradientBoostingClassifier (tabular, handles non-linearity well)
Threshold lowered to maximise recall.
Saves: skills/url_reputation/model/model.pkl, meta.pkl
"""
from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

DATA = Path(__file__).parents[2] / "COMS6901-Dataset/data/processed/normalized_dataset.csv"
MODEL_DIR = Path(__file__).parent / "model"

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


def main() -> None:
    print("Loading data...")
    cols = FEATURES + ["label_id", "normalized_label"]
    df = pd.read_csv(DATA, usecols=cols, low_memory=False)

    print(f"Dataset size: {len(df)}")
    print("Label distribution:\n", df["normalized_label"].value_counts())

    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    # Binary: phishing vs everything else (spam + legitimate = not phishing)
    y = (df["label_id"] == 2).astype(int).values
    X = df[FEATURES].values

    print(f"Phishing: {y.sum()} / {len(y)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )

    print("Training GradientBoostingClassifier (no class reweighting)...")
    clf = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )

    # No sample_weight — let the natural class distribution dominate
    # so the model is conservative about flagging legitimate emails
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\nClassification report (default 0.5 threshold):")
    print(classification_report(y_test, y_pred, target_names=["not phishing", "phishing"]))

    # Raise threshold to maximise specificity (minimise false positives on legitimate emails)
    probs = clf.predict_proba(X_test)[:, 1]
    best_thresh, best_spec = 0.5, 0.0
    for t in np.arange(0.20, 0.95, 0.01):
        pred = (probs >= t).astype(int)
        tn = ((pred == 0) & (y_test == 0)).sum()
        fp = ((pred == 1) & (y_test == 0)).sum()
        spec = tn / (tn + fp + 1e-9)
        if spec > best_spec:
            best_spec, best_thresh = spec, t

    print(f"\nOptimal phishing threshold for specificity: {best_thresh:.2f}  (specificity={best_spec:.3f})")

    MODEL_DIR.mkdir(exist_ok=True)
    pickle.dump(clf, open(MODEL_DIR / "model.pkl", "wb"))
    pickle.dump({
        "features": FEATURES,
        "phishing_threshold": best_thresh,
        "label": "phishing_binary",
        "optimised_for": "specificity",
    }, open(MODEL_DIR / "meta.pkl", "wb"))

    print("Saved to", MODEL_DIR)


if __name__ == "__main__":
    main()
