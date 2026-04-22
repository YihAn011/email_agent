"""
Train urgency classifier on dataset/processed/normalized_dataset.csv.
Target: urgency_level (not urgent / somewhat urgent / very urgent)
Saves: skills/urgency/model/vectorizer.pkl, model.pkl, meta.pkl
"""
from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

DATA = Path(__file__).parents[2] / "dataset" / "processed" / "normalized_dataset.csv"
MODEL_DIR = Path(__file__).parent / "model"
TARGET_FPR = 0.05

LABEL_MAP = {"not urgent": 0, "somewhat urgent": 1, "very urgent": 2}


def choose_threshold(true_urgent: np.ndarray, urgent_prob: np.ndarray) -> tuple[float, dict[str, float]]:
    candidates: list[tuple[float, dict[str, float]]] = []
    for t in np.arange(0.20, 0.951, 0.01):
        pred_urgent = (urgent_prob >= t).astype(int)
        tn = int(((pred_urgent == 0) & (true_urgent == 0)).sum())
        fp = int(((pred_urgent == 1) & (true_urgent == 0)).sum())
        fn = int(((pred_urgent == 0) & (true_urgent == 1)).sum())
        tp = int(((pred_urgent == 1) & (true_urgent == 1)).sum())
        precision, recall, f1, _ = precision_recall_fscore_support(
            true_urgent, pred_urgent, average="binary", zero_division=0
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


def compute_urgency(text: str, subject: str = "") -> str:
    combined = f"{text or ''} {subject or ''}".lower()
    urgent_keywords = [
        "urgent",
        "immediately",
        "asap",
        "action required",
        "verify",
        "suspend",
        "suspended",
        "click now",
        "last chance",
        "important",
        "attention",
        "password expires",
        "confirm",
        "update now",
        "limited time",
        "security alert",
        "unusual activity",
        "act now",
        "final notice",
    ]
    keyword_count = sum(1 for word in urgent_keywords if word in combined)
    exclam_count = combined.count("!")
    score = keyword_count * 2 + exclam_count
    if len(combined) < 200 and keyword_count > 0:
        score += 2
    if score >= 6:
        return "very urgent"
    if score >= 3:
        return "somewhat urgent"
    return "not urgent"


def main() -> None:
    print("Loading data...")
    df = pd.read_csv(
        DATA,
        usecols=lambda col: col in {"email_text", "subject", "urgency_level"},
        low_memory=False,
    )
    if "urgency_level" not in df.columns:
        df["urgency_level"] = df.apply(
            lambda row: compute_urgency(row.get("email_text", ""), row.get("subject", "")),
            axis=1,
        )
        print("No urgency_level column found; generated labels with compute_urgency().")
    df = df.dropna(subset=["urgency_level"])
    df["urgency_level"] = df["urgency_level"].astype(str).str.strip().str.lower()
    df = df[df["urgency_level"].isin(LABEL_MAP)]

    df["text"] = (
        df["subject"].fillna("").astype(str) + " " + df["email_text"].fillna("").astype(str)
    ).str[:2000]  # cap at 2k chars to keep TF-IDF tractable

    print(f"Dataset size: {len(df)}")
    print("Label distribution:\n", df["urgency_level"].value_counts())

    y = df["urgency_level"].map(LABEL_MAP).values
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"].values, y, test_size=0.15, random_state=42, stratify=y
    )

    print("Fitting TF-IDF...")
    vec = TfidfVectorizer(
        max_features=30_000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=3,
    )
    X_train_tf = vec.fit_transform(X_train)
    X_test_tf = vec.transform(X_test)

    print("Training Logistic Regression...")
    clf = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        C=1.0,
        solver="saga",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train_tf, y_train)

    y_pred = clf.predict(X_test_tf)
    labels = ["not urgent", "somewhat urgent", "very urgent"]
    print("\nClassification report (default threshold):")
    print(classification_report(y_test, y_pred, target_names=labels))

    probs = clf.predict_proba(X_test_tf)
    urgent_prob = probs[:, 1] + probs[:, 2]
    true_urgent = (y_test >= 1).astype(int)

    best_thresh, metrics = choose_threshold(true_urgent, urgent_prob)

    print(
        f"\nChosen urgency threshold: {best_thresh:.2f}  "
        f"(fpr={metrics['fpr']:.4f}, recall={metrics['recall']:.4f}, precision={metrics['precision']:.4f})"
    )

    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR / "vectorizer.pkl", "wb") as handle:
        pickle.dump(vec, handle)
    with open(MODEL_DIR / "model.pkl", "wb") as handle:
        pickle.dump(clf, handle)
    with open(MODEL_DIR / "meta.pkl", "wb") as handle:
        pickle.dump(
            {
                "urgent_threshold": best_thresh,
                "label_map": LABEL_MAP,
                "optimised_for": "max_recall_under_fpr_cap",
                "target_fpr": TARGET_FPR,
                "test_metrics": metrics,
            },
            handle,
        )

    print("Saved to", MODEL_DIR)


if __name__ == "__main__":
    main()
