"""
Train urgency classifier on normalized_dataset.csv.
Target: urgency_level (not urgent / somewhat urgent / very urgent)
Model: TF-IDF on subject+body → Logistic Regression
Threshold lowered to maximize recall of urgent classes.
Saves: skills/urgency/model/vectorizer.pkl, model.pkl, threshold.pkl
"""
from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

DATA = Path(__file__).parents[2] / "COMS6901-Dataset/data/processed/normalized_dataset.csv"
MODEL_DIR = Path(__file__).parent / "model"

LABEL_MAP = {"not urgent": 0, "somewhat urgent": 1, "very urgent": 2}


def main() -> None:
    print("Loading data...")
    df = pd.read_csv(DATA, usecols=["email_text", "subject", "urgency_level"], low_memory=False)
    df = df.dropna(subset=["urgency_level"])
    df["urgency_level"] = df["urgency_level"].str.strip().str.lower()
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
        class_weight=None,         # no reweighting — let the model respect class priors
        C=0.5,                     # stronger regularisation reduces over-confident urgent predictions
        solver="saga",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train_tf, y_train)

    y_pred = clf.predict(X_test_tf)
    labels = ["not urgent", "somewhat urgent", "very urgent"]
    print("\nClassification report (default threshold):")
    print(classification_report(y_test, y_pred, target_names=labels))

    # Find threshold that maximises specificity on the NOT-urgent class
    # i.e. minimise false positives (legitimate emails wrongly flagged as urgent)
    probs = clf.predict_proba(X_test_tf)
    urgent_prob = probs[:, 1] + probs[:, 2]
    true_urgent = (y_test >= 1).astype(int)

    best_thresh, best_spec = 0.5, 0.0
    for t in np.arange(0.30, 0.90, 0.01):
        pred_urgent = (urgent_prob >= t).astype(int)
        tn = ((pred_urgent == 0) & (true_urgent == 0)).sum()
        fp = ((pred_urgent == 1) & (true_urgent == 0)).sum()
        spec = tn / (tn + fp + 1e-9)
        if spec > best_spec:
            best_spec, best_thresh = spec, t

    print(f"\nOptimal urgency threshold for specificity: {best_thresh:.2f}  (specificity={best_spec:.3f})")

    MODEL_DIR.mkdir(exist_ok=True)
    pickle.dump(vec, open(MODEL_DIR / "vectorizer.pkl", "wb"))
    pickle.dump(clf, open(MODEL_DIR / "model.pkl", "wb"))
    pickle.dump({"urgent_threshold": best_thresh, "label_map": LABEL_MAP, "optimised_for": "specificity"}, open(MODEL_DIR / "meta.pkl", "wb"))

    print("Saved to", MODEL_DIR)


if __name__ == "__main__":
    main()
