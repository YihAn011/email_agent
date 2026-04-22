from __future__ import annotations

import argparse
import csv
import json
import pickle
import sys
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve

csv.field_size_limit(sys.maxsize)

ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = ROOT / "dataset" / "processed"
MODEL_DIR = Path(__file__).resolve().parent / "model"
REPORT_DIR = ROOT / "dataset" / "reports"


def _load_rows(path: Path, *, sources: set[str]) -> tuple[list[str], np.ndarray]:
    texts: list[str] = []
    labels: list[int] = []
    with path.open(encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if sources and row.get("source", "") not in sources:
                continue
            labels.append(int(row["binary_label"]))
            texts.append(
                " ".join(
                    [
                        f"subject={row.get('subject', '')}",
                        f"sender={row.get('sender', '')}",
                        f"sender_domain={row.get('sender_domain', '')}",
                        f"content_type={row.get('content_types', '')}",
                        f"body={(row.get('email_text', '') or '')[:4000]}",
                    ]
                )
            )
    return texts, np.asarray(labels, dtype=np.int32)


def _metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    preds = (scores >= threshold).astype(int)
    tp = int(((preds == 1) & (y_true == 1)).sum())
    fp = int(((preds == 1) & (y_true == 0)).sum())
    tn = int(((preds == 0) & (y_true == 0)).sum())
    fn = int(((preds == 0) & (y_true == 1)).sum())
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "fpr": fpr,
        "recall": recall,
        "precision": precision,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--sources", default="nazario,spamassassin,github,meajor")
    args = parser.parse_args()

    sources = {item.strip() for item in args.sources.split(",") if item.strip()}
    train_texts, y_train = _load_rows(PROCESSED_DIR / "spam_binary_train.csv", sources=sources)
    val_texts, y_val = _load_rows(PROCESSED_DIR / "spam_binary_val.csv", sources=sources)
    test_texts, y_test = _load_rows(PROCESSED_DIR / "spam_binary_test.csv", sources=sources)

    word_vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=2,
        max_features=120000,
        sublinear_tf=True,
    )
    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=180000,
        sublinear_tf=True,
    )

    x_train = sparse.hstack(
        [word_vectorizer.fit_transform(train_texts), char_vectorizer.fit_transform(train_texts)],
        format="csr",
    )
    x_val = sparse.hstack(
        [word_vectorizer.transform(val_texts), char_vectorizer.transform(val_texts)],
        format="csr",
    )
    x_test = sparse.hstack(
        [word_vectorizer.transform(test_texts), char_vectorizer.transform(test_texts)],
        format="csr",
    )

    classifier = LogisticRegression(
        max_iter=120,
        solver="saga",
        class_weight={0: 2.0, 1: 1.0},
        random_state=42,
    )
    classifier.fit(x_train, y_train)

    val_scores = classifier.predict_proba(x_val)[:, 1]
    test_scores = classifier.predict_proba(x_test)[:, 1]
    fpr_values, tpr_values, thresholds = roc_curve(y_val, val_scores)
    viable = np.where(fpr_values <= args.target_fpr)[0]
    chosen_idx = int(viable[np.argmax(tpr_values[viable])]) if len(viable) else int(np.argmin(np.abs(fpr_values - args.target_fpr)))
    threshold = float(thresholds[chosen_idx])

    val_metrics = _metrics(y_val, val_scores, threshold)
    test_metrics = _metrics(y_test, test_scores, threshold)
    report = {
        "sources": sorted(sources),
        "target_fpr": args.target_fpr,
        "threshold": threshold,
        "val_auc": float(roc_auc_score(y_val, val_scores)),
        "test_auc": float(roc_auc_score(y_test, test_scores)),
        "val_metrics": val_metrics,
        "test_metrics": test_metrics,
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with (MODEL_DIR / "word_vectorizer.pkl").open("wb") as handle:
        pickle.dump(word_vectorizer, handle)
    with (MODEL_DIR / "char_vectorizer.pkl").open("wb") as handle:
        pickle.dump(char_vectorizer, handle)
    with (MODEL_DIR / "classifier.pkl").open("wb") as handle:
        pickle.dump(classifier, handle)
    with (MODEL_DIR / "meta.pkl").open("wb") as handle:
        pickle.dump(
            {
                "threshold": threshold,
                "target_fpr": args.target_fpr,
                "sources": sorted(sources),
            },
            handle,
        )
    (REPORT_DIR / "content_model_metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
