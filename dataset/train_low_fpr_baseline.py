import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction import FeatureHasher
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score, roc_curve


ROOT = Path(__file__).resolve().parent
PROCESSED_DIR = ROOT / "processed"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"

TRAIN_PATH = PROCESSED_DIR / "spam_binary_train.csv"
VAL_PATH = PROCESSED_DIR / "spam_binary_val.csv"
TEST_PATH = PROCESSED_DIR / "spam_binary_test.csv"

MODEL_PATH = MODEL_DIR / "low_fpr_baseline.joblib"
REPORT_PATH = REPORT_DIR / "low_fpr_baseline_report.md"
METRICS_PATH = REPORT_DIR / "low_fpr_baseline_metrics.json"

NEGATIVE_WEIGHT = 2.0
POSITIVE_WEIGHT = 1.0
TARGET_FPR = 0.01
MAX_NEGATIVE_TRAIN_ROWS = 70000
DEFAULT_DECISION_THRESHOLD = 0.0


TEXT_COLUMNS = ["subject", "email_text", "sender", "sender_domain", "content_types", "source"]
NUMERIC_COLUMNS = [
    "num_urls",
    "has_ip_url",
    "email_length",
    "num_exclamation_marks",
    "num_links_in_body",
    "is_html_email",
    "attachment_count",
    "has_attachments",
]


def load_frame(path: Path) -> pd.DataFrame:
    usecols = ["binary_label", *TEXT_COLUMNS, *NUMERIC_COLUMNS]
    frame = pd.read_csv(path, usecols=usecols, low_memory=False)
    for col in TEXT_COLUMNS:
        frame[col] = frame[col].fillna("").astype(str)
    for col in NUMERIC_COLUMNS:
        frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0.0)
    frame["binary_label"] = pd.to_numeric(frame["binary_label"], errors="raise").astype(int)
    return frame


def combine_text(frame: pd.DataFrame) -> pd.Series:
    pieces = [
        "subject=" + frame["subject"],
        "body=" + frame["email_text"].str.slice(0, 4000),
        "sender=" + frame["sender"],
        "sender_domain=" + frame["sender_domain"],
        "content_type=" + frame["content_types"],
    ]
    return pieces[0].str.cat(pieces[1:], sep=" ")


def rows_to_feature_dicts(frame: pd.DataFrame) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for row in frame.itertuples(index=False):
        feature_dict = {
            "source": row.source,
            "sender_domain": row.sender_domain,
            "content_types": row.content_types,
            "num_urls": float(row.num_urls),
            "has_ip_url": float(row.has_ip_url),
            "email_length": float(row.email_length),
            "num_exclamation_marks": float(row.num_exclamation_marks),
            "num_links_in_body": float(row.num_links_in_body),
            "is_html_email": float(row.is_html_email),
            "attachment_count": float(row.attachment_count),
            "has_attachments": float(row.has_attachments),
        }
        records.append(feature_dict)
    return records


def rebalance_train_frame(frame: pd.DataFrame) -> pd.DataFrame:
    negatives = frame[frame["binary_label"] == 0]
    positives = frame[frame["binary_label"] == 1]
    if len(negatives) > MAX_NEGATIVE_TRAIN_ROWS:
        negatives = negatives.sample(n=MAX_NEGATIVE_TRAIN_ROWS, random_state=42)
    return (
        pd.concat([negatives, positives], ignore_index=True)
        .sample(frac=1.0, random_state=42)
        .reset_index(drop=True)
    )


def build_matrices(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame):
    text_vectorizer = HashingVectorizer(
        n_features=2**18,
        alternate_sign=False,
        norm="l2",
        ngram_range=(1, 2),
        lowercase=True,
    )
    struct_hasher = FeatureHasher(n_features=2**12, input_type="dict", alternate_sign=False)

    train_text = text_vectorizer.transform(combine_text(train))
    val_text = text_vectorizer.transform(combine_text(val))
    test_text = text_vectorizer.transform(combine_text(test))

    train_struct = struct_hasher.transform(rows_to_feature_dicts(train))
    val_struct = struct_hasher.transform(rows_to_feature_dicts(val))
    test_struct = struct_hasher.transform(rows_to_feature_dicts(test))

    x_train = sparse.hstack([train_text, train_struct], format="csr")
    x_val = sparse.hstack([val_text, val_struct], format="csr")
    x_test = sparse.hstack([test_text, test_struct], format="csr")

    return text_vectorizer, struct_hasher, x_train, x_val, x_test


def fit_model(x_train, y_train):
    clf = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=1e-6,
        max_iter=20,
        early_stopping=True,
        validation_fraction=0.05,
        n_iter_no_change=3,
        random_state=42,
    )
    sample_weight = np.where(y_train == 0, NEGATIVE_WEIGHT, POSITIVE_WEIGHT)
    clf.fit(x_train, y_train, sample_weight=sample_weight)
    return clf


def confusion_metrics(y_true, y_pred) -> dict[str, float]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fpr),
        "fnr": float(fnr),
    }


def choose_threshold(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, dict[str, float]]:
    fpr_values, tpr_values, thresholds = roc_curve(y_true, scores)
    candidates: list[tuple[float, float, float, dict[str, float]]] = []
    for fpr, tpr, threshold in zip(fpr_values, tpr_values, thresholds):
        preds = (scores >= threshold).astype(int)
        metrics = confusion_metrics(y_true, preds)
        candidates.append((float(fpr), float(tpr), float(threshold), metrics))

    viable = [item for item in candidates if item[0] <= TARGET_FPR]
    if viable:
        viable.sort(key=lambda item: (item[1], -item[0], item[3]["precision"]), reverse=True)
        _, _, threshold, metrics = viable[0]
        return threshold, metrics

    candidates.sort(key=lambda item: (item[0], -item[1], item[3]["precision"]))
    _, _, threshold, metrics = candidates[0]
    return threshold, metrics


def write_report(metrics: dict[str, object]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Low-FPR Baseline Report",
        "",
        f"- Target FPR: {TARGET_FPR:.4f}",
        f"- Chosen threshold: {metrics['chosen_threshold']:.6f}",
        f"- Validation ROC-AUC: {metrics['val_auc']:.6f}",
        f"- Test ROC-AUC: {metrics['test_auc']:.6f}",
        "",
        "## Validation Metrics",
    ]

    for key, value in metrics["val_metrics_default"].items():
        lines.append(f"- default_{key}: {value}")
    for key, value in metrics["val_metrics_tuned"].items():
        lines.append(f"- tuned_{key}: {value}")

    lines.extend(["", "## Test Metrics"])
    for key, value in metrics["test_metrics_default"].items():
        lines.append(f"- default_{key}: {value}")
    for key, value in metrics["test_metrics_tuned"].items():
        lines.append(f"- tuned_{key}: {value}")

    lines.extend(
        [
            "",
            "## Notes",
            f"- Negative-class sample weight: {NEGATIVE_WEIGHT}",
            f"- Positive-class sample weight: {POSITIVE_WEIGHT}",
            "- Text features use hashed unigram/bigram representations from subject/body/sender fields.",
            "- Structured features include URL, length, HTML, and attachment signals.",
            "- This baseline is optimized for low false positives by weighting legitimate mail higher and tuning the decision threshold on validation data.",
        ]
    )

    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")


def main() -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    train = rebalance_train_frame(load_frame(TRAIN_PATH))
    val = load_frame(VAL_PATH)
    test = load_frame(TEST_PATH)

    text_vectorizer, struct_hasher, x_train, x_val, x_test = build_matrices(train, val, test)

    y_train = train["binary_label"].to_numpy()
    y_val = val["binary_label"].to_numpy()
    y_test = test["binary_label"].to_numpy()

    clf = fit_model(x_train, y_train)

    val_scores = clf.decision_function(x_val)
    test_scores = clf.decision_function(x_test)

    chosen_threshold, val_tuned_metrics = choose_threshold(y_val, val_scores)

    val_default_preds = (val_scores >= DEFAULT_DECISION_THRESHOLD).astype(int)
    val_tuned_preds = (val_scores >= chosen_threshold).astype(int)
    test_default_preds = (test_scores >= DEFAULT_DECISION_THRESHOLD).astype(int)
    test_tuned_preds = (test_scores >= chosen_threshold).astype(int)

    metrics = {
        "chosen_threshold": chosen_threshold,
        "target_fpr": TARGET_FPR,
        "negative_weight": NEGATIVE_WEIGHT,
        "positive_weight": POSITIVE_WEIGHT,
        "max_negative_train_rows": MAX_NEGATIVE_TRAIN_ROWS,
        "val_auc": float(roc_auc_score(y_val, val_scores)),
        "test_auc": float(roc_auc_score(y_test, test_scores)),
        "val_metrics_default": confusion_metrics(y_val, val_default_preds),
        "val_metrics_tuned": val_tuned_metrics,
        "test_metrics_default": confusion_metrics(y_test, test_default_preds),
        "test_metrics_tuned": confusion_metrics(y_test, test_tuned_preds),
    }

    joblib.dump(
        {
            "text_vectorizer": text_vectorizer,
            "struct_hasher": struct_hasher,
            "classifier": clf,
            "threshold": chosen_threshold,
            "default_threshold": DEFAULT_DECISION_THRESHOLD,
            "target_fpr": TARGET_FPR,
            "text_columns": TEXT_COLUMNS,
            "numeric_columns": NUMERIC_COLUMNS,
        },
        MODEL_PATH,
    )
    write_report(metrics)

    print(f"Saved model: {MODEL_PATH}")
    print(f"Saved report: {REPORT_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
