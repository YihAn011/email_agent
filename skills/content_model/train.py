from __future__ import annotations

import argparse
import csv
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import roc_auc_score, roc_curve

csv.field_size_limit(sys.maxsize)

ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = ROOT / "dataset" / "processed"
MODEL_DIR = Path(__file__).resolve().parent / "model"
REPORT_DIR = ROOT / "dataset" / "reports"
CHECKPOINT_PATH = MODEL_DIR / "training_checkpoint.pkl"


def _compose_row_text(row: dict[str, str]) -> str:
    return " ".join(
        [
            f"subject={row.get('subject', '')}",
            f"sender={row.get('sender', '')}",
            f"sender_domain={row.get('sender_domain', '')}",
            f"content_type={row.get('content_types', '')}",
            f"body={(row.get('email_text', '') or '')[:4000]}",
        ]
    )


def _iter_rows(path: Path, *, sources: set[str], skip_rows: int = 0):
    seen = 0
    with path.open(encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if sources and row.get("source", "") not in sources:
                continue
            if seen < skip_rows:
                seen += 1
                continue
            yield _compose_row_text(row), int(row["binary_label"]), row.get("source", "")


def _iter_batches(path: Path, *, sources: set[str], batch_size: int, skip_rows: int = 0):
    texts: list[str] = []
    labels: list[int] = []
    for text, label, _source in _iter_rows(path, sources=sources, skip_rows=skip_rows):
        texts.append(text)
        labels.append(label)
        if len(texts) >= batch_size:
            yield texts, np.asarray(labels, dtype=np.int32)
            texts = []
            labels = []
    if texts:
        yield texts, np.asarray(labels, dtype=np.int32)


def _count_rows(path: Path, *, sources: set[str]) -> int:
    return sum(1 for _text, _label, _source in _iter_rows(path, sources=sources))


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


def _atomic_pickle(path: Path, value: object) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("wb") as handle:
        pickle.dump(value, handle)
    temp_path.replace(path)


def _atomic_text(path: Path, value: str) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(value, encoding="utf-8")
    temp_path.replace(path)


def _build_vectorizers(word_features: int, char_features: int) -> tuple[HashingVectorizer, HashingVectorizer]:
    word_vectorizer = HashingVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        n_features=word_features,
        alternate_sign=False,
        norm="l2",
        lowercase=True,
    )
    char_vectorizer = HashingVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        n_features=char_features,
        alternate_sign=False,
        norm="l2",
        lowercase=True,
    )
    return word_vectorizer, char_vectorizer


def _features(word_vectorizer: HashingVectorizer, char_vectorizer: HashingVectorizer, texts: list[str]):
    return sparse.hstack(
        [word_vectorizer.transform(texts), char_vectorizer.transform(texts)],
        format="csr",
    )


def _load_checkpoint(*, resume: bool) -> dict | None:
    if not resume or not CHECKPOINT_PATH.exists():
        return None
    with CHECKPOINT_PATH.open("rb") as handle:
        return pickle.load(handle)


def _load_existing_model() -> tuple[HashingVectorizer, HashingVectorizer, SGDClassifier, dict]:
    paths = {
        "word_vectorizer": MODEL_DIR / "word_vectorizer.pkl",
        "char_vectorizer": MODEL_DIR / "char_vectorizer.pkl",
        "classifier": MODEL_DIR / "classifier.pkl",
        "meta": MODEL_DIR / "meta.pkl",
    }
    missing = [str(path) for path in paths.values() if not path.exists()]
    if missing:
        raise SystemExit(f"Cannot continue because model files are missing: {', '.join(missing)}")
    with paths["word_vectorizer"].open("rb") as handle:
        word_vectorizer = pickle.load(handle)
    with paths["char_vectorizer"].open("rb") as handle:
        char_vectorizer = pickle.load(handle)
    with paths["classifier"].open("rb") as handle:
        classifier = pickle.load(handle)
    with paths["meta"].open("rb") as handle:
        meta = pickle.load(handle)
    if not isinstance(word_vectorizer, HashingVectorizer) or not isinstance(char_vectorizer, HashingVectorizer):
        raise SystemExit("Existing model does not use HashingVectorizer, so it cannot be continued safely.")
    if not isinstance(classifier, SGDClassifier):
        raise SystemExit("Existing classifier is not SGDClassifier, so it cannot be continued safely.")
    return word_vectorizer, char_vectorizer, classifier, meta


def _evaluate_split(
    path: Path,
    *,
    sources: set[str],
    batch_size: int,
    word_vectorizer: HashingVectorizer,
    char_vectorizer: HashingVectorizer,
    classifier: SGDClassifier,
) -> tuple[np.ndarray, np.ndarray]:
    labels: list[np.ndarray] = []
    scores: list[np.ndarray] = []
    for texts, y_batch in _iter_batches(path, sources=sources, batch_size=batch_size):
        x_batch = _features(word_vectorizer, char_vectorizer, texts)
        labels.append(y_batch)
        scores.append(classifier.predict_proba(x_batch)[:, 1])
    return np.concatenate(labels), np.concatenate(scores)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument(
        "--sources",
        default="nazario,spamassassin,github,meajor,enron,phishing_pot,nazario_monkey,rpuv_email_dataset",
    )
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--word-features", type=int, default=2**18)
    parser.add_argument("--char-features", type=int, default=2**19)
    parser.add_argument("--alpha", type=float, default=1e-6)
    parser.add_argument("--negative-weight", type=float, default=2.0)
    parser.add_argument("--positive-weight", type=float, default=1.0)
    parser.add_argument("--checkpoint-every", type=int, default=10)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--continue-from-model", action="store_true")
    args = parser.parse_args()

    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be positive")
    if args.epochs <= 0:
        raise SystemExit("--epochs must be positive")

    sources = {item.strip() for item in args.sources.split(",") if item.strip()}
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if args.resume and args.continue_from_model:
        raise SystemExit("Use either --resume or --continue-from-model, not both.")

    checkpoint = _load_checkpoint(resume=args.resume)
    if checkpoint:
        checkpoint_sources = set(checkpoint["sources"])
        if checkpoint_sources != sources:
            raise SystemExit(
                "Checkpoint sources do not match --sources. Remove the checkpoint or use matching sources."
            )
        word_vectorizer, char_vectorizer = _build_vectorizers(
            checkpoint["word_features"],
            checkpoint["char_features"],
        )
        classifier = checkpoint["classifier"]
        start_epoch = int(checkpoint["epoch"])
        rows_seen_in_epoch = int(checkpoint["rows_seen_in_epoch"])
        global_batches = int(checkpoint["global_batches"])
        print(
            json.dumps(
                {
                    "event": "resuming_checkpoint",
                    "epoch": start_epoch + 1,
                    "rows_seen_in_epoch": rows_seen_in_epoch,
                    "global_batches": global_batches,
                }
            ),
            flush=True,
        )
    elif args.continue_from_model:
        word_vectorizer, char_vectorizer, classifier, meta = _load_existing_model()
        existing_sources = set(meta.get("sources", []))
        if existing_sources and existing_sources != sources:
            raise SystemExit(
                "Existing model sources do not match --sources. Use matching sources or retrain from scratch."
            )
        args.word_features = int(word_vectorizer.n_features)
        args.char_features = int(char_vectorizer.n_features)
        start_epoch = 0
        rows_seen_in_epoch = 0
        global_batches = 0
        print(
            json.dumps(
                {
                    "event": "continuing_existing_model",
                    "sources": sorted(sources),
                    "word_features": args.word_features,
                    "char_features": args.char_features,
                }
            ),
            flush=True,
        )
    else:
        word_vectorizer, char_vectorizer = _build_vectorizers(args.word_features, args.char_features)
        classifier = SGDClassifier(
            loss="log_loss",
            penalty="l2",
            alpha=args.alpha,
            average=True,
            random_state=42,
        )
        start_epoch = 0
        rows_seen_in_epoch = 0
        global_batches = 0

    train_path = PROCESSED_DIR / "spam_binary_train.csv"
    total_train_rows = _count_rows(train_path, sources=sources)
    started_at = time.time()

    for epoch in range(start_epoch, args.epochs):
        epoch_skip = rows_seen_in_epoch if epoch == start_epoch else 0
        if epoch_skip >= total_train_rows:
            rows_seen_in_epoch = 0
            continue
        epoch_rows = epoch_skip
        for texts, y_batch in _iter_batches(
            train_path,
            sources=sources,
            batch_size=args.batch_size,
            skip_rows=epoch_skip,
        ):
            x_batch = _features(word_vectorizer, char_vectorizer, texts)
            sample_weight = np.where(y_batch == 0, args.negative_weight, args.positive_weight)
            classifier.partial_fit(
                x_batch,
                y_batch,
                classes=np.asarray([0, 1], dtype=np.int32),
                sample_weight=sample_weight,
            )
            batch_rows = len(y_batch)
            epoch_rows += batch_rows
            global_batches += 1
            epoch_skip = 0

            if global_batches % args.checkpoint_every == 0:
                _atomic_pickle(
                    CHECKPOINT_PATH,
                    {
                        "classifier": classifier,
                        "sources": sorted(sources),
                        "epoch": epoch,
                        "rows_seen_in_epoch": epoch_rows,
                        "global_batches": global_batches,
                        "word_features": args.word_features,
                        "char_features": args.char_features,
                    },
                )
                print(
                    json.dumps(
                        {
                            "event": "checkpoint",
                            "epoch": epoch + 1,
                            "epochs": args.epochs,
                            "rows_seen_in_epoch": epoch_rows,
                            "total_train_rows": total_train_rows,
                            "global_batches": global_batches,
                        }
                    ),
                    flush=True,
                )

        rows_seen_in_epoch = 0
        _atomic_pickle(
            CHECKPOINT_PATH,
            {
                "classifier": classifier,
                "sources": sorted(sources),
                "epoch": epoch + 1,
                "rows_seen_in_epoch": 0,
                "global_batches": global_batches,
                "word_features": args.word_features,
                "char_features": args.char_features,
            },
        )
        print(
            json.dumps(
                {
                    "event": "epoch_complete",
                    "epoch": epoch + 1,
                    "epochs": args.epochs,
                    "global_batches": global_batches,
                }
            ),
            flush=True,
        )

    y_val, val_scores = _evaluate_split(
        PROCESSED_DIR / "spam_binary_val.csv",
        sources=sources,
        batch_size=args.batch_size,
        word_vectorizer=word_vectorizer,
        char_vectorizer=char_vectorizer,
        classifier=classifier,
    )
    y_test, test_scores = _evaluate_split(
        PROCESSED_DIR / "spam_binary_test.csv",
        sources=sources,
        batch_size=args.batch_size,
        word_vectorizer=word_vectorizer,
        char_vectorizer=char_vectorizer,
        classifier=classifier,
    )
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
        "training": {
            "algorithm": "HashingVectorizer+SGDClassifier(log_loss)",
            "batch_size": args.batch_size,
            "epochs": args.epochs,
            "word_features": args.word_features,
            "char_features": args.char_features,
            "alpha": args.alpha,
            "negative_weight": args.negative_weight,
            "positive_weight": args.positive_weight,
            "train_rows": total_train_rows,
            "elapsed_seconds": round(time.time() - started_at, 2),
        },
    }

    _atomic_pickle(MODEL_DIR / "word_vectorizer.pkl", word_vectorizer)
    _atomic_pickle(MODEL_DIR / "char_vectorizer.pkl", char_vectorizer)
    _atomic_pickle(MODEL_DIR / "classifier.pkl", classifier)
    _atomic_pickle(
        MODEL_DIR / "meta.pkl",
        {
            "threshold": threshold,
            "target_fpr": args.target_fpr,
            "sources": sorted(sources),
            "algorithm": "HashingVectorizer+SGDClassifier(log_loss)",
        },
    )
    _atomic_text(REPORT_DIR / "content_model_metrics.json", json.dumps(report, indent=2))
    if CHECKPOINT_PATH.exists():
        CHECKPOINT_PATH.unlink()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
