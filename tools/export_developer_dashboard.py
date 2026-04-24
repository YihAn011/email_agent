from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


def build_dashboard(runs: list[dict[str, Any]], out_path: Path) -> Path:
    if len(runs) < 2:
        raise ValueError("At least 2 finished tests are required to generate a dashboard.")

    mins = {k: min(float(r.get(k, 0.0)) for r in runs) for k in ["runtime_min", "fpr", "accuracy", "precision", "recall", "f1"]}
    maxs = {k: max(float(r.get(k, 0.0)) for r in runs) for k in ["runtime_min", "fpr", "accuracy", "precision", "recall", "f1"]}
    max_applied = max(int(r.get("llm_applied", 0)) for r in runs) or 1

    def hi(value: float, key: str) -> float:
        lower, upper = mins[key], maxs[key]
        if upper == lower:
            return 1.0
        return (value - lower) / (upper - lower)

    def lo(value: float, key: str) -> float:
        lower, upper = mins[key], maxs[key]
        if upper == lower:
            return 1.0
        return (upper - value) / (upper - lower)

    for run in runs:
        run["composite"] = (
            0.28 * hi(float(run["f1"]), "f1")
            + 0.18 * hi(float(run["recall"]), "recall")
            + 0.18 * lo(float(run["fpr"]), "fpr")
            + 0.10 * hi(float(run["accuracy"]), "accuracy")
            + 0.08 * hi(float(run["precision"]), "precision")
            + 0.10 * lo(float(run["runtime_min"]), "runtime_min")
            + 0.08 * (int(run["llm_applied"]) / max_applied)
        )

    best = max(runs, key=lambda item: float(item["composite"]))
    width, height = 2400, 1750
    image = Image.new("RGB", (width, height), "#F6F3ED")
    draw = ImageDraw.Draw(image)
    regular_font = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold_font = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

    def font(size: int, bold: bool = False) -> Any:
        try:
            return ImageFont.truetype(bold_font if bold else regular_font, size)
        except Exception:
            return ImageFont.load_default()

    title_font = font(48, True)
    subtitle_font = font(22)
    h2_font = font(30, True)
    h3_font = font(20, True)
    text_font = font(18)
    small_font = font(16)
    tiny_font = font(14)

    bg = "#FFFFFF"
    border = "#D8D1C6"
    text = "#1F2937"
    muted = "#667085"
    grid = "#E9E2D8"

    def rr(box: tuple[int, int, int, int], fill: str = bg, outline: str = border, r: int = 18, width_px: int = 2) -> None:
        draw.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width_px)

    def label(x: float, y: float, s: str, f: Any = text_font, fill: str = text, anchor: str | None = None) -> None:
        draw.text((x, y), s, font=f, fill=fill, anchor=anchor)

    def panel_title(box: tuple[int, int, int, int], s: str) -> None:
        x0, y0, _x1, _y1 = box
        label(x0 + 20, y0 + 14, s, h2_font)

    def text_wrap(s: str, f: Any, max_width: int) -> list[str]:
        words = s.split()
        lines: list[str] = []
        current = ""
        for word in words:
            trial = word if not current else f"{current} {word}"
            if draw.textlength(trial, font=f) <= max_width:
                current = trial
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines

    margin = 26
    gutter = 20
    row1_y, row1_h = 110, 390
    col4 = (width - 2 * margin - 3 * gutter) // 4
    b1 = (margin, row1_y, margin + col4, row1_y + row1_h)
    b2 = (margin + col4 + gutter, row1_y, margin + 2 * col4 + gutter, row1_y + row1_h)
    b3 = (margin + 2 * (col4 + gutter), row1_y, margin + 3 * col4 + 2 * gutter, row1_y + row1_h)
    b4 = (margin + 3 * (col4 + gutter), row1_y, width - margin, row1_y + row1_h)
    row2_y, row2_h = 520, 420
    left2_w, mid2_w = 1260, 470
    b5 = (margin, row2_y, margin + left2_w, row2_y + row2_h)
    b6 = (margin + left2_w + gutter, row2_y, margin + left2_w + gutter + mid2_w, row2_y + row2_h)
    b7 = (margin + left2_w + 2 * gutter + mid2_w, row2_y, width - margin, row2_y + row2_h)
    row3_y, row3_h = 960, 760
    b8 = (margin, row3_y, margin + 1320, row3_y + row3_h)
    b9 = (margin + 1320 + gutter, row3_y, width - margin, row3_y + row3_h)

    label(36, 24, "Developer Run Comparison Dashboard", title_font)
    label(
        38,
        78,
        f"{len(runs)} finished tests | one-page PPT-ready comparison across runtime, quality, review behavior, error profile, and composite ranking",
        subtitle_font,
        fill=muted,
    )

    rr(b1)
    panel_title(b1, "Runtime (minutes)")
    x0, y0, x1, y1 = b1
    cx0, cy0, cx1, cy1 = x0 + 55, y0 + 70, x1 - 18, y1 - 34
    for i in range(5):
        yy = cy0 + i * (cy1 - cy0) / 4
        draw.line((cx0, yy, cx1, yy), fill=grid, width=1)
    draw.line((cx0, cy1, cx1, cy1), fill="#B8B0A4", width=2)
    space = (cx1 - cx0) / len(runs)
    bw = min(58, max(28, space * 0.45))
    max_runtime = max(max(float(run["runtime_min"]) for run in runs) * 1.05, 60.0)
    for i, run in enumerate(runs):
        cx = cx0 + space * (i + 0.5)
        top = cy1 - (float(run["runtime_min"]) / max_runtime) * (cy1 - cy0 - 10)
        draw.rounded_rectangle((cx - bw / 2, top, cx + bw / 2, cy1), radius=12, fill=str(run["color"]))
        label(cx, top - 12, f"{float(run['runtime_min']):.1f}", small_font, anchor="ms")
        label(cx, cy1 + 10, str(run["name"]), small_font, anchor="ma")

    rr(b2)
    panel_title(b2, "FPR vs Recall")
    x0, y0, x1, y1 = b2
    cx0, cy0, cx1, cy1 = x0 + 70, y0 + 78, x1 - 26, y1 - 48
    fpr_values = [float(run["fpr"]) for run in runs]
    recall_values = [float(run["recall"]) for run in runs]
    xmin = max(0.0, min(fpr_values) - 0.0010)
    xmax = max(fpr_values) + 0.0010
    ymin = max(0.0, min(recall_values) - 0.0150)
    ymax = min(1.0, max(recall_values) + 0.0100)
    for i in range(6):
        xx = cx0 + i * (cx1 - cx0) / 5
        yy = cy0 + i * (cy1 - cy0) / 5
        draw.line((xx, cy0, xx, cy1), fill=grid, width=1)
        draw.line((cx0, yy, cx1, yy), fill=grid, width=1)
        label(xx, cy1 + 8, f"{xmin + i * (xmax - xmin) / 5:.3f}", tiny_font, anchor="ma")
        label(cx0 - 10, yy, f"{ymax - i * (ymax - ymin) / 5:.3f}", tiny_font, anchor="rm")
    draw.line((cx0, cy1, cx1, cy1), fill="#B8B0A4", width=2)
    draw.line((cx0, cy0, cx0, cy1), fill="#B8B0A4", width=2)
    label((cx0 + cx1) / 2, cy1 + 28, "False Positive Rate", small_font, anchor="ma")
    label(x0 + 16, (cy0 + cy1) / 2, "Recall", small_font)
    for i, run in enumerate(runs):
        px = cx0 + (float(run["fpr"]) - xmin) / max(0.0001, xmax - xmin) * (cx1 - cx0)
        py = cy1 - (float(run["recall"]) - ymin) / max(0.0001, ymax - ymin) * (cy1 - cy0)
        draw.ellipse((px - 10, py - 10, px + 10, py + 10), fill=str(run["color"]), outline="white", width=2)
        if px > cx1 - 80:
            label(px - 10, py - 2, str(run["model_label"]), small_font, anchor="rs")
        else:
            vertical_offset = -18 if i % 2 == 0 else 12
            label(px + 14, py + vertical_offset, str(run["model_label"]), small_font)

    rr(b3)
    panel_title(b3, "LLM Review Activity")
    x0, y0, x1, y1 = b3
    cx0, cy0, cx1, cy1 = x0 + 42, y0 + 88, x1 - 34, y1 - 38
    max_llm = max(max(int(run.get("llm_used", 0)), int(run.get("llm_applied", 0)), int(run.get("llm_errors", 0))) for run in runs) or 1
    group_width = (cx1 - cx0) / len(runs)
    metric_bar_width = max(12, min(18, group_width * 0.18))
    for i, (name, color) in enumerate([("Used", "#5B8FB9"), ("Accepted", "#111827"), ("Errors", "#C1121F")]):
        yy = y0 + 18 + i * 22
        draw.rounded_rectangle((x1 - 130, yy + 3, x1 - 116, yy + 17), radius=4, fill=color)
        label(x1 - 108, yy, name, small_font)
    for i, run in enumerate(runs):
        gx = cx0 + i * group_width
        xs = [gx + group_width * 0.18, gx + group_width * 0.40, gx + group_width * 0.62]
        values = [int(run.get("llm_used", 0)), int(run.get("llm_applied", 0)), int(run.get("llm_errors", 0))]
        colors = ["#5B8FB9", "#111827", "#C1121F"]
        for x_pos, value, color in zip(xs, values, colors):
            left = x_pos
            right = x_pos + metric_bar_width
            top = cy1 - (value / max_llm) * (cy1 - cy0)
            draw.rounded_rectangle((left, top, right, cy1), radius=7, fill=color)
            label((left + right) / 2, top - 8, str(value), tiny_font, anchor="ms")
        label(gx + group_width / 2, cy1 + 10, str(run["name"]), small_font, anchor="ma")

    rr(b4)
    panel_title(b4, "Change vs Baseline")
    x0, y0, x1, y1 = b4
    halves = [
        ("Delta FPR", "delta_fpr", x0 + 18, y0 + 96, (x0 + x1) // 2 - 14, y1 - 44, -0.020, 0.0),
        ("Delta Recall", "delta_recall", (x0 + x1) // 2 + 14, y0 + 96, x1 - 18, y1 - 44, -0.030, 0.0),
    ]
    for title_text, key, sx0, sy0, sx1, sy1, min_value, max_value in halves:
        label((sx0 + sx1) / 2, y0 + 54, title_text, h3_font, anchor="ma")
        zero_y = sy0 + (max_value - 0) / max(0.0001, max_value - min_value) * (sy1 - sy0)
        draw.line((sx0 + 16, zero_y, sx1 - 16, zero_y), fill="#B8B0A4", width=2)
        space = (sx1 - sx0 - 32) / len(runs)
        bw = max(12, min(18, space * 0.35))
        for i, run in enumerate(runs):
            cx = sx0 + 16 + space * (i + 0.5)
            value = float(run.get(key, 0.0))
            yy = sy0 + (max_value - value) / max(0.0001, max_value - min_value) * (sy1 - sy0)
            top = min(yy, zero_y)
            bottom = max(yy, zero_y)
            draw.rounded_rectangle((cx - bw / 2, top, cx + bw / 2, bottom), radius=7, fill=str(run["color"]))
            label(cx, top - 8, f"{value:.4f}", tiny_font, anchor="ms")
            label(cx, sy1 + 8, str(run["name"]), tiny_font, anchor="ma")

    rr(b5)
    panel_title(b5, "Core Quality Metrics")
    x0, y0, x1, y1 = b5
    legend_x, legend_y = x1 - 230, y0 + 16
    for i, run in enumerate(runs):
        yy = legend_y + i * 24
        draw.rounded_rectangle((legend_x, yy + 3, legend_x + 14, yy + 17), radius=4, fill=str(run["color"]))
        label(legend_x + 22, yy, str(run["model_label"]), small_font)
    cx0, cy0, cx1, cy1 = x0 + 24, y0 + 90, x1 - 300, y1 - 36
    group_width = (cx1 - cx0) / 4
    for group_index, (name, key) in enumerate([("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall"), ("F1", "f1")]):
        gx = cx0 + group_index * group_width
        bw = max(14, min(22, group_width * 0.12))
        for run_index, run in enumerate(runs):
            left = gx + 16 + run_index * (bw + 9)
            right = left + bw
            top = cy1 - float(run.get(key, 0.0)) * (cy1 - cy0 - 8)
            draw.rounded_rectangle((left, top, right, cy1), radius=7, fill=str(run["color"]))
            label((left + right) / 2, top - 8, f"{float(run.get(key, 0.0)):.3f}", tiny_font, anchor="ms")
        label(gx + group_width / 2, cy1 + 12, name, small_font, anchor="ma")

    rr(b6)
    panel_title(b6, "Error Volume")
    x0, y0, x1, y1 = b6
    legend_left, legend_top = x1 - 110, y0 + 20
    draw.rounded_rectangle((legend_left, legend_top, legend_left + 14, legend_top + 14), radius=4, fill="#D95D76")
    label(legend_left + 22, legend_top - 2, "FP", small_font)
    draw.rounded_rectangle((legend_left, legend_top + 24, legend_left + 14, legend_top + 38), radius=4, fill="#577590")
    label(legend_left + 22, legend_top + 22, "FN", small_font)
    cx0, cy0, cx1, cy1 = x0 + 48, y0 + 84, x1 - 18, y1 - 36
    max_total = max(int(run.get("fp", 0)) + int(run.get("fn", 0)) for run in runs) or 1
    space = (cx1 - cx0) / len(runs)
    bw = min(58, max(26, space * 0.45))
    for i, run in enumerate(runs):
        cx = cx0 + space * (i + 0.5)
        fn_height = (int(run.get("fn", 0)) / max_total) * (cy1 - cy0)
        fp_height = (int(run.get("fp", 0)) / max_total) * (cy1 - cy0)
        y_fn = cy1 - fn_height
        y_fp = y_fn - fp_height
        draw.rounded_rectangle((cx - bw / 2, y_fn, cx + bw / 2, cy1), radius=10, fill="#577590")
        draw.rounded_rectangle((cx - bw / 2, y_fp, cx + bw / 2, y_fn), radius=10, fill="#D95D76")
        label(cx, y_fp - 10, str(int(run.get("fp", 0)) + int(run.get("fn", 0))), small_font, anchor="ms")
        label(cx, cy1 + 10, str(run["name"]), small_font, anchor="ma")

    rr(b7, fill="#FBF8F1")
    panel_title(b7, "Interpretation Highlights")
    x0, y0, x1, y1 = b7
    lowest_fpr = min(runs, key=lambda item: float(item["fpr"]))
    fastest = min(runs, key=lambda item: float(item["runtime_min"]))
    highest_f1 = max(runs, key=lambda item: float(item["f1"]))
    most_active = max(runs, key=lambda item: int(item["llm_applied"]))
    notes = [
        f"Lowest FPR: {lowest_fpr['model_label']} ({float(lowest_fpr['fpr']):.4f}).",
        f"Fastest runtime: {fastest['model_label']} ({float(fastest['runtime_min']):.1f} min).",
        f"Best F1 in this export set: {highest_f1['model_label']} ({float(highest_f1['f1']):.4f}).",
        f"Most active reviewer: {most_active['model_label']} ({int(most_active['llm_applied'])} accepted).",
        f"Overall best composite: {best['name']} / {best['model_label']} ({float(best['composite']):.3f}).",
        "Read composite as the best all-around tradeoff, not the best on every single metric.",
    ]
    yy = y0 + 76
    max_text_width = (x1 - x0) - 68
    for line in notes:
        lines = text_wrap(line, text_font, max_text_width)
        draw.rounded_rectangle((x0 + 20, yy + 6, x0 + 30, yy + 16), radius=3, fill="#8A6E47")
        for index, wrapped in enumerate(lines):
            label(x0 + 42, yy + index * 22, wrapped, text_font)
        yy += max(42, len(lines) * 22 + 12)

    rr(b8)
    panel_title(b8, "Executive Summary Table")
    x0, y0, x1, y1 = b8
    headers = ["Run", "Model", "Time", "Acc", "FPR", "Recall", "F1", "LLM", "Accpt", "Comp"]
    col_widths = [70, 220, 84, 74, 74, 84, 74, 74, 74, 84]
    sx, sy, row_h = x0 + 18, y0 + 66, 38
    xx = sx
    for header, width_value in zip(headers, col_widths):
        draw.rounded_rectangle((xx, sy, xx + width_value, sy + row_h), radius=8, fill="#ECE5D9")
        label(xx + 8, sy + 9, header, small_font)
        xx += width_value + 6
    for row_index, run in enumerate(runs):
        yy = sy + (row_index + 1) * (row_h + 8)
        xx = sx
        total_seconds = max(0, int(round(float(run["runtime_min"]) * 60.0)))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, _seconds = divmod(remainder, 60)
        row_values = [
            str(run["name"]),
            str(run["model_label"]),
            f"{hours}h {minutes:02d}m",
            f"{float(run['accuracy']):.4f}",
            f"{float(run['fpr']):.4f}",
            f"{float(run['recall']):.4f}",
            f"{float(run['f1']):.4f}",
            str(int(run["llm_used"])),
            str(int(run["llm_applied"])),
            f"{float(run['composite']):.3f}",
        ]
        for col_index, (value, width_value) in enumerate(zip(row_values, col_widths)):
            fill = "#FFFFFF" if row_index % 2 == 0 else "#FAF8F3"
            draw.rounded_rectangle((xx, yy, xx + width_value, yy + row_h), radius=8, fill=fill, outline="#ECE6DB")
            label(xx + 8, yy + 9, value, small_font, fill=str(run["color"]) if col_index == 0 else text)
            xx += width_value + 6
    footer = "Composite weights: F1 28%, Recall 18%, FPR 18%, Accuracy 10%, Precision 8%, Runtime 10%, LLM accepted 8%"
    label(x0 + 24, y1 - 42, footer, tiny_font, fill=muted)

    rr(b9)
    panel_title(b9, "Overall Best Model / Composite Ranking")
    x0, y0, x1, y1 = b9
    label(x0 + 24, y0 + 58, f"Best overall in this export: {best['name']} ({best['model_label']})", h3_font, fill=str(best["color"]))
    intro = "This panel fuses quality, false-positive control, runtime, and reviewer usefulness into one score."
    for i, wrapped in enumerate(text_wrap(intro, small_font, (x1 - x0) - 48)):
        label(x0 + 24, y0 + 88 + i * 20, wrapped, small_font, fill=muted)
    cx0, cy0, cx1, cy1 = x0 + 55, y0 + 170, x1 - 26, y0 + 470
    ordered = sorted(runs, key=lambda item: float(item["composite"]), reverse=True)
    max_composite = max(float(run["composite"]) for run in ordered) * 1.08
    space = (cx1 - cx0) / len(ordered)
    bw = min(70, max(28, space * 0.45))
    for i, run in enumerate(ordered):
        cx = cx0 + space * (i + 0.5)
        top = cy1 - (float(run["composite"]) / max_composite) * (cy1 - cy0)
        draw.rounded_rectangle((cx - bw / 2, top, cx + bw / 2, cy1), radius=12, fill=str(run["color"]))
        if run["name"] == best["name"]:
            draw.rounded_rectangle((cx - bw / 2 - 4, top - 4, cx + bw / 2 + 4, cy1 + 4), radius=14, outline="#111827", width=4)
        label(cx, top - 10, f"{float(run['composite']):.3f}", small_font, anchor="ms")
        label(cx, cy1 + 10, str(run["name"]), small_font, anchor="ma")
        label(cx, cy1 + 30, str(run["model_label"]), tiny_font, anchor="ma")
    label(x0 + 24, y0 + 520, "Ranking", h3_font)
    yy = y0 + 556
    for index, run in enumerate(ordered, start=1):
        ranking_text = f"{index}. {run['name']}  {run['model_label']}  score {float(run['composite']):.3f}"
        label(x0 + 28, yy, ranking_text, text_font, fill=str(run["color"]))
        yy += 34
    label(x0 + 24, y1 - 36, "Use this as the best all-around tradeoff for the exported set of finished tests.", tiny_font, fill=muted)
    label(width - 30, height - 24, f"Generated from developer mode on {time.strftime('%Y-%m-%d %H:%M:%S')}", tiny_font, fill=muted, anchor="ra")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(out_path)
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    runs = json.loads(input_path.read_text(encoding="utf-8"))
    build_dashboard(runs, output_path)
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
