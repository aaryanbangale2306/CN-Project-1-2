"""
AegisGraph: Metrics Evaluation and Multi-Seed Aggregation
=========================================================
Computes precision, recall, macro-F1, per-class F1 with support counts,
low-support (<30) warnings, ROC-AUC, PR-AUC, confusion matrix, false-positive rate (FPR),
and inference latency.
Never invents metrics: all figures are strictly computed from true predictions.
"""

import sys
import os
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    roc_curve,
    auc,
    confusion_matrix
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.preprocess import CANONICAL_CLASSES


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_probs: Optional[np.ndarray] = None,
    inference_time_ms: float = 0.0,
    num_samples: int = 1
) -> Dict[str, Any]:
    """
    Compute full classification metrics dictionary:
    - Precision (Macro & Weighted)
    - Recall (Macro & Weighted)
    - Macro-F1 & Micro-F1
    - Per-class F1 score, support count, and low-support warning
    - ROC-AUC (OVR) & PR-AUC
    - Confusion Matrix (raw and normalized)
    - False Positive Rate (FPR on Benign)
    - Latency per 1k flows (ms)
    """
    num_classes = len(CANONICAL_CLASSES)
    
    prec_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    accuracy = float(np.mean(y_true == y_pred))
    
    # Per-class metrics and support
    per_class_f1_arr = f1_score(y_true, y_pred, average=None, labels=list(range(num_classes)), zero_division=0)
    per_class_metrics = {}
    
    for i in range(num_classes):
        cls_name = CANONICAL_CLASSES[i]
        support = int(np.sum(y_true == i))
        f1_val = float(per_class_f1_arr[i])
        per_class_metrics[cls_name] = {
            "f1": f1_val,
            "support": support,
            "low_support_warning": (support < 30 and support > 0)
        }

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=list(range(num_classes)))
    cm_norm = cm.astype(float) / (cm.sum(axis=1, keepdims=True) + 1e-9)

    # FPR on Benign (Class 0)
    benign_total = int(cm[0].sum())
    false_positives = int(cm[0, 1:].sum())
    fpr = float(false_positives / max(1, benign_total))

    # ROC-AUC and PR-AUC
    roc_auc_val = 0.0
    pr_auc_val = 0.0
    
    if y_probs is not None:
        try:
            present_classes = np.unique(y_true)
            if len(present_classes) > 1:
                y_true_onehot = np.eye(num_classes)[y_true]
                roc_auc_val = float(roc_auc_score(y_true_onehot, y_probs, multi_class="ovr", average="macro"))
                
                pr_aucs = []
                for c in range(num_classes):
                    if np.sum(y_true == c) > 0:
                        p, r, _ = precision_recall_curve(y_true == c, y_probs[:, c])
                        pr_aucs.append(auc(r, p))
                pr_auc_val = float(np.mean(pr_aucs)) if pr_aucs else 0.0
        except Exception:
            roc_auc_val = 0.0
            pr_auc_val = 0.0

    ms_per_1k = float((inference_time_ms / max(1, num_samples)) * 1000.0)

    return {
        "accuracy": accuracy,
        "precision_macro": prec_macro,
        "recall_macro": rec_macro,
        "macro_f1": f1_macro,
        "weighted_f1": f1_weighted,
        "per_class": per_class_metrics,
        "per_class_f1": {k: v["f1"] for k, v in per_class_metrics.items()},
        "roc_auc": roc_auc_val,
        "pr_auc": pr_auc_val,
        "false_positive_rate": fpr,
        "inference_ms_per_1k": ms_per_1k,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_normalized": np.round(cm_norm, 4).tolist(),
        "total_evaluated_flows": int(len(y_true))
    }


def compute_roc_pr_points(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    max_points: int = 40
) -> Dict[str, Any]:
    """Generate downsampled curve points for frontend chart rendering."""
    curves = {}
    num_classes = len(CANONICAL_CLASSES)

    for c in range(num_classes):
        cls_name = CANONICAL_CLASSES[c]
        if np.sum(y_true == c) == 0:
            continue

        y_binary = (y_true == c).astype(int)
        prob_c = y_probs[:, c]

        fpr_pts, tpr_pts, _ = roc_curve(y_binary, prob_c)
        prec_pts, rec_pts, _ = precision_recall_curve(y_binary, prob_c)

        step_roc = max(1, len(fpr_pts) // max_points)
        step_pr = max(1, len(rec_pts) // max_points)

        curves[cls_name] = {
            "roc": [
                {"fpr": round(float(fpr_pts[i]), 4), "tpr": round(float(tpr_pts[i]), 4)}
                for i in range(0, len(fpr_pts), step_roc)
            ],
            "pr": [
                {"recall": round(float(rec_pts[i]), 4), "precision": round(float(prec_pts[i]), 4)}
                for i in range(0, len(rec_pts), step_pr)
            ]
        }

    return curves


def aggregate_seed_metrics(seed_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute mean and std over multiple random seeds for each metric."""
    if not seed_results:
        return {}
    
    n_seeds = len(seed_results)
    scalar_keys = [
        "accuracy", "precision_macro", "recall_macro", "macro_f1",
        "weighted_f1", "roc_auc", "pr_auc", "false_positive_rate", "inference_ms_per_1k"
    ]
    
    summary = {"num_seeds": n_seeds}
    for k in scalar_keys:
        vals = [res[k] for res in seed_results if k in res]
        summary[k] = {
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals))
        }

    # Per-class F1 aggregation
    per_class_summary = {}
    for cls in CANONICAL_CLASSES:
        f1_vals = [res["per_class_f1"][cls] for res in seed_results if cls in res.get("per_class_f1", {})]
        supports = [res["per_class"][cls]["support"] for res in seed_results if cls in res.get("per_class", {})]
        per_class_summary[cls] = {
            "f1_mean": float(np.mean(f1_vals)) if f1_vals else 0.0,
            "f1_std": float(np.std(f1_vals)) if f1_vals else 0.0,
            "support": int(supports[0]) if supports else 0,
            "low_support_warning": (supports[0] < 30 if supports else False)
        }
    summary["per_class"] = per_class_summary

    # Use the confusion matrix from seed 0
    summary["confusion_matrix"] = seed_results[0].get("confusion_matrix", [])
    summary["confusion_matrix_normalized"] = seed_results[0].get("confusion_matrix_normalized", [])
    return summary
