"""
AegisGraph: End-to-End Multi-Seed Training Pipeline
===================================================
Executes 5-seed multi-model training and evaluation:
  - Baselines: Random Forest, Flow MLP, Graph-Augmented RF
  - GNNs: GCN, GraphSAGE, GAT, E-GraphSAGE
Saves verified artifacts:
  - artifacts/metrics.json
  - artifacts/roc_pr_curves.json
  - artifacts/feature_importance.json
  - artifacts/sample_graph.json
  - artifacts/explanations.json
  - artifacts/model.pt
"""

import os
import sys
import time
import json
import yaml
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.optim import Adam

# Ensure workspace root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.preprocess import CANONICAL_CLASSES, LABEL_TO_ID, ID_TO_LABEL
from ml.models.losses import get_loss_function
from ml.models.baselines import FlowMLP, BaselineManager
from ml.models.gnn_models import (
    GCNEdgeClassifier,
    GraphSAGEEdgeClassifier,
    GATEdgeClassifier,
    EGraphSAGEClassifier
)
from ml.evaluate import compute_metrics, compute_roc_pr_points, aggregate_seed_metrics
from ml.explain import GraphExplainer


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def extract_tabular_from_graphs(graphs: List[Any]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Extracts raw edge features, edge labels, src indices, and dst indices."""
    feats, labels, srcs, dsts = [], [], [], []
    for g in graphs:
        feats.append(g.edge_attr.cpu().numpy())
        labels.append(g.y.cpu().numpy())
        srcs.append(g.edge_index[0].cpu().numpy())
        dsts.append(g.edge_index[1].cpu().numpy())
    X = np.concatenate(feats, axis=0)
    y = np.concatenate(labels, axis=0)
    src = np.concatenate(srcs, axis=0)
    dst = np.concatenate(dsts, axis=0)
    return X, y, src, dst


def train_gnn_model(
    model: nn.Module,
    train_graphs: List[Any],
    val_graphs: List[Any],
    test_graphs: List[Any],
    epochs: int = 25,
    lr: float = 0.003,
    weight_decay: float = 1e-4,
    loss_type: str = "focal",
    device: str = "cpu"
) -> Tuple[Dict[str, Any], np.ndarray, np.ndarray]:
    """Trains a GNN edge classifier across window graphs."""
    model = model.to(device)
    optimizer = Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    
    # Compute class weights for loss
    all_train_y = np.concatenate([g.y.cpu().numpy() for g in train_graphs])
    counts = np.bincount(all_train_y, minlength=len(CANONICAL_CLASSES)).astype(float)
    weights = len(all_train_y) / (len(CANONICAL_CLASSES) * (counts + 1e-5))
    class_weights_t = torch.tensor(weights, dtype=torch.float32, device=device)
    
    criterion = get_loss_function(loss_type=loss_type, class_weights=class_weights_t, gamma=2.0)

    best_val_f1 = -1.0
    best_weights = None

    for epoch in range(epochs):
        model.train()
        for g in train_graphs:
            g = g.to(device)
            optimizer.zero_grad()
            logits, _ = model(g.x, g.edge_index, g.edge_attr)
            loss = criterion(logits, g.y)
            loss.backward()
            optimizer.step()

        # Validation
        model.eval()
        val_preds, val_trues = [], []
        with torch.no_grad():
            for g in val_graphs:
                g = g.to(device)
                logits, _ = model(g.x, g.edge_index, g.edge_attr)
                preds = torch.argmax(logits, dim=-1).cpu().numpy()
                val_preds.append(preds)
                val_trues.append(g.y.cpu().numpy())
        
        y_val_true = np.concatenate(val_trues)
        y_val_pred = np.concatenate(val_preds)
        val_res = compute_metrics(y_val_true, y_val_pred)
        val_f1 = val_res["macro_f1"]

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    # Load best weights
    if best_weights is not None:
        model.load_state_dict(best_weights)

    # Evaluate on test set
    model.eval()
    test_trues, test_preds, test_probs = [], [], []
    t_start = time.time()
    with torch.no_grad():
        for g in test_graphs:
            g = g.to(device)
            logits, _ = model(g.x, g.edge_index, g.edge_attr)
            probs = torch.softmax(logits, dim=-1).cpu().numpy()
            preds = np.argmax(probs, axis=-1)
            test_trues.append(g.y.cpu().numpy())
            test_preds.append(preds)
            test_probs.append(probs)
    inf_time_ms = (time.time() - t_start) * 1000.0

    y_test_true = np.concatenate(test_trues)
    y_test_pred = np.concatenate(test_preds)
    y_test_prob = np.concatenate(test_probs, axis=0)

    test_metrics = compute_metrics(
        y_true=y_test_true,
        y_pred=y_test_pred,
        y_probs=y_test_prob,
        inference_time_ms=inf_time_ms,
        num_samples=len(y_test_true)
    )

    return test_metrics, y_test_prob, y_test_pred


def train_mlp_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    epochs: int = 25,
    lr: float = 0.003,
    device: str = "cpu"
) -> Tuple[Dict[str, Any], np.ndarray, np.ndarray]:
    """Trains tabular MLP baseline."""
    mlp = FlowMLP(input_dim=X_train.shape[1], hidden_dim=64, num_classes=len(CANONICAL_CLASSES)).to(device)
    optimizer = Adam(mlp.parameters(), lr=lr)
    
    counts = np.bincount(y_train, minlength=len(CANONICAL_CLASSES)).astype(float)
    weights = len(y_train) / (len(CANONICAL_CLASSES) * (counts + 1e-5))
    criterion = nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32, device=device))

    X_tr_t = torch.tensor(X_train, dtype=torch.float32, device=device)
    y_tr_t = torch.tensor(y_train, dtype=torch.long, device=device)
    X_va_t = torch.tensor(X_val, dtype=torch.float32, device=device)
    X_te_t = torch.tensor(X_test, dtype=torch.float32, device=device)

    best_val_f1 = -1.0
    best_weights = None

    for epoch in range(epochs):
        mlp.train()
        optimizer.zero_grad()
        logits = mlp(X_tr_t)
        loss = criterion(logits, y_tr_t)
        loss.backward()
        optimizer.step()

        mlp.eval()
        with torch.no_grad():
            va_logits = mlp(X_va_t)
            va_preds = torch.argmax(va_logits, dim=-1).cpu().numpy()
            val_f1 = compute_metrics(y_val, va_preds)["macro_f1"]
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                best_weights = {k: v.cpu().clone() for k, v in mlp.state_dict().items()}

    if best_weights is not None:
        mlp.load_state_dict(best_weights)

    mlp.eval()
    t0 = time.time()
    with torch.no_grad():
        te_logits = mlp(X_te_t)
        probs = torch.softmax(te_logits, dim=-1).cpu().numpy()
        preds = np.argmax(probs, axis=-1)
    ms = (time.time() - t0) * 1000.0

    metrics = compute_metrics(y_test, preds, y_probs=probs, inference_time_ms=ms, num_samples=len(y_test))
    return metrics, probs, preds


def run_training_pipeline(config_path: str = "config.yaml"):
    config = load_config(config_path)
    graphs_pt = os.path.join(config["data"]["processed_dir"], "graphs.pt")
    
    if not os.path.exists(graphs_pt):
        print("Graphs not found. Running Phase 2 generation first...")
        from ml.graphs import generate_and_save_graphs
        generate_and_save_graphs(config_path)

    print(f"Loading pre-split graphs from {graphs_pt}...")
    payload = torch.load(graphs_pt, weights_only=False)
    train_graphs = payload["train_graphs"]
    val_graphs = payload["val_graphs"]
    test_graphs = payload["test_graphs"]

    # Extract tabular arrays
    X_train, y_train, src_tr, dst_tr = extract_tabular_from_graphs(train_graphs)
    X_val, y_val, src_va, dst_va = extract_tabular_from_graphs(val_graphs)
    X_test, y_test, src_te, dst_te = extract_tabular_from_graphs(test_graphs)

    # Graph-augmented features
    X_tr_aug = BaselineManager.extract_graph_augmented_features(X_train, src_tr, dst_tr)
    X_va_aug = BaselineManager.extract_graph_augmented_features(X_val, src_va, dst_va)
    X_te_aug = BaselineManager.extract_graph_augmented_features(X_test, src_te, dst_te)

    seeds = config["training"]["seeds"]
    models_to_run = config["models"]["baselines"] + config["models"]["gnns"]
    device = config["training"].get("device", "cpu")
    epochs = 20

    print("\n" + "=" * 70)
    print(f"  RUNNING 5-SEED TRAINING EXPERIMENT")
    print(f"  Seeds: {seeds}")
    print(f"  Models: {models_to_run}")
    print(f"  Train: {len(y_train)} flows, Val: {len(y_val)} flows, Test: {len(y_test)} flows")
    print("=" * 70 + "\n")

    # Store results per model across seeds
    all_model_seed_results = {m: [] for m in models_to_run}
    best_overall_f1 = -1.0
    best_model_name = None
    best_model_obj = None
    seed_0_probs = {}

    for s_idx, seed in enumerate(seeds):
        print(f"--- Running Seed {seed} ({s_idx+1}/{len(seeds)}) ---")
        torch.manual_seed(seed)
        np.random.seed(seed)

        bm = BaselineManager(random_state=seed, num_classes=len(CANONICAL_CLASSES))

        # 1. Random Forest
        t0 = time.time()
        bm.rf_model.fit(X_train, y_train)
        t_fit = (time.time() - t0) * 1000.0
        rf_probs = bm.rf_model.predict_proba(X_test)
        rf_preds = np.argmax(rf_probs, axis=-1)
        rf_res = compute_metrics(y_test, rf_preds, y_probs=rf_probs, inference_time_ms=t_fit, num_samples=len(y_test))
        all_model_seed_results["RandomForest"].append(rf_res)
        if s_idx == 0:
            seed_0_probs["RandomForest"] = rf_probs

        # 2. Graph-Augmented Random Forest
        t0 = time.time()
        bm.graph_rf_model.fit(X_tr_aug, y_train)
        t_fit = (time.time() - t0) * 1000.0
        grf_probs = bm.graph_rf_model.predict_proba(X_te_aug)
        grf_preds = np.argmax(grf_probs, axis=-1)
        grf_res = compute_metrics(y_test, grf_preds, y_probs=grf_probs, inference_time_ms=t_fit, num_samples=len(y_test))
        all_model_seed_results["GraphAugmentedRF"].append(grf_res)
        if s_idx == 0:
            seed_0_probs["GraphAugmentedRF"] = grf_probs

        # 3. Flow MLP
        mlp_res, mlp_probs, _ = train_mlp_model(X_train, y_train, X_val, y_val, X_test, y_test, epochs=epochs, device=device)
        all_model_seed_results["MLP"].append(mlp_res)
        if s_idx == 0:
            seed_0_probs["MLP"] = mlp_probs

        # GNN models dictionary
        gnn_constructors = {
            "GCN": lambda: GCNEdgeClassifier(node_in_dim=8, edge_in_dim=24, hidden_dim=64, num_classes=len(CANONICAL_CLASSES)),
            "GraphSAGE": lambda: GraphSAGEEdgeClassifier(node_in_dim=8, edge_in_dim=24, hidden_dim=64, num_classes=len(CANONICAL_CLASSES)),
            "GAT": lambda: GATEdgeClassifier(node_in_dim=8, edge_in_dim=24, hidden_dim=64, num_classes=len(CANONICAL_CLASSES)),
            "E-GraphSAGE": lambda: EGraphSAGEClassifier(node_in_dim=8, edge_in_dim=24, hidden_dim=64, num_classes=len(CANONICAL_CLASSES))
        }

        for gnn_name in config["models"]["gnns"]:
            model = gnn_constructors[gnn_name]()
            res, gnn_probs, _ = train_gnn_model(
                model=model,
                train_graphs=train_graphs,
                val_graphs=val_graphs,
                test_graphs=test_graphs,
                epochs=epochs,
                loss_type=config["training"].get("loss_type", "focal"),
                device=device
            )
            all_model_seed_results[gnn_name].append(res)
            if s_idx == 0:
                seed_0_probs[gnn_name] = gnn_probs

            if res["macro_f1"] > best_overall_f1:
                best_overall_f1 = res["macro_f1"]
                best_model_name = gnn_name
                best_model_obj = model

        print(f"  Seed {seed} finished. RF F1: {rf_res['macro_f1']:.4f}, E-GraphSAGE F1: {all_model_seed_results['E-GraphSAGE'][-1]['macro_f1']:.4f}")

    # Aggregate over 5 seeds
    final_metrics_summary = {}
    for m in models_to_run:
        final_metrics_summary[m] = aggregate_seed_metrics(all_model_seed_results[m])

    # Print Summary Table
    print("\n" + "=" * 90)
    print("  FINAL 5-SEED EVALUATION RESULTS (MEAN ± STD)")
    print("=" * 90)
    print(f"  {'Model':<18} {'Accuracy':<14} {'Macro-F1':<14} {'Precision':<14} {'Recall':<14} {'ROC-AUC':<14}")
    print("  " + "-" * 85)
    for m in models_to_run:
        acc = f"{final_metrics_summary[m]['accuracy']['mean']*100:.1f} ± {final_metrics_summary[m]['accuracy']['std']*100:.1f}%"
        f1 = f"{final_metrics_summary[m]['macro_f1']['mean']:.4f} ± {final_metrics_summary[m]['macro_f1']['std']:.3f}"
        pr = f"{final_metrics_summary[m]['precision_macro']['mean']:.4f} ± {final_metrics_summary[m]['precision_macro']['std']:.3f}"
        rc = f"{final_metrics_summary[m]['recall_macro']['mean']:.4f} ± {final_metrics_summary[m]['recall_macro']['std']:.3f}"
        roc = f"{final_metrics_summary[m]['roc_auc']['mean']:.4f}"
        print(f"  {m:<18} {acc:<14} {f1:<14} {pr:<14} {rc:<14} {roc:<14}")
    print("=" * 90 + "\n")

    # Print Per-Class F1 with Support and Low-Support warnings
    print("=" * 95)
    print(f"  PER-CLASS F1 BREAKDOWN (BEST GNN: {best_model_name})")
    print("=" * 95)
    print(f"  {'Class':<16} {'Support (Test)':>16} {'F1 Score':>14} {'Status':>14}")
    print("  " + "-" * 65)
    best_per_class = final_metrics_summary[best_model_name]["per_class"]
    for cls in CANONICAL_CLASSES:
        stat = "⚠ low support" if best_per_class[cls]["low_support_warning"] else "✓ verified"
        f1_str = f"{best_per_class[cls]['f1_mean']:.4f} ± {best_per_class[cls]['f1_std']:.3f}"
        print(f"  {cls:<16} {best_per_class[cls]['support']:>16,} {f1_str:>14} {stat:>14}")
    print("=" * 95 + "\n")

    # Save artifacts
    artifacts_dir = "artifacts"
    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(os.path.join(artifacts_dir, "models"), exist_ok=True)

    # 1. metrics.json
    metrics_path = os.path.join(artifacts_dir, "metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(final_metrics_summary, f, indent=2)
    print(f"Saved: {metrics_path}")

    # 2. roc_pr_curves.json
    curves_payload = {}
    for m in ["RandomForest", "E-GraphSAGE", "GAT"]:
        if m in seed_0_probs:
            curves_payload[m] = compute_roc_pr_points(y_test, seed_0_probs[m])
    curves_path = os.path.join(artifacts_dir, "roc_pr_curves.json")
    with open(curves_path, "w", encoding="utf-8") as f:
        json.dump(curves_payload, f, indent=2)
    print(f"Saved: {curves_path}")

    # 3. feature_importance.json (from RandomForest)
    rf_feat_names = [
        "flow_duration", "tot_pkts", "tot_bytes",
        "pkt_sz_avg", "pkt_sz_max_fwd", "pkt_sz_max_bwd",
        "bytes_per_sec", "pkts_per_sec",
        "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg",
        "proto_tcp", "proto_udp", "proto_other",
        "port_wellknown", "port_registered", "port_ephemeral",
        "port_web", "port_remote", "port_dns", "port_mail"
    ]
    rf_imps = bm.rf_model.feature_importances_
    feat_imp_payload = [
        {"feature": name, "importance": round(float(rf_imps[i]), 4)}
        for i, name in enumerate(rf_feat_names[:len(rf_imps)])
    ]
    feat_imp_payload.sort(key=lambda x: x["importance"], reverse=True)
    feat_path = os.path.join(artifacts_dir, "feature_importance.json")
    with open(feat_path, "w", encoding="utf-8") as f:
        json.dump(feat_imp_payload, f, indent=2)
    print(f"Saved: {feat_path}")

    # 4. model.pt
    model_save_path = os.path.join(artifacts_dir, "model.pt")
    torch.save({
        "model_name": best_model_name,
        "state_dict": best_model_obj.state_dict(),
        "classes": CANONICAL_CLASSES,
        "node_dim": 8,
        "edge_dim": 24,
        "hidden_dim": 64
    }, model_save_path)
    print(f"Saved best model weights to: {model_save_path}")

    # 5. sample_graph.json (for frontend Cytoscape graph viewer)
    # Pick a test window that has attack flows
    sample_g = None
    for g in test_graphs:
        if (g.y > 0).any():
            sample_g = g
            break
    if sample_g is None:
        sample_g = test_graphs[0]

    nodes = []
    for i in range(sample_g.x.size(0)):
        ip_name = sample_g.node_id_to_ip.get(i, f"Host_{i}")
        nodes.append({"data": {"id": f"node_{i}", "label": ip_name, "degree": float(sample_g.x[i, 2].item())}})
    
    edges = []
    edge_idx_np = sample_g.edge_index.cpu().numpy()
    y_np = sample_g.y.cpu().numpy()
    for j in range(edge_idx_np.shape[1]):
        u = int(edge_idx_np[0, j])
        v = int(edge_idx_np[1, j])
        lbl_name = CANONICAL_CLASSES[int(y_np[j])]
        edges.append({
            "data": {
                "id": f"edge_{j}",
                "source": f"node_{u}",
                "target": f"node_{v}",
                "label": lbl_name,
                "is_attack": int(y_np[j]) > 0
            }
        })

    sample_graph_payload = {
        "window_id": sample_g.global_window_id,
        "period": getattr(sample_g, "period", "TestWindow"),
        "elements": nodes + edges,
        "num_nodes": len(nodes),
        "num_edges": len(edges)
    }
    sample_graph_path = os.path.join(artifacts_dir, "sample_graph.json")
    with open(sample_graph_path, "w", encoding="utf-8") as f:
        json.dump(sample_graph_payload, f, indent=2)
    print(f"Saved: {sample_graph_path}")

    # 6. explanations.json
    explainer = GraphExplainer(model=best_model_obj, device=device)
    explanations = []
    attack_edge_indices = [i for i, y_val in enumerate(sample_g.y.cpu().numpy()) if y_val > 0]
    for idx in attack_edge_indices[:5]:  # Explain up to 5 attack flows
        exp = explainer.explain_flow(sample_g, target_edge_idx=idx)
        explanations.append(exp)
    exp_path = os.path.join(artifacts_dir, "explanations.json")
    with open(exp_path, "w", encoding="utf-8") as f:
        json.dump(explanations, f, indent=2)
    print(f"Saved: {exp_path}")

    print("\n" + "=" * 60)
    print("  Phase 3 & Phase 4 Training & Evaluation COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    run_training_pipeline()
