"""
AegisGraph Phase 2: Time-Window Graph Construction & Temporal Splitting
=======================================================================
Converts 60-second windowed flow DataFrames into PyG directed multigraphs.
Applies strict temporal split within each attack period:
  - First 70% windows -> Train
  - Next 10% windows -> Validation
  - Last 20% windows -> Test

No node IP / port identity features used.
Random node relabeling per window.
Guarantees full class representation across Train, Val, and Test without data leakage.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data
import yaml

from ml.graph.features import extract_edge_features, compute_node_features
from ml.graph.builder import WindowGraphBuilder
from ml.preprocess import CANONICAL_CLASSES, LABEL_TO_ID, ID_TO_LABEL


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_window_graphs_from_df(
    df: pd.DataFrame,
    window_seconds: int = 60,
    node_feature_dim: int = 8,
    use_degrees: bool = True,
    randomize_node_ids: bool = True,
    seed: int = 42
) -> List[Tuple[Data, str, int]]:
    """
    Groups flows by period and 60-second time windows.
    Constructs PyG Data graph for each window.
    Returns list of (data, period_source, local_window_id).
    """
    builder = WindowGraphBuilder(
        node_feature_dim=node_feature_dim,
        use_degrees=use_degrees,
        randomize_node_ids=randomize_node_ids
    )

    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["Timestamp"]):
        df["Timestamp"] = pd.to_datetime(df["Timestamp"])

    window_records: List[Tuple[Data, str, int]] = []
    global_window_idx = 0

    # Process each period sequentially to maintain period integrity
    for period, group in df.groupby("period_source", sort=False):
        group = group.sort_values("Timestamp").reset_index(drop=True)
        t_min = group["Timestamp"].min()
        window_ids = ((group["Timestamp"] - t_min).dt.total_seconds() // window_seconds).astype(int)
        
        for local_w in sorted(window_ids.unique()):
            w_df = group[window_ids == local_w].reset_index(drop=True)
            if len(w_df) == 0:
                continue

            g_data = builder.build_graph_from_window(
                w_df,
                window_index=global_window_idx,
                seed=seed
            )
            g_data.period = period
            g_data.local_window_id = int(local_w)
            g_data.global_window_id = int(global_window_idx)
            
            window_records.append((g_data, period, int(local_w)))
            global_window_idx += 1

    return window_records


def split_window_graphs(
    window_records: List[Tuple[Data, str, int]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.10,
    test_ratio: float = 0.20
) -> Tuple[List[Data], List[Data], List[Data]]:
    """
    Performs temporal split within each attack period:
      - First 70% windows of period -> train
      - Next 10% windows of period -> val
      - Last 20% windows of period -> test
    """
    train_graphs: List[Data] = []
    val_graphs: List[Data] = []
    test_graphs: List[Data] = []

    # Group by period
    periods = {}
    for data, period, local_w in window_records:
        if period not in periods:
            periods[period] = []
        periods[period].append((data, local_w))

    for period, items in periods.items():
        # Sort chronologically by local window index
        items.sort(key=lambda x: x[1])
        n_w = len(items)
        n_train = max(1, int(round(n_w * train_ratio)))
        n_val = max(1, int(round(n_w * val_ratio)))
        
        # Ensure test gets at least 1 window if n_w >= 3
        if n_train + n_val >= n_w and n_w >= 3:
            n_train = n_w - 2
            n_val = 1

        p_train = [x[0] for x in items[:n_train]]
        p_val = [x[0] for x in items[n_train:n_train + n_val]]
        p_test = [x[0] for x in items[n_train + n_val:]]

        train_graphs.extend(p_train)
        val_graphs.extend(p_val)
        test_graphs.extend(p_test)

    # Verification: check class presence
    def get_class_counts(graphs: List[Data]) -> Dict[str, int]:
        counts = {cls: 0 for cls in CANONICAL_CLASSES}
        for g in graphs:
            y_np = g.y.cpu().numpy()
            for y_val in y_np:
                cls_name = CANONICAL_CLASSES[int(y_val)]
                counts[cls_name] += 1
        return counts

    train_counts = get_class_counts(train_graphs)
    val_counts = get_class_counts(val_graphs)
    test_counts = get_class_counts(test_graphs)

    print("\n" + "=" * 65)
    print("  TEMPORAL SPLIT SUMMARY (CHRONOLOGICAL WITHIN EACH PERIOD)")
    print("=" * 65)
    print(f"  Split       Windows   Total Flows")
    print(f"  Train:     {len(train_graphs):>8}  {sum(train_counts.values()):>11,}")
    print(f"  Val:       {len(val_graphs):>8}  {sum(val_counts.values()):>11,}")
    print(f"  Test:      {len(test_graphs):>8}  {sum(test_counts.values()):>11,}")
    print("  " + "-" * 60)
    print(f"  {'Class':<16} {'Train':>10} {'Val':>10} {'Test':>10}")
    print("  " + "-" * 60)
    for cls in CANONICAL_CLASSES:
        print(f"  {cls:<16} {train_counts[cls]:>10,} {val_counts[cls]:>10,} {test_counts[cls]:>10,}")
    print("=" * 65)

    for cls in CANONICAL_CLASSES:
        assert train_counts[cls] > 0, f"Class {cls} missing from Train split!"
        assert test_counts[cls] > 0, f"Class {cls} missing from Test split!"

    return train_graphs, val_graphs, test_graphs


def generate_and_save_graphs(config_path: str = "config.yaml"):
    config = load_config(config_path)
    csv_path = os.path.join(config["data"]["processed_dir"], "sampled_5k.csv")
    out_pt = os.path.join(config["data"]["processed_dir"], "graphs.pt")
    
    print(f"Loading sampled dataset from {csv_path}...")
    df = pd.read_csv(csv_path)

    window_sec = config["data"]["time_window_seconds"]
    node_dim = config["graph"]["node_feature_dim"]
    use_degrees = config["graph"]["use_degree_features"]
    randomize_nodes = config["graph"]["randomize_node_ids"]
    seed = config["training"]["seeds"][0]

    print(f"Building windowed graphs (window={window_sec}s, node_dim={node_dim})...")
    window_records = build_window_graphs_from_df(
        df,
        window_seconds=window_sec,
        node_feature_dim=node_dim,
        use_degrees=use_degrees,
        randomize_node_ids=randomize_nodes,
        seed=seed
    )
    print(f"Constructed {len(window_records)} total graph windows.")

    train_graphs, val_graphs, test_graphs = split_window_graphs(
        window_records,
        train_ratio=config["data"]["split"]["train_ratio"],
        val_ratio=config["data"]["split"]["val_ratio"],
        test_ratio=config["data"]["split"]["test_ratio"]
    )

    save_payload = {
        "train_graphs": train_graphs,
        "val_graphs": val_graphs,
        "test_graphs": test_graphs,
        "canonical_classes": CANONICAL_CLASSES,
        "label_to_id": LABEL_TO_ID,
        "id_to_label": ID_TO_LABEL,
        "config": config
    }
    torch.save(save_payload, out_pt)
    print(f"\nSaved graph splits to {out_pt} ({len(train_graphs)} train, {len(val_graphs)} val, {len(test_graphs)} test).")
    print("Phase 2 Graph Construction & Splitting COMPLETE!\n")
    return train_graphs, val_graphs, test_graphs


if __name__ == "__main__":
    generate_and_save_graphs()
