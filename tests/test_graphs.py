"""
Tests for Graph Construction & Temporal Splitting
"""
import sys
import os
import torch
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.preprocess import CANONICAL_CLASSES


def test_saved_graphs_pt():
    pt_path = os.path.join("data", "processed", "graphs.pt")
    assert os.path.exists(pt_path), f"File {pt_path} does not exist!"
    payload = torch.load(pt_path, weights_only=False)
    
    train_graphs = payload["train_graphs"]
    val_graphs = payload["val_graphs"]
    test_graphs = payload["test_graphs"]

    assert len(train_graphs) > 0
    assert len(val_graphs) > 0
    assert len(test_graphs) > 0

    # Ensure no window overlap
    train_global_ids = {g.global_window_id for g in train_graphs}
    val_global_ids = {g.global_window_id for g in val_graphs}
    test_global_ids = {g.global_window_id for g in test_graphs}

    assert len(train_global_ids.intersection(val_global_ids)) == 0
    assert len(train_global_ids.intersection(test_global_ids)) == 0
    assert len(val_global_ids.intersection(test_global_ids)) == 0

    # Ensure class coverage in train and test
    def extract_classes(graphs):
        classes = set()
        for g in graphs:
            for y_val in g.y.cpu().numpy():
                classes.add(CANONICAL_CLASSES[int(y_val)])
        return classes

    train_classes = extract_classes(train_graphs)
    test_classes = extract_classes(test_graphs)

    for cls in CANONICAL_CLASSES:
        assert cls in train_classes, f"Class {cls} missing from train split"
        assert cls in test_classes, f"Class {cls} missing from test split"


def test_random_node_relabeling():
    pt_path = os.path.join("data", "processed", "graphs.pt")
    payload = torch.load(pt_path, weights_only=False)
    sample_g = payload["train_graphs"][0]

    # Node indices must be contiguous 0..N-1
    num_nodes = sample_g.x.size(0)
    assert sample_g.edge_index.max().item() < num_nodes
    assert sample_g.edge_index.min().item() >= 0
    assert sample_g.edge_attr.size(1) == 24
    assert sample_g.x.size(1) == 8
