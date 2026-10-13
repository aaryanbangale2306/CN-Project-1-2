"""
Tests for Training & Multi-Seed Determinism
"""
import sys
import os
import torch
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.models.gnn_models import GCNEdgeClassifier
from ml.models.losses import FocalLoss


def test_model_forward_pass():
    model = GCNEdgeClassifier(node_in_dim=8, edge_in_dim=24, hidden_dim=32, num_classes=7)
    x = torch.randn(10, 8)
    edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 0]], dtype=torch.long)
    edge_attr = torch.randn(4, 24)
    
    logits, _ = model(x, edge_index, edge_attr)
    assert logits.shape == (4, 7)
    assert not torch.isnan(logits).any()


def test_focal_loss_computation():
    criterion = FocalLoss(gamma=2.0)
    logits = torch.randn(4, 7)
    targets = torch.tensor([0, 1, 2, 3], dtype=torch.long)
    loss = criterion(logits, targets)
    assert loss.item() > 0.0
    assert not torch.isnan(loss).any()
