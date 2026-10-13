"""
Tests for Feature Extraction (No IP / Port identity leakage)
"""
import sys
import os
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.graph.features import extract_edge_features, encode_port_bucket, encode_protocol_onehot, compute_node_features


def test_no_ip_identity_leak_in_edge_features():
    df = pd.DataFrame({
        "Flow Duration": [1000, 2000],
        "Total Fwd Packets": [10, 20],
        "Total Backward Packets": [5, 15],
        "Total Length of Fwd Packets": [1000, 2000],
        "Total Length of Bwd Packets": [500, 1500],
        "Average Packet Size": [100, 150],
        "Fwd Packet Length Max": [500, 600],
        "Bwd Packet Length Max": [300, 400],
        "Flow Bytes/s": [10000, 20000],
        "Flow Packets/s": [100, 200],
        "SYN Flag Count": [1, 0],
        "ACK Flag Count": [0, 1],
        "FIN Flag Count": [0, 0],
        "RST Flag Count": [0, 0],
        "PSH Flag Count": [1, 1],
        "URG Flag Count": [0, 0],
        "protocol": [6, 17],
        "Destination Port": [80, 443],
        "src_ip": ["192.168.1.10", "10.0.0.1"],
        "dst_ip": ["192.168.1.1", "10.0.0.2"],
    })
    
    feats = extract_edge_features(df)
    assert feats.shape == (2, 24), f"Expected shape (2, 24), got {feats.shape}"
    assert not np.isnan(feats).any()
    assert not np.isinf(feats).any()


def test_port_buckets():
    ports = pd.Series([80, 443, 22, 53, 25, 8080, 50000, 1025])
    buckets = encode_port_bucket(ports)
    assert buckets.shape == (8, 7)
    # Check web bucket for port 80 and 443
    assert buckets[0, 3] == 1.0  # port 80 web
    assert buckets[1, 3] == 1.0  # port 443 web
    assert buckets[2, 4] == 1.0  # port 22 remote
    assert buckets[3, 5] == 1.0  # port 53 dns


def test_node_features_no_identity():
    node_map = {"192.168.1.1": 0, "192.168.1.2": 1, "192.168.1.3": 2}
    src_idx = np.array([0, 0, 1])
    dst_idx = np.array([1, 2, 2])
    feats = compute_node_features(node_map, src_idx, dst_idx, feature_dim=8, use_degrees=True)
    assert feats.shape == (3, 8)
    assert not np.isnan(feats).any()
