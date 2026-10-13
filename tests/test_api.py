"""
Smoke Tests for Backend FastAPI Service
"""
import sys
import os
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.main import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "classes" in data
    assert len(data["classes"]) == 7


def test_metrics_endpoint():
    res = client.get("/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "RandomForest" in data
    assert "accuracy" in data["RandomForest"]


def test_graph_endpoint():
    res = client.get("/graph")
    assert res.status_code == 200
    data = res.json()
    assert "elements" in data
    assert len(data["elements"]) > 0


def test_models_endpoint():
    res = client.get("/models")
    assert res.status_code == 200
    data = res.json()
    assert "trained" in data
    assert data["trained"] is True


def test_predict_endpoint():
    payload = {
        "duration_ms": 150.0,
        "total_fwd_packets": 4,
        "total_bwd_packets": 2,
        "fwd_bytes": 240.0,
        "bwd_bytes": 800.0,
        "protocol": 6,
        "dst_port": 80,
        "syn_flag": 1,
        "ack_flag": 1,
        "fin_flag": 0,
        "rst_flag": 0,
        "psh_flag": 1,
        "urg_flag": 0
    }
    res = client.post("/predict", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "prediction" in data
    assert "is_attack" in data
    assert "confidence" in data
