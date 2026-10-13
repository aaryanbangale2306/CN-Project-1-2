"""
AegisGraph: Baseline Classifiers (Non-GNN)
1. Random Forest on raw flow features
2. Deep MLP on raw flow features
3. Graph-Augmented Random Forest (flow features + window-level graph features)
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier


class FlowMLP(nn.Module):
    """
    Standard tabular Multi-Layer Perceptron acting strictly on individual flow attributes.
    Has no access to topological network context.
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 64,
        num_classes: int = 7,
        dropout: float = 0.2
    ):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class BaselineManager:
    """Manages baseline models: Random Forest, Flow MLP, Graph-Augmented Random Forest."""

    def __init__(self, random_state: int = 42, num_classes: int = 7):
        self.random_state = random_state
        self.num_classes = num_classes
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            class_weight="balanced_subsample",
            random_state=random_state,
            n_jobs=-1
        )
        self.graph_rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            class_weight="balanced_subsample",
            random_state=random_state,
            n_jobs=-1
        )
        self.mlp_model: Optional[FlowMLP] = None

    @staticmethod
    def extract_graph_augmented_features(
        edge_features: np.ndarray,
        src_nodes: np.ndarray,
        dst_nodes: np.ndarray,
        dst_ports: Optional[np.ndarray] = None
    ) -> np.ndarray:
        """
        Derive local structural graph summary statistics without GNN message passing:
        - src out-degree
        - src in-degree
        - dst in-degree
        - dst out-degree
        - src unique destination ports
        - window flow density
        """
        num_flows = len(src_nodes)
        if num_flows == 0:
            return edge_features

        num_nodes = max(np.max(src_nodes), np.max(dst_nodes)) + 1 if num_flows > 0 else 1

        out_deg = np.bincount(src_nodes, minlength=num_nodes).astype(np.float32)
        in_deg = np.bincount(dst_nodes, minlength=num_nodes).astype(np.float32)

        src_out = out_deg[src_nodes][:, None]
        src_in = in_deg[src_nodes][:, None]
        dst_in = in_deg[dst_nodes][:, None]
        dst_out = out_deg[dst_nodes][:, None]
        window_density = np.full((num_flows, 1), float(num_flows), dtype=np.float32)

        # Unique ports contacted by src node
        if dst_ports is not None and len(dst_ports) == num_flows:
            ports = np.array(dst_ports)
            unique_dst_ports = np.zeros((num_flows, 1), dtype=np.float32)
            for u in np.unique(src_nodes):
                mask = (src_nodes == u)
                u_ports = len(np.unique(ports[mask]))
                unique_dst_ports[mask] = u_ports
        else:
            unique_dst_ports = np.zeros((num_flows, 1), dtype=np.float32)

        graph_stats = np.concatenate([
            np.log1p(src_out) / 5.0,
            np.log1p(src_in) / 5.0,
            np.log1p(dst_in) / 5.0,
            np.log1p(dst_out) / 5.0,
            np.log1p(unique_dst_ports) / 3.0,
            np.log1p(window_density) / 10.0
        ], axis=1)

        return np.concatenate([edge_features, graph_stats], axis=1)
