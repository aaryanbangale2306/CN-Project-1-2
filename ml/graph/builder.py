"""
AegisGraph: Windowed Graph Construction
Converts flow DataFrames into PyTorch Geometric Data objects (directed multigraphs).
IP addresses are strictly mapped to temporary window-scoped node IDs with random relabeling.
"""

from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data
import networkx as nx

from ml.graph.features import extract_edge_features, compute_node_features
from ml.data.dataset import LABEL_TO_ID, CANONICAL_CLASSES


class WindowGraphBuilder:
    """Builds PyTorch Geometric Data instances from windowed flow DataFrames."""

    def __init__(
        self,
        node_feature_dim: int = 8,
        use_degrees: bool = True,
        randomize_node_ids: bool = True
    ):
        self.node_feature_dim = node_feature_dim
        self.use_degrees = use_degrees
        self.randomize_node_ids = randomize_node_ids

    def build_graph_from_window(
        self,
        window_df: pd.DataFrame,
        window_index: int = 0,
        seed: Optional[int] = None
    ) -> Data:
        """
        Convert a contiguous window DataFrame into a PyG Data object.
        Edge indices point to window-scoped node IDs.
        """
        if len(window_df) == 0:
            raise ValueError("Cannot build graph from empty window DataFrame.")

        # Identify unique host IPs in this window
        src_ips = window_df["src_ip"].astype(str).values
        dst_ips = window_df["dst_ip"].astype(str).values
        unique_ips = np.unique(np.concatenate([src_ips, dst_ips]))
        
        # Optional random permutation to prevent memorizing node ordering
        if self.randomize_node_ids:
            rng = np.random.RandomState(seed + window_index if seed is not None else None)
            shuffled_ips = rng.permutation(unique_ips)
        else:
            shuffled_ips = unique_ips

        ip_to_node_id = {ip: idx for idx, ip in enumerate(shuffled_ips)}
        node_id_to_ip = {idx: ip for ip, idx in ip_to_node_id.items()}

        src_indices = np.array([ip_to_node_id[ip] for ip in src_ips], dtype=np.int64)
        dst_indices = np.array([ip_to_node_id[ip] for ip in dst_ips], dtype=np.int64)

        edge_index = torch.tensor(np.stack([src_indices, dst_indices]), dtype=torch.long)

        # Edge features
        edge_feat_np = extract_edge_features(window_df)
        edge_attr = torch.tensor(edge_feat_np, dtype=torch.float32)

        # Node features (degree stats + constant)
        node_feat_np = compute_node_features(
            ip_to_node_id,
            src_indices,
            dst_indices,
            feature_dim=self.node_feature_dim,
            use_degrees=self.use_degrees
        )
        x = torch.tensor(node_feat_np, dtype=torch.float32)

        # Labels
        if "Label_ID" in window_df.columns:
            y = torch.tensor(window_df["Label_ID"].values, dtype=torch.long)
        elif "Canonical_Label" in window_df.columns:
            y = torch.tensor(window_df["Canonical_Label"].map(LABEL_TO_ID).values, dtype=torch.long)
        else:
            y = torch.zeros(len(window_df), dtype=torch.long)

        # Construct PyG Data container
        data = Data(
            x=x,
            edge_index=edge_index,
            edge_attr=edge_attr,
            y=y
        )
        
        # Keep non-tensor metadata for debugging & explainability
        data.num_flows = len(window_df)
        data.window_id = window_index
        data.ip_to_node_id = ip_to_node_id
        data.node_id_to_ip = node_id_to_ip
        data.raw_labels = window_df["Canonical_Label"].tolist() if "Canonical_Label" in window_df.columns else ["Benign"] * len(window_df)
        data.flow_metadata = {
            "timestamps": window_df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").tolist() if "Timestamp" in window_df.columns else [],
            "src_ips": src_ips.tolist(),
            "dst_ips": dst_ips.tolist(),
            "src_ports": window_df["src_port"].tolist() if "src_port" in window_df.columns else [],
            "dst_ports": window_df["dst_port"].tolist() if "dst_port" in window_df.columns else []
        }

        return data

    def to_networkx(self, data: Data) -> nx.MultiDiGraph:
        """Convert PyG Data object to NetworkX MultiDiGraph for topology analysis."""
        G = nx.MultiDiGraph()
        
        for i in range(data.x.size(0)):
            ip = data.node_id_to_ip.get(i, f"Host_{i}")
            G.add_node(i, ip=ip, features=data.x[i].cpu().numpy())

        edge_index_np = data.edge_index.cpu().numpy()
        edge_attr_np = data.edge_attr.cpu().numpy()
        y_np = data.y.cpu().numpy()

        for j in range(edge_index_np.shape[1]):
            u, v = int(edge_index_np[0, j]), int(edge_index_np[1, j])
            label_name = CANONICAL_CLASSES[int(y_np[j])]
            G.add_edge(
                u, v,
                key=j,
                flow_id=j,
                label=label_name,
                label_id=int(y_np[j]),
                features=edge_attr_np[j]
            )

        return G
