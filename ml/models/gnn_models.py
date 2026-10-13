"""
AegisGraph: Graph Neural Network Edge Classifiers
Implements:
1. GCNEdgeClassifier
2. GraphSAGEEdgeClassifier
3. GATEdgeClassifier
4. EGraphSAGEClassifier (Edge-conditioned message passing)
All models share the EdgeClassificationHead: MLP([h_src || h_dst || edge_attr])
"""

from typing import Tuple, Optional
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, SAGEConv, GATConv, MessagePassing


class EdgeClassificationHead(nn.Module):
    """
    Edge Classification Head shared across all GNN backbones.
    Fuses topological representations of source host and destination host
    with raw normalized flow attributes:
    edge_input = [ h_src || h_dst || edge_features ]
    logits = MLP(edge_input)
    """

    def __init__(
        self,
        node_hidden_dim: int,
        edge_feature_dim: int,
        head_hidden_dim: int = 64,
        num_classes: int = 7,
        dropout: float = 0.2
    ):
        super().__init__()
        input_dim = 2 * node_hidden_dim + edge_feature_dim
        self.mlp = nn.Sequential(
            nn.Linear(input_dim, head_hidden_dim),
            nn.BatchNorm1d(head_hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(head_hidden_dim, head_hidden_dim),
            nn.BatchNorm1d(head_hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(head_hidden_dim, num_classes)
        )

    def forward(
        self,
        h_node: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor
    ) -> torch.Tensor:
        src = edge_index[0]
        dst = edge_index[1]
        h_src = h_node[src]
        h_dst = h_node[dst]

        # Concatenate [h_src || h_dst || edge_attr]
        edge_repr = torch.cat([h_src, h_dst, edge_attr], dim=-1)
        return self.mlp(edge_repr)


class GCNEdgeClassifier(nn.Module):
    """GCN backbone + Edge Classification Head."""

    def __init__(
        self,
        node_in_dim: int = 8,
        edge_in_dim: int = 24,
        hidden_dim: int = 64,
        num_classes: int = 7,
        dropout: float = 0.2
    ):
        super().__init__()
        self.conv1 = GCNConv(node_in_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.dropout = dropout
        self.head = EdgeClassificationHead(
            node_hidden_dim=hidden_dim,
            edge_feature_dim=edge_in_dim,
            head_hidden_dim=hidden_dim,
            num_classes=num_classes,
            dropout=dropout
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)
        h = self.conv2(h, edge_index)
        h = F.relu(h)

        logits = self.head(h, edge_index, edge_attr)
        return logits, h


class GraphSAGEEdgeClassifier(nn.Module):
    """GraphSAGE (mean aggregation) backbone + Edge Classification Head."""

    def __init__(
        self,
        node_in_dim: int = 8,
        edge_in_dim: int = 24,
        hidden_dim: int = 64,
        num_classes: int = 7,
        dropout: float = 0.2
    ):
        super().__init__()
        self.conv1 = SAGEConv(node_in_dim, hidden_dim, aggr="mean")
        self.conv2 = SAGEConv(hidden_dim, hidden_dim, aggr="mean")
        self.dropout = dropout
        self.head = EdgeClassificationHead(
            node_hidden_dim=hidden_dim,
            edge_feature_dim=edge_in_dim,
            head_hidden_dim=hidden_dim,
            num_classes=num_classes,
            dropout=dropout
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)
        h = self.conv2(h, edge_index)
        h = F.relu(h)

        logits = self.head(h, edge_index, edge_attr)
        return logits, h


class GATEdgeClassifier(nn.Module):
    """Multi-Head Graph Attention Network + Edge Classification Head."""

    def __init__(
        self,
        node_in_dim: int = 8,
        edge_in_dim: int = 24,
        hidden_dim: int = 64,
        heads: int = 4,
        num_classes: int = 7,
        dropout: float = 0.2
    ):
        super().__init__()
        self.conv1 = GATConv(node_in_dim, hidden_dim // heads, heads=heads, concat=True)
        self.conv2 = GATConv(hidden_dim, hidden_dim // heads, heads=heads, concat=True)
        self.dropout = dropout
        self.head = EdgeClassificationHead(
            node_hidden_dim=hidden_dim,
            edge_feature_dim=edge_in_dim,
            head_hidden_dim=hidden_dim,
            num_classes=num_classes,
            dropout=dropout
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        h = self.conv1(x, edge_index)
        h = F.elu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)
        h = self.conv2(h, edge_index)
        h = F.elu(h)

        logits = self.head(h, edge_index, edge_attr)
        return logits, h


class EGraphSAGEConv(MessagePassing):
    """
    Edge-conditioned GraphSAGE Layer:
    Messages are conditioned on both neighboring node features AND edge attributes:
    m_ij = ReLU(W_v * h_j + W_e * e_ij)
    h_i' = W_self * h_i + W_aggr * Mean(m_ij)
    """

    def __init__(self, in_channels: int, edge_channels: int, out_channels: int):
        super().__init__(aggr="mean")
        self.lin_node = nn.Linear(in_channels, out_channels, bias=False)
        self.lin_edge = nn.Linear(edge_channels, out_channels, bias=False)
        self.lin_self = nn.Linear(in_channels, out_channels)
        self.lin_update = nn.Linear(out_channels, out_channels)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_attr: torch.Tensor) -> torch.Tensor:
        out = self.propagate(edge_index, x=x, edge_attr=edge_attr)
        return F.relu(self.lin_self(x) + self.lin_update(out))

    def message(self, x_j: torch.Tensor, edge_attr: torch.Tensor) -> torch.Tensor:
        # x_j: features of sender nodes, edge_attr: features of connecting edges
        return F.relu(self.lin_node(x_j) + self.lin_edge(edge_attr))


class EGraphSAGEClassifier(nn.Module):
    """E-GraphSAGE (Edge-conditioned Message Passing) + Edge Classification Head."""

    def __init__(
        self,
        node_in_dim: int = 8,
        edge_in_dim: int = 24,
        hidden_dim: int = 64,
        num_classes: int = 7,
        dropout: float = 0.2
    ):
        super().__init__()
        self.conv1 = EGraphSAGEConv(node_in_dim, edge_in_dim, hidden_dim)
        self.conv2 = EGraphSAGEConv(hidden_dim, edge_in_dim, hidden_dim)
        self.dropout = dropout
        self.head = EdgeClassificationHead(
            node_hidden_dim=hidden_dim,
            edge_feature_dim=edge_in_dim,
            head_hidden_dim=hidden_dim,
            num_classes=num_classes,
            dropout=dropout
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        h = self.conv1(x, edge_index, edge_attr)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)
        h = self.conv2(h, edge_index, edge_attr)
        h = F.relu(h)

        logits = self.head(h, edge_index, edge_attr)
        return logits, h
