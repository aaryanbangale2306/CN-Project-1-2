"""
AegisGraph: Feature Extraction and Normalization
Extracts node and edge features from network flows without leaking IP or port identity.
"""

from typing import List, Tuple, Dict
import numpy as np
import pandas as pd
import torch


def encode_port_bucket(port_series: pd.Series) -> np.ndarray:
    """
    Encode destination port into structural buckets (NEVER as raw identity):
    - Well-known: 0 - 1023
    - Registered: 1024 - 49151
    - Ephemeral: 49152 - 65535
    - Common service indicators: Web (80, 443, 8080), Remote (22, 23, 3389), DNS (53), Mail (25, 110, 143, 993)
    """
    ports = port_series.fillna(0).astype(int).values
    buckets = np.zeros((len(ports), 7), dtype=np.float32)
    
    # 0: Well known
    buckets[:, 0] = (ports <= 1023).astype(np.float32)
    # 1: Registered
    buckets[:, 1] = ((ports > 1023) & (ports <= 49151)).astype(np.float32)
    # 2: Ephemeral
    buckets[:, 2] = (ports > 49151).astype(np.float32)
    # 3: Web ports (80, 443, 8080)
    buckets[:, 3] = np.isin(ports, [80, 443, 8080, 8443]).astype(np.float32)
    # 4: Remote admin (22, 23, 3389)
    buckets[:, 4] = np.isin(ports, [22, 23, 3389]).astype(np.float32)
    # 5: DNS (53)
    buckets[:, 5] = (ports == 53).astype(np.float32)
    # 6: Mail (25, 110, 143, 993)
    buckets[:, 6] = np.isin(ports, [25, 110, 143, 993]).astype(np.float32)
    
    return buckets


def encode_protocol_onehot(protocol_series: pd.Series) -> np.ndarray:
    """Encode protocol (6=TCP, 17=UDP, other=ICMP/other)."""
    proto = protocol_series.fillna(6).astype(int).values
    enc = np.zeros((len(proto), 3), dtype=np.float32)
    enc[:, 0] = (proto == 6).astype(np.float32)   # TCP
    enc[:, 1] = (proto == 17).astype(np.float32)  # UDP
    enc[:, 2] = (~np.isin(proto, [6, 17])).astype(np.float32)  # Other/ICMP
    return enc


def extract_edge_features(df: pd.DataFrame) -> np.ndarray:
    """
    Extract normalized edge features from tabular flow columns:
    - Log-scaled flow volume (duration, packets, bytes)
    - TCP flags
    - Packet size statistics
    - Protocol one-hot
    - Port buckets
    Total dimension: ~24 features
    """
    n_flows = len(df)
    features_list = []

    # 1. Flow Duration (log1p)
    duration = pd.to_numeric(df.get("Flow Duration", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0)
    features_list.append(np.log1p(duration.values)[:, None].astype(np.float32) / 10.0)

    # 2. Total Packets (Fwd + Bwd)
    fwd_pkts = pd.to_numeric(df.get("Total Fwd Packets", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0)
    bwd_pkts = pd.to_numeric(df.get("Total Backward Packets", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0)
    tot_pkts = fwd_pkts + bwd_pkts
    features_list.append(np.log1p(tot_pkts.values)[:, None].astype(np.float32) / 5.0)

    # 3. Total Bytes
    fwd_bytes = pd.to_numeric(df.get("Total Length of Fwd Packets", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0)
    bwd_bytes = pd.to_numeric(df.get("Total Length of Bwd Packets", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0)
    tot_bytes = fwd_bytes + bwd_bytes
    features_list.append(np.log1p(tot_bytes.values)[:, None].astype(np.float32) / 10.0)

    # 4. Packet Length Stats
    avg_pkt_sz = pd.to_numeric(df.get("Average Packet Size", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0, upper=1500)
    fwd_len_max = pd.to_numeric(df.get("Fwd Packet Length Max", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0, upper=1500)
    bwd_len_max = pd.to_numeric(df.get("Bwd Packet Length Max", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0, upper=1500)
    pkt_stats = np.column_stack([avg_pkt_sz / 1500.0, fwd_len_max / 1500.0, bwd_len_max / 1500.0]).astype(np.float32)
    features_list.append(pkt_stats)

    # 5. Flow Rates (Bytes/s, Packets/s)
    bytes_s = pd.to_numeric(df.get("Flow Bytes/s", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0)
    pkts_s = pd.to_numeric(df.get("Flow Packets/s", pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0)
    flow_rates = np.column_stack([np.log1p(bytes_s) / 15.0, np.log1p(pkts_s) / 10.0]).astype(np.float32)
    features_list.append(flow_rates)

    # 6. TCP Flag indicators (SYN, ACK, FIN, RST, PSH, URG)
    flags = []
    for flg_col in ["SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "URG Flag Count"]:
        flg_val = pd.to_numeric(df.get(flg_col, pd.Series(np.zeros(n_flows))), errors="coerce").fillna(0).clip(lower=0, upper=1)
        flags.append(flg_val.values.astype(np.float32))
    features_list.append(np.column_stack(flags))

    # 7. Protocol one-hot (3 dims)
    proto_col = df.get("protocol", df.get("Protocol", pd.Series(np.full(n_flows, 6))))
    features_list.append(encode_protocol_onehot(proto_col))

    # 8. Port Buckets (7 dims)
    dst_port_col = df.get("dst_port", df.get("Destination Port", pd.Series(np.zeros(n_flows))))
    features_list.append(encode_port_bucket(dst_port_col))

    # Concatenate all edge features
    edge_features = np.concatenate(features_list, axis=1).astype(np.float32)
    # Ensure no NaN or inf
    edge_features = np.nan_to_num(edge_features, nan=0.0, posinf=1.0, neginf=0.0)
    return edge_features


def compute_node_features(
    node_id_map: Dict[str, int],
    src_indices: np.ndarray,
    dst_indices: np.ndarray,
    feature_dim: int = 8,
    use_degrees: bool = True
) -> np.ndarray:
    """
    Compute node features for a single graph window:
    - Base: constant ones vector (dim)
    - Optional: in-degree, out-degree, total incident flows, in/out ratio
    IP identity is strictly omitted.
    """
    num_nodes = len(node_id_map)
    node_feat = np.ones((num_nodes, feature_dim), dtype=np.float32)

    if use_degrees and num_nodes > 0:
        out_degrees = np.bincount(src_indices, minlength=num_nodes).astype(np.float32)
        in_degrees = np.bincount(dst_indices, minlength=num_nodes).astype(np.float32)
        tot_degrees = out_degrees + in_degrees
        ratio = np.divide(out_degrees, tot_degrees + 1e-5)

        # Populate first 4 channels with degree stats (normalized)
        node_feat[:, 0] = np.log1p(out_degrees) / 5.0
        node_feat[:, 1] = np.log1p(in_degrees) / 5.0
        node_feat[:, 2] = np.log1p(tot_degrees) / 5.0
        node_feat[:, 3] = ratio

    return node_feat
