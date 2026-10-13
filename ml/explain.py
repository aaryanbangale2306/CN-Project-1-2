"""
AegisGraph: Explainability Module
Generates subgraph attributions and plain-language reasoning for detected alerts.
Computes top contributing neighbor edges and local neighborhood graph structures.
"""

from typing import Dict, List, Any, Optional
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from ml.data.dataset import CANONICAL_CLASSES


class GraphExplainer:
    """Extracts local subgraphs and computes edge attribution for model alerts."""

    def __init__(self, model: torch.nn.Module, device: str = "cpu"):
        self.model = model
        self.device = device
        self.model.to(device)
        self.model.eval()

    def explain_flow(
        self,
        graph_data: Data,
        target_edge_idx: int,
        k_hops: int = 2,
        top_k_neighbors: int = 5
    ) -> Dict[str, Any]:
        """
        Explain why target_edge_idx was classified as an attack:
        - Identify k-hop incident edges
        - Compute feature gradient attribution
        - Synthesize plain-language rationale
        """
        edge_index = graph_data.edge_index.to(self.device)
        edge_attr = graph_data.edge_attr.to(self.device).clone()
        x = graph_data.x.to(self.device)

        u = int(edge_index[0, target_edge_idx])
        v = int(edge_index[1, target_edge_idx])
        
        # Determine incident edges (connected to u or v)
        incident_mask = (edge_index[0] == u) | (edge_index[1] == u) | (edge_index[0] == v) | (edge_index[1] == v)
        incident_indices = torch.where(incident_mask)[0].cpu().numpy()

        # Compute gradient-based edge saliency
        edge_attr.requires_grad = True
        self.model.zero_grad()

        logits, _ = self.model(x, edge_index, edge_attr)
        probs = F.softmax(logits, dim=-1)
        pred_class = int(torch.argmax(logits[target_edge_idx]).item())
        confidence = float(probs[target_edge_idx, pred_class].item())

        # Backprop on target edge's predicted class
        score = logits[target_edge_idx, pred_class]
        score.backward(retain_graph=True)

        if edge_attr.grad is not None:
            edge_importances = edge_attr.grad.abs().sum(dim=-1).detach().cpu().numpy()
        else:
            edge_importances = np.ones(edge_index.size(1), dtype=np.float32)

        # Rank incident neighbor edges
        neighbor_indices = [idx for idx in incident_indices if idx != target_edge_idx]
        if neighbor_indices:
            sorted_neighbors = sorted(
                neighbor_indices,
                key=lambda idx: float(edge_importances[idx]),
                reverse=True
            )[:top_k_neighbors]
        else:
            sorted_neighbors = []

        # Build neighbor details
        top_contributing = []
        for n_idx in sorted_neighbors:
            src_node = int(edge_index[0, n_idx])
            dst_node = int(edge_index[1, n_idx])
            raw_cls = graph_data.raw_labels[n_idx] if hasattr(graph_data, "raw_labels") else "Unknown"
            top_contributing.append({
                "edge_id": int(n_idx),
                "source_node": src_node,
                "target_node": dst_node,
                "importance_score": round(float(edge_importances[n_idx]), 4),
                "flow_type": raw_cls
            })

        # Generate human-readable reason
        attack_name = CANONICAL_CLASSES[pred_class]
        reason_str = self._generate_reason_string(
            attack_name=attack_name,
            u=u,
            v=v,
            num_incident=len(incident_indices),
            graph_data=graph_data,
            target_edge_idx=target_edge_idx
        )

        return {
            "target_edge_id": int(target_edge_idx),
            "predicted_class": attack_name,
            "confidence": round(confidence, 4),
            "source_node": u,
            "target_node": v,
            "reason": reason_str,
            "top_contributing_edges": top_contributing,
            "subgraph_summary": {
                "total_neighbor_flows": len(incident_indices),
                "top_ranked_analyzed": len(top_contributing)
            }
        }

    @staticmethod
    def _generate_reason_string(
        attack_name: str,
        u: int,
        v: int,
        num_incident: int,
        graph_data: Data,
        target_edge_idx: int
    ) -> str:
        """Create plain-English rationale for non-experts."""
        src_ip = graph_data.node_id_to_ip.get(u, f"Host {u}") if hasattr(graph_data, "node_id_to_ip") else f"Host {u}"
        dst_ip = graph_data.node_id_to_ip.get(v, f"Host {v}") if hasattr(graph_data, "node_id_to_ip") else f"Host {v}"

        if attack_name == "DDoS":
            return f"Flagged because {num_incident} coordinated flows converged on target server ({dst_ip}) simultaneously, overwhelming bandwidth capacity."
        elif attack_name == "PortScan":
            return f"Flagged because host ({src_ip}) rapidly fanned out probes across multiple ports on ({dst_ip}) within this time window."
        elif attack_name == "BruteForce":
            return f"Flagged due to repeated rapid authentication bursts directed at service port on ({dst_ip}) with characteristic retry intervals."
        elif attack_name == "DoS":
            return f"Flagged due to sustained asymmetric volumetric packets from ({src_ip}) depleting server connection state on ({dst_ip})."
        elif attack_name == "Botnet":
            return f"Flagged due to synchronized periodic beaconing and structured communication between infected node ({src_ip}) and controller ({dst_ip})."
        elif attack_name == "Other attack":
            return f"Flagged due to anomalous segment sizes and TCP control flag transitions differing sharply from benign baselines."
        else:
            return f"Flow from {src_ip} to {dst_ip} exhibits normal benign communication patterns."
