"""
AegisGraph: Loss Functions for Class Imbalance
Implements Class-Weighted Cross Entropy and Multi-Class Focal Loss.
"""

from typing import Optional
import torch
import torch.nn as nn
import torch.nn.functional as F


class FocalLoss(nn.Module):
    """
    Multi-class Focal Loss:
    FL(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t)
    Down-weights easy examples (e.g. abundant Benign traffic)
    focusing gradients on hard, rare attack classes.
    """

    def __init__(
        self,
        alpha: Optional[torch.Tensor] = None,
        gamma: float = 2.0,
        reduction: str = "mean"
    ):
        super().__init__()
        self.alpha = alpha  # class weights [C]
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        # logits: [N, C], targets: [N]
        ce_loss = F.cross_entropy(logits, targets, reduction="none", weight=self.alpha)
        pt = torch.exp(-ce_loss)  # probability of true class
        focal_loss = ((1.0 - pt) ** self.gamma) * ce_loss

        if self.reduction == "mean":
            return focal_loss.mean()
        elif self.reduction == "sum":
            return focal_loss.sum()
        return focal_loss


def get_loss_function(
    loss_type: str = "focal",
    class_weights: Optional[torch.Tensor] = None,
    gamma: float = 2.0
) -> nn.Module:
    """Factory to create configured loss function."""
    if loss_type == "focal":
        return FocalLoss(alpha=class_weights, gamma=gamma)
    elif loss_type == "weighted_ce":
        return nn.CrossEntropyLoss(weight=class_weights)
    elif loss_type == "ce":
        return nn.CrossEntropyLoss()
    else:
        raise ValueError(f"Unknown loss type: {loss_type}")
