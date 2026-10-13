"""
AegisGraph: Data Acquisition and Contiguous Slicing
Downloads contiguous slices from real CIC-IDS2017 CSV files directly from HuggingFace
or loads local CSVs from ml/data/raw/.
Maintains strict contiguous temporal windows (~200k-250k flows total).
"""

import os
import io
import urllib.request
import pandas as pd
import numpy as np

DATASET_REPO = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main"

# Target files covering all canonical attacks in CIC-IDS2017:
# Friday Afternoon DDoS -> DDoS + Benign
# Friday Afternoon PortScan -> PortScan + Benign
# Friday Morning -> Botnet + Benign
# Tuesday -> FTP-Patator, SSH-Patator (BruteForce) + Benign
# Wednesday -> DoS GoldenEye, Slowloris, Slowhttptest, Hulk + Benign
# Thursday Morning -> Web Attacks (merged into Other attack / BruteForce)
TARGET_SLICES = [
    {
        "filename": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "attack_type": "DDoS",
        "byte_range": "0-40000000",   # ~40MB contiguous slice (~80k flows)
    },
    {
        "filename": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "attack_type": "PortScan",
        "byte_range": "0-30000000",   # ~30MB contiguous slice (~60k flows)
    },
    {
        "filename": "Tuesday-WorkingHours.pcap_ISCX.csv",
        "attack_type": "BruteForce",
        "byte_range": "0-25000000",   # ~25MB contiguous slice (~50k flows)
    },
    {
        "filename": "Wednesday-workingHours.pcap_ISCX.csv",
        "attack_type": "DoS",
        "byte_range": "0-30000000",   # ~30MB contiguous slice (~60k flows)
    },
    {
        "filename": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "attack_type": "Botnet",
        "byte_range": "0-58316725",   # Full file (~58MB) captures all 1,966 Botnet flows
    },
    {
        "filename": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "attack_type": "Other/Web",
        "byte_range": "0-15000000",   # ~15MB contiguous slice (~25k flows)
    }
]


def download_contiguous_slice(url: str, byte_range: str) -> pd.DataFrame:
    """Download a contiguous byte range of CSV and parse into DataFrame."""
    print(f"Streaming slice from {url} ({byte_range})...")
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AegisGraph-Dataset-Loader/1.0",
            "Range": f"bytes={byte_range}"
        }
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read()

    # Find the last complete line to avoid truncated row
    last_newline = content.rfind(b"\n")
    if last_newline != -1:
        content = content[:last_newline]

    # Parse with pandas
    df = pd.read_csv(
        io.BytesIO(content),
        encoding="utf-8",
        low_memory=False,
        on_bad_lines="skip"
    )
    return df


def acquire_dataset(
    output_path: str = "ml/data/raw/cicids2017_contiguous_sample.csv",
    force_download: bool = False
) -> pd.DataFrame:
    """
    Acquire contiguous slices of CIC-IDS2017.
    If output_path exists and not force_download, loads directly.
    Otherwise streams slices from HuggingFace and merges into a contiguous dataframe.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if os.path.exists(output_path) and not force_download:
        print(f"Loading existing contiguous dataset from {output_path}...")
        df = pd.read_csv(output_path, low_memory=False)
        print(f"Loaded {len(df):,} flows.")
        return df

    dfs = []
    for item in TARGET_SLICES:
        url = f"{DATASET_REPO}/{item['filename']}"
        try:
            slice_df = download_contiguous_slice(url, item["byte_range"])
            print(f"  -> Acquired {len(slice_df):,} flows for {item['attack_type']}")
            dfs.append(slice_df)
        except Exception as e:
            print(f"  ! Warning: Failed to stream {item['filename']}: {e}")

    if not dfs:
        raise RuntimeError("Failed to acquire any dataset slices.")

    # Combine into unified dataset
    combined = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal acquired contiguous flows: {len(combined):,}")

    # Save to disk
    combined.to_csv(output_path, index=False)
    print(f"Saved dataset to {output_path}")
    return combined


if __name__ == "__main__":
    acquire_dataset()
