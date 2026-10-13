import urllib.request
import io
import pandas as pd

print("Streaming Thursday-WorkingHours-Morning-WebAttacks...")
url = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
req = urllib.request.Request(url, headers={"User-Agent": "AegisGraph/1.0"})
with urllib.request.urlopen(req, timeout=120) as resp:
    content = resp.read()

last_nl = content.rfind(b"\n")
if last_nl != -1:
    content = content[:last_nl]

thursday_df = pd.read_csv(io.BytesIO(content), encoding="utf-8", low_memory=False, on_bad_lines="skip")
thursday_df.columns = [c.strip() for c in thursday_df.columns]
print(f"Thursday morning loaded: {len(thursday_df)} rows")
counts = thursday_df["Label"].value_counts().to_dict()
print("Thursday labels:", {str(k).encode("ascii", "ignore").decode(): v for k, v in counts.items()})

csv_path = "ml/data/raw/cicids2017_contiguous_sample.csv"
print(f"Loading existing {csv_path}...")
existing_df = pd.read_csv(csv_path, low_memory=False)
existing_df.columns = [c.strip() for c in existing_df.columns]

# Drop old partial Web Attack rows to replace with full Thursday morning
existing_clean = existing_df[~existing_df["Label"].str.contains("Web Attack", na=False)].copy()

combined = pd.concat([existing_clean, thursday_df], ignore_index=True)
print(f"Total combined flows: {len(combined)}")

combined.to_csv(csv_path, index=False)
print(f"Successfully saved updated dataset to {csv_path}")
