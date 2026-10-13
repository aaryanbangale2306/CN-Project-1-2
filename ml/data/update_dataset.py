import urllib.request
import io
import pandas as pd

print("Streaming full Friday-WorkingHours-Morning...")
url = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Friday-WorkingHours-Morning.pcap_ISCX.csv"
req = urllib.request.Request(url, headers={"User-Agent": "AegisGraph/1.0"})
with urllib.request.urlopen(req, timeout=120) as resp:
    content = resp.read()

last_nl = content.rfind(b"\n")
if last_nl != -1:
    content = content[:last_nl]

friday_df = pd.read_csv(io.BytesIO(content), encoding="utf-8", low_memory=False, on_bad_lines="skip")
friday_df.columns = [c.strip() for c in friday_df.columns]
bot_count = (friday_df["Label"] == "Bot").sum()
print(f"Friday morning loaded: {len(friday_df)} rows, Bot flows: {bot_count}")

csv_path = "ml/data/raw/cicids2017_contiguous_sample.csv"
print(f"Loading existing {csv_path}...")
existing_df = pd.read_csv(csv_path, low_memory=False)
existing_df.columns = [c.strip() for c in existing_df.columns]

# Drop old partial Friday morning (rows with Bot or from old Friday morning slice)
clean_existing = existing_df[existing_df["Label"] != "Bot"].copy()

# Combine
combined = pd.concat([clean_existing, friday_df], ignore_index=True)
print(f"Total combined flows: {len(combined)}")

combined.to_csv(csv_path, index=False)
print(f"Successfully saved updated dataset to {csv_path}")
