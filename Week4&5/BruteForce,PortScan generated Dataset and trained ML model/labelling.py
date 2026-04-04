import pandas as pd

INPUT_FILE  = "realdata_Flow.csv"
OUTPUT_FILE = "label_realdata_flows.csv"

df = pd.read_csv(INPUT_FILE)


bruteforce = (
    (df["Src IP"] == "192.168.56.105") &
    (df["Dst IP"] == "192.168.56.104") &
    (df["Dst Port"] == 22)
)

portscan = (
    (df["Src IP"] == "192.168.56.105") &
    (df["Dst IP"] == "192.168.56.104") &
    (df["Dst Port"] != 22)
)

benign = (
    (df["Src IP"] == "10.0.3.15") |
    (df["Dst IP"] == "10.0.3.15")
)
df["Label"] = "BENIGN"                       
df.loc[benign,     "Label"] = "BENIGN"        
df.loc[portscan,   "Label"] = "PortScan"
df.loc[bruteforce, "Label"] = "BruteForce"

print("Label distribution:")
print(df["Label"].value_counts())
print(f"\nTotal rows: {len(df)}")

df.to_csv(OUTPUT_FILE, index=False)
print(f"\nSaved to {OUTPUT_FILE}")