
"""Build the malicious side of the label table (npm). Static extraction only; nothing is executed."""
import json, pathlib, re
import pandas as pd
import pyzipper
from tqdm import tqdm

ROOT = pathlib.Path(".")
DD = ROOT / "malicious-software-packages-dataset" / "samples" / "npm"
OSSF = ROOT / "malicious-packages" / "osv" / "malicious" / "npm"
OUT_SAMPLES = ROOT / "samples" / "malicious" / "npm"
OUT = ROOT / "processed"
OUT.mkdir(exist_ok=True)
OUT_SAMPLES.mkdir(parents=True, exist_ok=True)
PASSWORD = b"infected"


def decode_name(folder):
    """'@scope@pkg' -> '@scope/pkg'; unscoped names are unchanged."""
    if folder.startswith("@") and folder.count("@") >= 2:
        scope, pkg = folder[1:].split("@", 1)
        return f"@{scope}/{pkg}"
    return folder


def safe_extract(zf, dest):
    """Extract manually, rejecting paths that escape dest (zip-slip)."""
    dest = dest.resolve()
    n = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        target = (dest / info.filename).resolve()
        if dest not in target.parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(info))
        n += 1
    return n


def count_files(path):
    return sum(1 for p in path.rglob("*") if p.is_file())


# ---------- DataDog ----------
zips = sorted(DD.rglob("*.zip"))
rows, failed, skipped = [], 0, 0
for z in tqdm(zips, desc="DataDog zips", unit="zip"):
    kind = z.relative_to(DD).parts[0]            # compromised_lib | malicious_intent
    version = z.parent.name
    m = re.match(r"(\d{4}-\d{2}-\d{2})-", z.name)
    discovered = m.group(1) if m else None
    folder = z.parent.parent.name
    name = decode_name(folder)
    dest = OUT_SAMPLES / kind / folder / version
    try:
        if dest.exists() and any(dest.rglob("*")):   # already extracted on a previous run
            n = count_files(dest)
            skipped += 1
        else:
            with pyzipper.AESZipFile(z) as zf:
                zf.setpassword(PASSWORD)
                n = safe_extract(zf, dest)
        rows.append(dict(ecosystem="npm", name=name.lower(), version=version, label=1,
                         source="datadog", kind=kind, published=discovered,
                         path=str(dest), n_files=n))
    except Exception as e:
        failed += 1
        if failed <= 5:
            tqdm.write(f"FAILED {z} {e}")

dd = pd.DataFrame(rows)
dd["published"] = pd.to_datetime(dd["published"], utc=True, errors="coerce")
dd.to_parquet(OUT / "malicious_datadog_npm.parquet")
print(f"DataDog rows: {len(dd)} | skipped (already extracted): {skipped} | failed: {failed}")
if len(dd):
    print(dd["kind"].value_counts().to_string())
    print("empty extractions:", int((dd["n_files"] == 0).sum()))
    print("DataDog dates:", dd["published"].min(), "->", dd["published"].max(),
          "| missing:", int(dd["published"].isna().sum()))

# ---------- OSSF (metadata only, no code) ----------
print("Listing OSSF npm reports (this can take a minute)...")
files = list(OSSF.rglob("*.json"))
rows = []
for f in tqdm(files, desc="OSSF reports", unit="file"):
    try:
        r = json.load(open(f))
    except Exception:
        continue
    if r.get("withdrawn") or not str(r.get("id", "")).startswith("MAL-"):
        continue
    for aff in r.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").lower() != "npm":
            continue
        for v in (aff.get("versions") or [None]):
            rows.append(dict(ecosystem="npm", name=pkg["name"].lower(), version=v, label=1,
                             source="ossf", kind="malicious_intent",
                             published=r.get("published"), osv_id=r["id"]))

ossf = pd.DataFrame(rows)
ossf["published"] = pd.to_datetime(ossf["published"], utc=True, errors="coerce")
ossf.to_parquet(OUT / "malicious_ossf_npm.parquet")
print("OSSF rows:", len(ossf), "| unique packages:", ossf["name"].nunique())
print("OSSF dates:", ossf["published"].min(), "->", ossf["published"].max())
if len(dd):
    print("Packages in both DataDog and OSSF:", len(set(dd["name"]) & set(ossf["name"])))
