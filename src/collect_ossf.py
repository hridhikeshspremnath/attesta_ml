"""Resumable OSSF npm parser. Saves progress in chunks; rerun to continue after an interruption."""
import json, pathlib
from multiprocessing import Pool

import pandas as pd
from tqdm import tqdm

OSSF = pathlib.Path("malicious-packages/osv/malicious/npm")
OUT = pathlib.Path("processed")
CHUNK_DIR = OUT / "ossf_chunks"
FILELIST = OUT / "ossf_filelist.txt"
FINAL = OUT / "malicious_ossf_npm.parquet"
CHUNK_SIZE = 2000
COLS = ["ecosystem", "name", "version", "label", "source", "kind", "published", "osv_id"]


def list_report_files():
    """List report files once and cache the list (the walk is slow on this drive)."""
    if FILELIST.exists():
        return FILELIST.read_text().splitlines()
    print("Listing OSSF npm reports (one-time, can take a few minutes)...")
    files = sorted(str(p) for p in OSSF.rglob("*.json"))
    FILELIST.write_text("\n".join(files))
    return files


def parse_report(path):
    """Return one row per (package, version) in a single OSV report."""
    try:
        r = json.load(open(path))
    except Exception:
        return []
    if r.get("withdrawn") or not str(r.get("id", "")).startswith("MAL-"):
        return []
    rows = []
    for aff in r.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").lower() != "npm":
            continue
        for v in (aff.get("versions") or [None]):
            rows.append(dict(ecosystem="npm", name=pkg["name"].lower(), version=v, label=1,
                             source="ossf", kind="malicious_intent",
                             published=r.get("published"), osv_id=r["id"]))
    return rows


def chunk_path(i):
    return CHUNK_DIR / f"chunk_{i:05d}.parquet"


def process_chunk(i, files, pool):
    rows = []
    for part in pool.imap(parse_report, files, chunksize=50):
        rows.extend(part)
    pd.DataFrame(rows, columns=COLS).to_parquet(chunk_path(i))


def run_all_chunks(files):
    CHUNK_DIR.mkdir(parents=True, exist_ok=True)
    chunks = [files[i:i + CHUNK_SIZE] for i in range(0, len(files), CHUNK_SIZE)]
    todo = [i for i in range(len(chunks)) if not chunk_path(i).exists()]
    print(f"{len(files)} reports | {len(chunks)} chunks | {len(chunks) - len(todo)} already done")
    with Pool(8) as pool:
        for i in tqdm(todo, desc="chunks", unit="chunk"):
            process_chunk(i, chunks[i], pool)


def combine_chunks():
    parts = [pd.read_parquet(p) for p in sorted(CHUNK_DIR.glob("chunk_*.parquet"))]
    df = pd.concat(parts, ignore_index=True)
    df["published"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
    df.to_parquet(FINAL)
    return df


def main():
    files = list_report_files()
    run_all_chunks(files)
    df = combine_chunks()
    print("OSSF rows:", len(df), "| unique packages:", df["name"].nunique())
    print("OSSF dates:", df["published"].min(), "->", df["published"].max())


if __name__ == "__main__":
    main()
