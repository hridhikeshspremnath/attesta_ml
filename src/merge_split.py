"""Merge sources, dedupe, and split train/val/test (grouped; time-based for malicious)."""
import hashlib, pathlib
from multiprocessing import Pool

import numpy as np
import pandas as pd
from tqdm import tqdm

P = pathlib.Path("processed")
SEED, TEST_FRAC, VAL_FRAC = 42, 0.20, 0.10
SKIP_PREFIXES = ("package.json", "readme", "license", "changelog")


# ---------- loading ----------
def load_sources():
    dd = pd.read_parquet(P / "malicious_datadog_npm.parquet")
    ossf = pd.read_parquet(P / "malicious_ossf_npm.parquet")
    ben = pd.read_parquet(P / "benign_npm.parquet")
    print(f"loaded: datadog={len(dd)} ossf(meta)={len(ossf)} benign={len(ben)}")
    return dd, ossf, ben


def fill_missing_dates(dd, ossf):
    """Fill missing DataDog dates from the earliest OSSF report for the same package."""
    first_report = ossf.groupby("name")["published"].min()
    dd["published"] = dd["published"].fillna(dd["name"].map(first_report))
    return dd


# ---------- benign cleanup ----------
def remove_malicious_from_benign(ben, dd, ossf):
    """Drop benign rows sharing a name with malicious_intent/OSSF, or an exact compromised (name, version)."""
    bad_names = set(dd.loc[dd.kind == "malicious_intent", "name"]) | set(ossf["name"])
    comp = dd[dd.kind == "compromised_lib"]
    bad_pairs = set(zip(comp["name"], comp["version"]))
    before = len(ben)
    ben = ben[~ben["name"].isin(bad_names)]
    keep = [(n, v) not in bad_pairs for n, v in zip(ben["name"], ben["version"])]
    ben = ben[keep]
    print(f"benign removed for malicious name/version overlap: {before - len(ben)}")
    return ben


# ---------- hashing ----------
def hash_pkg(path):
    """Return (hash of all files, hash of code files excluding package.json/readme/license)."""
    root = pathlib.Path(path)
    h_all, h_code, n_code = hashlib.sha256(), hashlib.sha256(), 0
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            data = f.read_bytes()
        except Exception:
            continue
        rel = f.relative_to(root).as_posix().encode()
        digest = hashlib.sha256(data).digest()
        h_all.update(rel); h_all.update(digest)
        if not f.name.lower().startswith(SKIP_PREFIXES):
            h_code.update(rel); h_code.update(digest); n_code += 1
    return h_all.hexdigest(), (h_code.hexdigest() if n_code else None)


def add_hashes(df):
    with Pool() as pool:
        res = list(tqdm(pool.imap(hash_pkg, df["path"], chunksize=8),
                        total=len(df), desc="hashing", unit="pkg"))
    df["hash_all"] = [r[0] for r in res]
    df["hash_code"] = [r[1] for r in res]
    return df


# ---------- dedupe ----------
def dedupe_name_version(df):
    n0 = len(df)
    df = df.sort_values("label", ascending=False).drop_duplicates(["ecosystem", "name", "version"])
    print(f"dropped duplicate name+version: {n0 - len(df)}")
    return df


def dedupe_content(df):
    n0 = len(df)
    mal_hashes = set(df.loc[df.label == 1, "hash_all"])
    df = df[~((df.label == 0) & df.hash_all.isin(mal_hashes))]   # benign identical to malicious
    df = df.drop_duplicates(["hash_all", "label"])               # exact content duplicates
    print(f"dropped exact content duplicates: {n0 - len(df)}")
    return df


# ---------- grouping (union-find) ----------
def find(parent, x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def assign_groups(df):
    """Group by package name; link malicious packages that share identical code."""
    parent = {}
    for name, code_hash, label in zip(df["name"], df["hash_code"], df["label"]):
        root = find(parent, "n:" + name)
        if label == 1 and code_hash:
            parent[find(parent, "h:" + code_hash)] = root
    df["group"] = [find(parent, "n:" + n) for n in df["name"]]
    return df


# ---------- splitting ----------
def pick_test_groups(groups, rng):
    """Newest 20% of malicious groups by date, plus a random 20% of benign groups."""
    mal, ben = groups[groups.label == 1], groups[groups.label == 0]
    dated = mal.dropna(subset=["date"]).sort_values("date")
    test_mal = dated.tail(int(len(dated) * TEST_FRAC))
    cutoff = test_mal["date"].min() if len(test_mal) else None
    test = set(test_mal["group"])
    n_ben = int(len(ben) * TEST_FRAC)
    test |= set(rng.choice(ben["group"].to_numpy(), size=n_ben, replace=False))
    return test, cutoff


def pick_val_groups(groups, test_groups, rng):
    rest = groups.loc[~groups.group.isin(test_groups), "group"].to_numpy()
    return set(rng.choice(rest, size=int(len(rest) * VAL_FRAC), replace=False))


def assign_split(df):
    rng = np.random.default_rng(SEED)
    groups = df.groupby("group").agg(label=("label", "max"), date=("published", "min")).reset_index()
    test_groups, cutoff = pick_test_groups(groups, rng)
    val_groups = pick_val_groups(groups, test_groups, rng)
    df["split"] = np.where(df.group.isin(test_groups), "test",
                           np.where(df.group.isin(val_groups), "val", "train"))
    return df, cutoff


# ---------- reporting ----------
def report(df, cutoff):
    print("\n=== split x label x kind ===")
    print(pd.crosstab(df["split"], [df["label"], df["kind"]]))
    mal = df[df.label == 1]
    print("\nmalicious test cutoff (on or after):", cutoff)
    print("malicious date range:", mal["published"].min(), "->", mal["published"].max())
    print("malicious rows with no date (all in train/val):", int(mal["published"].isna().sum()))
    print("groups:", df["group"].nunique(), "| rows:", len(df))


# ---------- main ----------
def main():
    dd, ossf, ben = load_sources()
    dd = fill_missing_dates(dd, ossf)
    ben = remove_malicious_from_benign(ben, dd, ossf)

    df = pd.concat([dd, ben], ignore_index=True)
    df = df[df["n_files"] > 0]
    df = dedupe_name_version(df)
    df = add_hashes(df)
    df = dedupe_content(df)
    df = assign_groups(df)
    df, cutoff = assign_split(df)

    df.to_parquet(P / "dataset.parquet")
    report(df, cutoff)
    print("saved processed/dataset.parquet")


if __name__ == "__main__":
    main()
