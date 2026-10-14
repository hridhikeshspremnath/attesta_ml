
"""Benign side (npm): top packages by npm popularity score. Static extraction only."""
import io, json, pathlib, tarfile, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
from tqdm import tqdm

ROOT = pathlib.Path(".")
OUT = ROOT / "processed"
SAMPLES = ROOT / "samples" / "benign" / "npm"
OUT.mkdir(exist_ok=True)
SAMPLES.mkdir(parents=True, exist_ok=True)
N_TARGET = 7000
MAX_TARBALL = 25_000_000   # skip tarballs over ~25 MB
S = requests.Session()


def top_names(n):
    cache = OUT / "top_npm_names.json"
    if cache.exists():
        return json.load(open(cache))[:n]
    names, seen, frm = [], set(), 0
    with tqdm(total=n, desc="top npm names") as bar:
        while len(names) < n:
            r = S.get("https://registry.npmjs.org/-/v1/search",
                      params={"text": "not:deprecated", "popularity": 1.0, "quality": 0.0,
                              "maintenance": 0.0, "size": 250, "from": frm}, timeout=30)
            if r.status_code != 200:
                print("search stopped:", r.status_code)
                break
            objs = r.json().get("objects", [])
            if not objs:
                break
            for o in objs:
                nm = o["package"]["name"].lower()
                if nm not in seen:
                    seen.add(nm)
                    names.append(nm)
                    bar.update(1)
            frm += 250
            time.sleep(0.3)
    json.dump(names, open(cache, "w"))
    print("collected names:", len(names))
    return names[:n]


def safe_extract_tar(data, dest):
    dest = dest.resolve()
    n = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            parts = m.name.split("/", 1)
            rel = parts[1] if len(parts) == 2 else parts[0]   # strip leading "package/"
            target = (dest / rel).resolve()
            if dest not in target.parents:
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(f.read())
            n += 1
    return n


def fetch(name):
    try:
        folder = name.replace("/", "@")
        meta = S.get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), timeout=30)
        if meta.status_code != 200:
            return None
        j = meta.json()
        ver = j.get("dist-tags", {}).get("latest")
        if not ver:
            return None
        dest = SAMPLES / folder / ver
        if dest.exists() and any(dest.rglob("*")):
            n = sum(1 for p in dest.rglob("*") if p.is_file())
        else:
            tar = S.get(j["versions"][ver]["dist"]["tarball"], timeout=60)
            if tar.status_code != 200 or len(tar.content) > MAX_TARBALL:
                return None
            n = safe_extract_tar(tar.content, dest)
        return dict(ecosystem="npm", name=name, version=ver, label=0, source="npm_top",
                    kind="benign", published=j.get("time", {}).get(ver),
                    path=str(dest), n_files=n)
    except Exception:
        return None


names = top_names(N_TARGET)

# never treat a known-malicious name as benign (only works if the malicious parquets already exist)
bad = set()
for f in OUT.glob("malicious_*_npm.parquet"):
    bad |= set(pd.read_parquet(f, columns=["name"])["name"])
names = [n for n in names if n not in bad]
print("benign candidates:", len(names), "| excluded malicious names:", len(bad))

rows = []
with ThreadPoolExecutor(max_workers=8) as ex:
    futs = [ex.submit(fetch, n) for n in names]
    for fut in tqdm(as_completed(futs), total=len(futs), desc="benign packages", unit="pkg"):
        r = fut.result()
        if r:
            rows.append(r)

df = pd.DataFrame(rows)
df["published"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
df.to_parquet(OUT / "benign_npm.parquet")
print("benign packages saved:", len(df), "of", len(names))
print("empty extractions:", int((df["n_files"] == 0).sum()))
print("dates:", df["published"].min(), "->", df["published"].max())


