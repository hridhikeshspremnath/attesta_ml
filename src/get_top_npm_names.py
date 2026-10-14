"""Collect popular npm package names via many keyword searches (popularity-weighted)."""
import json, pathlib, time
import requests
from tqdm import tqdm

OUT = pathlib.Path("processed")
OUT.mkdir(exist_ok=True)
S = requests.Session()
URL = "https://registry.npmjs.org/-/v1/search"

QUERIES = """react vue angular svelte express koa fastify next nuxt webpack babel eslint prettier
typescript jest mocha chai cli utils lodash async promise stream http https server client api rest
graphql database sql mongodb redis orm logger log config env parser json yaml xml csv markdown html
css sass postcss template render test mock assert crypto hash uuid date time moment validate schema
form ui component icon image file fs path glob watch build bundle compile plugin loader middleware
auth jwt oauth password email websocket socket events queue cache cookie session proxy request fetch
axios debug color chalk string array object number math random buffer binary zip tar compress
stripe aws azure google firebase docker kubernetes git github npm yarn node browser dom animation
chart canvas svg audio video pdf excel regex url query uri semver ssh tls""".split()

names, seen = [], set()
for q in tqdm(QUERIES, desc="keywords"):
    frm = 0
    while frm < 1000:
        try:
            r = S.get(URL, params={"text": q, "popularity": 1.0, "quality": 0.0,
                                   "maintenance": 0.0, "size": 250, "from": frm}, timeout=30)
        except Exception:
            break
        if r.status_code != 200:
            break
        objs = r.json().get("objects", [])
        if not objs:
            break
        for o in objs:
            nm = o["package"]["name"].lower()
            if nm not in seen:
                seen.add(nm)
                names.append(nm)
        frm += 250
        time.sleep(0.3)
    tqdm.write(f"{q}: total names {len(names)}") if len(names) % 1000 < 50 else None

json.dump(names, open(OUT / "top_npm_names.json", "w"))
print("collected names:", len(names))
