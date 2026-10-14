"""Write an empty OSSF table so merge_split.py runs without OSSF metadata."""
import pathlib
import pandas as pd

OUT = pathlib.Path("processed") / "malicious_ossf_npm.parquet"


def empty_ossf():
    return pd.DataFrame({
        "name": pd.Series(dtype="object"),
        "version": pd.Series(dtype="object"),
        "published": pd.Series(dtype="datetime64[ns, UTC]"),
    })


def main():
    if OUT.exists():
        print("already exists, leaving it alone:", OUT)
        return
    empty_ossf().to_parquet(OUT)
    print("wrote empty placeholder:", OUT)


if __name__ == "__main__":
    main()
