"""
Anchor the trusted baseline in S3 Object Lock, where nobody can quietly rewrite it.

    python -m cloud.anchor upload --bucket <name>       # lock baseline files for 1 day
    python -m cloud.anchor check --bucket <name>        # does the local head match S3?
    python -m cloud.anchor try-delete --bucket <name>   # demo: deletion is refused

The bucket must be created with Object Lock enabled:
    aws s3api create-bucket --bucket <name> --object-lock-enabled-for-bucket --region us-east-1
"""
import argparse
import datetime as dt
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from common import BASELINE_DIR, DATA, HEAD

FILES = ["manifest.csv", "snapshot.csv", "head.txt"]
PREFIX = "baseline/"
S3_COPY = DATA / "baseline_s3"


def s3():
    return boto3.client("s3")


def upload(bucket: str, days: int = 1) -> None:
    until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)
    for name in FILES:
        resp = s3().put_object(
            Bucket=bucket, Key=PREFIX + name, Body=(BASELINE_DIR / name).read_bytes(),
            ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=until,
            ServerSideEncryption="aws:kms", ChecksumAlgorithm="SHA256",
        )
        print(f"Locked s3://{bucket}/{PREFIX}{name} until {until:%Y-%m-%d %H:%M} UTC "
              f"(version {resp.get('VersionId')})")


def fetch_head(bucket: str) -> str:
    return s3().get_object(Bucket=bucket, Key=PREFIX + "head.txt")["Body"].read().decode().strip()


def download(bucket: str, dest: Path = S3_COPY) -> Path:
    """Pull the locked copy so verification never trusts files on the local disk."""
    dest.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        s3().download_file(bucket, PREFIX + name, str(dest / name))
    return dest


def check(bucket: str) -> None:
    local, remote = HEAD.read_text().strip(), fetch_head(bucket)
    print(f"Local head: {local}\nS3 head:    {remote}")
    print("MATCH: local baseline is untouched" if local == remote else "MISMATCH: local baseline was altered")


def try_delete(bucket: str) -> None:
    key = PREFIX + "manifest.csv"
    version = s3().head_object(Bucket=bucket, Key=key)["VersionId"]
    print(f"Attempting to permanently delete {key} (version {version}) ...")
    try:
        s3().delete_object(Bucket=bucket, Key=key, VersionId=version)
        print("Deleted. Object Lock is NOT protecting this object, check the bucket settings.")
    except ClientError as err:
        print(f"Refused by S3: {err.response['Error']['Code']}. The baseline is write-once.")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["upload", "check", "try-delete"])
    p.add_argument("--bucket", required=True)
    p.add_argument("--days", type=int, default=1)
    a = p.parse_args()
    {"upload": lambda: upload(a.bucket, a.days), "check": lambda: check(a.bucket),
     "try-delete": lambda: try_delete(a.bucket)}[a.command]()


if __name__ == "__main__":
    main()
