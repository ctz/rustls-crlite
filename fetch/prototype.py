"""
Prototype rustls-crlite fetcher.

This program synchronises a local directory with the crlite files contained on a
remote server.  There is a manifest file that gives the names, sizes and hashes of
all valid files; this is fetched first.  Then a plan is formed by comparing this against
the local filesystem contents.  Finally, the plan is executed.  If that succeeds
the remote server contents matches the local filesystem.
"""

import argparse
import hashlib
import requests
import logging
import datetime
import os
import json

META_JSON = "meta.json"
REQUEST_TIMEOUT = 30


def fetch(local, remote):
    logging.info(f"Synchronising {remote} into {local}...")
    meta = requests.get(remote + META_JSON, timeout=REQUEST_TIMEOUT)
    meta.raise_for_status()
    meta = meta.json()

    os.makedirs(local, exist_ok=True)

    introduce_meta(meta)
    plan = form_plan(meta, remote, local)

    logging.info("Plan formed. {} steps required.".format(len(plan)))

    for p in plan:
        p()

    logging.info("Success.")


def introduce_meta(meta):
    logging.info(
        "We have metadata generated at {}".format(
            datetime.datetime.fromtimestamp(meta["generated_at"]).isoformat()
        )
    )
    if "comment" in meta:
        logging.info("Comment: {}".format(meta["comment"]))
    if "warning" in meta:
        logging.warning("Warning in metadata: {}".format(meta["warning"]))
    if "fatal" in meta:
        logging.fatal("Warning in metadata: {}".format(meta["fatal"]))


def form_plan(meta, remote, local):
    """
    Form a download plan, with *meta* as the target metadata and
    the *local* directory containing any locally stored files.
    """

    plan = []

    # also schedule deletion of unreferenced filters
    unreferenced_files = set(
        [f for f in os.listdir(local) if f.endswith(".filter") or f.endswith(".delta")]
    )

    for filter in meta.get("filters", []):
        if not satisfied_locally(filter, local):
            plan.append(download(filter, remote, local))
        else:
            unreferenced_files.remove(filter["filename"])

    for f in unreferenced_files:
        plan.append(delete(local, f))

    plan.append(save_metadata(meta, local))
    return plan


def satisfied_locally(filter, local):
    target = local_file_for_filter(filter, local)
    if not os.path.exists(target):
        return False

    with open(target, "rb") as f:
        hash = hashlib.file_digest(f, "sha256")
        if hash.hexdigest().lower() != filter["hash"].lower():
            return False

    return True


def local_file_for_filter(filter, local):
    return os.path.join(local, os.path.basename(filter["filename"]))


def download(filter, remote, local):
    def exec():
        logging.debug(f"Downloading {filter}")
        r = requests.get(remote + filter["filename"], stream=True)
        with open(local_file_for_filter(filter, local), "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

        assert satisfied_locally(
            filter, local
        ), f"Failed to download {filter} -- is the hash wrong?"

        logging.debug("Download successful")

    return exec


def delete(filter, local):
    def exec():
        target = local_file_for_filter(local, filter)
        logging.debug(f"Deleting unreferenced file {target}")
        os.remove(target)

    return exec


def save_metadata(meta, local):
    def exec():
        logging.debug("Saving metadata")
        json.dump(meta, open(local + META_JSON, "w", encoding="utf-8"))

    return exec


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--user", action="store_true", help="Download for just the current user."
    )
    args = ap.parse_args()

    if args.user:
        local = os.path.expanduser("~/.cache/rustls/crlite/")
    else:
        local = "/var/cache/rustls/crlite/"

    remote = "https://crlite.rustls.dev/"

    fetch(local, remote)
    logging.info("Success")
