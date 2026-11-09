#!/usr/bin/env python3
"""Push one image from a `docker save` OCI tarball to a registry.

Used by run-on-qemu-vm.sh --local-image, inside the guest, so a registry can
be filled before Docker exists there: the docker-install suite has to pull the
core image with the engine bootstrap just installed.

    push-oci.py TARBALL https://HOST:PORT REPOSITORY TAG CA_FILE

Only the linux/amd64 manifest is pushed. A tarball saved from containerd's
image store references an index whose other platforms' blobs it does not
contain, and a registry refuses a manifest whose blobs are missing.
"""

import json
import ssl
import sys
import tarfile
import urllib.error
import urllib.request

INDEXES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)


def main():
    tarball, base, repository, tag, cafile = sys.argv[1:]
    context = ssl.create_default_context(cafile=cafile)
    archive = tarfile.open(tarball)
    names = set(archive.getnames())

    def blob_path(digest):
        return "blobs/" + digest.replace(":", "/", 1)

    def read(name):
        return archive.extractfile(name).read()

    def request(method, url, data=None, headers=None):
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        try:
            return urllib.request.urlopen(req, context=context, timeout=120)
        except urllib.error.HTTPError as err:
            if method == "HEAD" and err.code == 404:
                return None
            raise SystemExit(f"{method} {url}: {err.code} {err.read()[:300]!r}")

    def resolve(descriptor):
        data = read(blob_path(descriptor["digest"]))
        if descriptor["mediaType"] not in INDEXES:
            return descriptor, data
        for candidate in json.loads(data)["manifests"]:
            platform = candidate.get("platform", {})
            if (platform.get("os"), platform.get("architecture")) == ("linux", "amd64") and blob_path(candidate["digest"]) in names:
                return resolve(candidate)
        raise SystemExit("the tarball holds no linux/amd64 manifest with its blobs")

    index = json.loads(read("index.json"))
    descriptor, manifest_data = resolve(index["manifests"][0])
    manifest = json.loads(manifest_data)
    for item in [manifest["config"]] + manifest["layers"]:
        digest = item["digest"]
        if request("HEAD", f"{base}/v2/{repository}/blobs/{digest}") is not None:
            continue
        started = request("POST", f"{base}/v2/{repository}/blobs/uploads/", data=b"")
        location = started.headers["Location"]
        if location.startswith("/"):
            location = base + location
        location += ("&" if "?" in location else "?") + "digest=" + digest
        request("PUT", location, data=read(blob_path(digest)), headers={"Content-Type": "application/octet-stream"})
    request("PUT", f"{base}/v2/{repository}/manifests/{tag}", data=manifest_data,
            headers={"Content-Type": descriptor["mediaType"]})
    print(f"pushed {repository}:{tag} ({descriptor['digest']})")


if __name__ == "__main__":
    main()
