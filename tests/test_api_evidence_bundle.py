"""Tests for the compliance evidence bundle ZIP export endpoint."""

import os
import tempfile
import zipfile
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

from neuroguard.api.app import create_app

REQUIRED_NAMES = [
    "compliance_report.pdf",
    "compliance_report.json",
    "consent_ledger.json",
    "audit_log.json",
    "hash_chain_proof.txt",
]


@pytest.fixture
def temp_ledger_path():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        yield path
    finally:
        if os.path.isfile(path):
            os.remove(path)


@pytest.fixture
def client(temp_ledger_path):
    os.environ["NEUROGUARD_LEDGER_PATH"] = temp_ledger_path
    try:
        app = create_app()
        with TestClient(app) as c:
            yield c
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)


def test_evidence_zip_status_200(client: TestClient) -> None:
    r = client.get("/compliance/evidence.zip")
    assert r.status_code == 200


def test_evidence_zip_content_type(client: TestClient) -> None:
    r = client.get("/compliance/evidence.zip")
    assert "application/zip" in r.headers.get("content-type", "")


def test_evidence_zip_contains_required_files(client: TestClient) -> None:
    r = client.get("/compliance/evidence.zip")
    assert r.status_code == 200
    z = zipfile.ZipFile(BytesIO(r.content), "r")
    names = set(z.namelist())
    z.close()
    for name in REQUIRED_NAMES:
        assert name in names, f"ZIP should contain {name}"
