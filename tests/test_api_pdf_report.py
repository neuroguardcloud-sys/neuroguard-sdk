"""Tests for the compliance report PDF export endpoint."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from neuroguard.api.app import create_app


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


def test_compliance_report_pdf_status_200(client: TestClient) -> None:
    r = client.get("/compliance/report.pdf")
    assert r.status_code == 200


def test_compliance_report_pdf_content_type(client: TestClient) -> None:
    r = client.get("/compliance/report.pdf")
    assert "application/pdf" in r.headers.get("content-type", "")


def test_compliance_report_pdf_body_starts_with_pdf_magic(client: TestClient) -> None:
    r = client.get("/compliance/report.pdf")
    assert r.content.startswith(b"%PDF")
