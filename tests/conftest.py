"""Shared pytest fixtures."""

import json
from pathlib import Path

import pytest


@pytest.fixture
def sample_targets_raw():
    return [
        {"name": "Employee1", "email": "employee1@fictionalcorp.test", "department": "Finance"},
        {"name": "Employee2", "email": "employee2@fictionalcorp.test", "department": "Finance"},
        {"name": "Employee3", "email": "employee3@fictionalcorp.test", "department": "HR"},
        {"name": "Employee4", "email": "employee4@fictionalcorp.test", "department": "HR"},
        {"name": "Employee5", "email": "employee5@fictionalcorp.test", "department": "Engineering"},
        {"name": "Employee6", "email": "employee6@fictionalcorp.test", "department": "Engineering"},
    ]


@pytest.fixture
def sample_targets_file(tmp_path: Path, sample_targets_raw):
    path = tmp_path / "targets.json"
    path.write_text(json.dumps({"targets": sample_targets_raw}), encoding="utf-8")
    return path


@pytest.fixture
def repo_sample_targets_path():
    return Path(__file__).resolve().parents[1] / "sample_data" / "targets.json"
