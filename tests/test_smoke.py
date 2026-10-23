"""Smoke checks for the project skeleton and required dependencies."""

from importlib import import_module
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ("ingestion", "preprocessing", "ml", "alerts", "storage", "dashboard")


@pytest.mark.parametrize("component", COMPONENTS)
def test_component_is_importable(component):
    module = import_module(f"mini_siem.{component}")
    assert Path(module.__file__).resolve() == ROOT / "mini_siem" / component / "__init__.py"


@pytest.mark.parametrize("module", ("pandas", "sklearn", "streamlit", "plotly", "sqlite3"))
def test_dependency_is_importable(module):
    import_module(module)


@pytest.mark.parametrize("relative_path", ("README.md", "requirements.txt", ".gitignore", "mini_siem/__init__.py"))
def test_project_file_exists(relative_path):
    assert (ROOT / relative_path).is_file()
