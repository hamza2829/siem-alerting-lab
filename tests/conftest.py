from pathlib import Path

import pytest

from siem_lab.detect import DEFAULT_CONFIG, load_settings
from siem_lab.generate import Scenario, generate
from siem_lab.records import Alert
from siem_lab.rules.common import Settings


@pytest.fixture(scope="session")
def settings() -> dict[str, Settings]:
    return load_settings(DEFAULT_CONFIG)


@pytest.fixture(scope="session")
def reference(
    tmp_path_factory: pytest.TempPathFactory, settings: dict[str, Settings]
) -> tuple[Path, list[Scenario], list[Alert]]:
    from siem_lab.detect import detect

    directory = tmp_path_factory.mktemp("reference")
    labels = generate(directory)
    return directory, labels, detect(directory / "logs", settings)
