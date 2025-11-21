import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_hash():
    return "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture
def sample_ip():
    return "8.8.8.8"


@pytest.fixture
def sample_domain():
    return "example.com"


@pytest.fixture
def sample_url():
    return "http://example.com/login"
