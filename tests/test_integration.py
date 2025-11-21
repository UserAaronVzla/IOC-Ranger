import asyncio
from unittest.mock import AsyncMock, patch

from ioc_ranger.cli import process
from ioc_ranger.config import Settings
from ioc_ranger.ioc_types import DomainResult, HashResult, IPResult, MixedRow, URLResult


def run_async(coro):
    return asyncio.run(coro)


def test_process_mixed():
    async def _test():
        settings = Settings(
            vt_api_key="fake",
            abuseipdb_key="fake",
            ipqs_key="fake",
            alienvault_key="fake",
            urlscan_key="fake",
            shodan_key="fake",
            greynoise_key="fake",
            threatfox_key="fake",
            cache_ttl=0,
        )

        items = ["1.1.1.1", "example.com", "http://example.com", "44d88612fea8a8f36de82e1278abb02f"]

        # Mock handlers
        with (
            patch("ioc_ranger.cli.handle_ip", new_callable=AsyncMock) as mock_ip,
            patch("ioc_ranger.cli.handle_domain", new_callable=AsyncMock) as mock_domain,
            patch("ioc_ranger.cli.handle_url", new_callable=AsyncMock) as mock_url,
            patch("ioc_ranger.cli.handle_hash", new_callable=AsyncMock) as mock_hash,
        ):
            mock_ip.return_value = MixedRow(kind="ip", data=IPResult(ioc="1.1.1.1"))
            mock_domain.return_value = MixedRow(kind="domain", data=DomainResult(ioc="example.com"))
            mock_url.return_value = MixedRow(kind="url", data=URLResult(ioc="http://example.com"))
            mock_hash.return_value = MixedRow(
                kind="hash", data=HashResult(ioc="44d88612fea8a8f36de82e1278abb02f")
            )

            rows = await process("mixed", items, settings, max_concurrency=5)

            assert len(rows) == 4
            assert mock_ip.called
            assert mock_domain.called
            assert mock_url.called
            assert mock_hash.called

    run_async(_test())


def test_process_progress_bar():
    async def _test():
        settings = Settings(
            vt_api_key="fake",
            abuseipdb_key="fake",
            ipqs_key="fake",
            alienvault_key="fake",
            urlscan_key="fake",
            shodan_key="fake",
            greynoise_key="fake",
            threatfox_key="fake",
            cache_ttl=0,
        )
        items = ["1.1.1.1"]
        with patch("ioc_ranger.cli.handle_ip", new_callable=AsyncMock) as mock_ip:
            mock_ip.return_value = MixedRow(kind="ip", data=IPResult(ioc="1.1.1.1"))
            await process("ip", items, settings)
            assert mock_ip.called

    run_async(_test())
