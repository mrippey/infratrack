"""Test script for Virustotal API calls"""

import pytest
import requests_mock
from infratrack.tools.virustotal_api import VirusTotalApiLookup
from infratrack.tools.error import StandardApiErrorMessage


def test_get_ip_info():
    with requests_mock.Mocker() as m:
        m.get(f"https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1", json={'data': {
            'attributes': {'last_analysis_stats': {'malicious': 2}}}})
        lookup = VirusTotalApiLookup()
        result = lookup.get_ip_info("1.1.1.1")
        assert result == "1.1.1.1 [white]was identified as malicious by [red]2 vendors"

def test_get_domain_info():
    with requests_mock.Mocker() as m:
        m.get(f"https://www.virustotal.com/api/v3/domains/example.com", json={'data': {
            'attributes': {'last_analysis_stats': {'malicious': 1}}}})
        lookup = VirusTotalApiLookup()
        result = lookup.get_domain_info("example.com")
        assert result == "example.com is clean"

def test_request_api_error():
    with requests_mock.Mocker() as m:
        m.get(
            "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
            status_code=400,
        )
        lookup = VirusTotalApiLookup()
        with pytest.raises(StandardApiErrorMessage, match="There may be an error in your API URL"):
            lookup.get_ip_info("330.1.1.1")
