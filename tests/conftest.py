from __future__ import annotations

import pytest

# Pre-initialize pycares Channel daemon thread to avoid verify_cleanup thread check failure
try:
    import pycares

    _channel = pycares.Channel()
except Exception:
    pass


@pytest.fixture
def sample_cert_pem() -> str:
    """Return a valid self-signed PEM certificate for testing."""
    return (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDDTCCAfWgAwIBAgIUGx8y2YXwDl3sygVGL+lRTjVxdGgwDQYJKoZIhvcNAQEL\n"
        "BQAwFjEUMBIGA1UEAwwLcGlrdm0ubG9jYWwwHhcNMjYwOTI4MTYxNzM5WhcNMjcw\n"
        "OTI4MTYxNzM5WjAWMRQwEgYDVQQDDAtwaWt2bS5sb2NhbDCCASIwDQYJKoZIhvcN\n"
        "AQEBBQADggEPADCCAQoCggEBAIbc2qrsotAn9o22/erkh8MhYA4iPe4neeK8NB8G\n"
        "MwTHMsrPC4jmkyGVGk1HozdlvVi8fewbUD1NTtFmdKlwKMzHdGdTtlvdsi12I6AG\n"
        "1sB3iSsCBMxsR+E/7mlAE/+VLH9KKFLwTDfGKe3iJKdCocKVnBTQWoSYm3rHV0ZM\n"
        "ebUQ/SN90quCSlsNafchCCqDe7J+eJYxhDLQ/YVLoNkPUhEPSJ166pp5sf4qSgEn\n"
        "eXAKT2/n2Koq5C1c/STLDa+3LOWdQWn6fFUoIJuPQ7qiAt9LZI3VeYeU5XlzIBZT\n"
        "DdPdaDoEoOhaBxXAZG7gxywcRwyWA9Yl8HwsXqwft6XrfdMCAwEAAaNTMFEwHQYD\n"
        "VR0OBBYEFEjDBIlmFCuf4mLzea3C37DtBGYtMB8GA1UdIwQYMBaAFEjDBIlmFCuf\n"
        "4mLzea3C37DtBGYtMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
        "AIAZjCHKFbouCwgEla1/nimBoFbfuFdls7DpRugTbxyALjgNi8QtL12WpOuFhryi\n"
        "UcVEBJJyM0rtSgkC++FxHJgSbIw1iQRKp5C6ErTlt7JPF3hS7Iur4GZ0jIspyrok\n"
        "9XCSogNlhE1ir5PYgTBvG8uMCIfzU0mSmLt93bfybYC+/kEO7IC+8pvtHx7Ybqww\n"
        "0s9T2FnzYSDsCPO+T0T20SPktgrO5N835jc+G5VCG9KNhIXuFUQRNgDA27FdFLH6\n"
        "TCvMc3K/uBo3Yt/1RRiuwS1YBl6jFNFkamdCs7+dwwTd2GuNgXlQPwOMpQAUwTzA\n"
        "d94+v71gOPoa9mV8f46e47Y=\n"
        "-----END CERTIFICATE-----"
    )


@pytest.fixture
def sample_info_payload() -> dict:
    """Return a representative PiKVM /api/info response dictionary."""
    return {
        "ok": True,
        "result": {
            "hw": {
                "platform": {
                    "type": "v3",
                    "model": "v3-hdmi",
                    "base": "rpi4",
                    "serial": "A1B2C3D4E5F6",
                },
                "health": {
                    "temp": {"cpu": 48.5},
                    "throttling": {
                        "raw_flags": 0,
                        "text_flags": [],
                        "voltage": {
                            "core": {
                                "now": False,
                                "past": False,
                            }
                        },
                    },
                },
                "performance": {
                    "cpu": {"utilization": 14.8},
                    "memory": {
                        "utilization": 32.1,
                        "total": 2147483648,
                        "available": 1458925568,
                    },
                    "fan": {"speed": 2400},
                },
            },
            "meta": {
                "server": {
                    "host": "pikvm.local",
                    "name": "Lab PiKVM",
                    "version": "3.240",
                }
            },
            "system": {
                "kvmd": {
                    "version": "3.240-1",
                }
            },
            "extras": {
                "vnc": {"is_running": True},
            },
        },
    }


@pytest.fixture
def sample_msd_payload() -> dict:
    """Return a representative PiKVM /api/msd response dictionary."""
    return {
        "ok": True,
        "result": {
            "is_enabled": True,
            "drive": {
                "is_mounted": True,
                "connected": True,
            },
            "storage": {
                "total": 16106127360,
                "available": 10737418240,
                "images": {
                    "ubuntu.iso": {"size": 2147483648},
                    "debian.iso": {"size": 1073741824},
                },
            },
        },
    }
