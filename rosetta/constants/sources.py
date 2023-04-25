BAD_IP_SOURCES = [
    {
        "type": "ip",
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta-observables/main/bad-ip.txt",
        "structure": "lines"
    },
    {
        "type": "ip",
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "structure": "lines"
    }
]
GOOD_IP_SOURCES = [
    {
        "type": "ip",
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta-observables/main/good-ip.txt",
        "structure": "lines"
    },
    {
        "type": "subnet",
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "structure": "json",
        "value_key": "prefixes.ip_prefix"
    }
]
BAD_URL_SOURCES = [
    {
        "type": "url",
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta-observables/main/bad-url.txt",
        "structure": "lines"
    },
    {
        "url": "https://urlhaus.abuse.ch/downloads/csv_online",
        "structure": "csv",
        "delimiter": ",",
        "value_column": 2
    }
]
GOOD_URL_SOURCES = [

]
BAD_SHA256_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta-observables/main/bad-sha256.txt",
        "structure": "lines"
    }
]
GOOD_SHA256_SOURCES = [

]
CVE_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta-observables/main/cve.txt",
        "structure": "csv",
        "delimiter": ",",
        "value_column": 0,
        "description": 1
    }
]
TERMS_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta-observables/main/techniques.csv",
        "structure": "csv",
        "value_column": 0,
        "delimiter": ","
    }
]
