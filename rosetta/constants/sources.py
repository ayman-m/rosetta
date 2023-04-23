BAD_IP_SOURCES = [
    {
        "type": "ip",
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "structure": "lines"
    }
]
GOOD_IP_SOURCES = [
    {
        "type": "subnet",
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "structure": "json",
        "value_key": "prefixes.ip_prefix"
    }
]
BAD_URL_SOURCES = [
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
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta/main/data/bad-sha256.txt",
        "structure": "lines"
    }
]
GOOD_SHA256_SOURCES = [

]
CVE_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta/main/data/cve.csv",
        "structure": "csv",
        "delimiter": ",",
        "value_column": 0,
        "description": 1
    }
]
TERMS_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/ayman-m/rosetta/main/data/techniques.csv",
        "structure": "csv",
        "value_column": 0,
        "delimiter": ","
    }
]