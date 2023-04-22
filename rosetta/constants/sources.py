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
        "url": "https://services.nvd.nist.gov/rest/json/cves/1.0",
        "structure": "json",
        "value_key": "result.CVE_Items.cve.CVE_data_meta.ID",
        "additional_keys": "result.CVE_Items.cve.description.description_data.value"
    }
]
TERMS_SOURCES = [
    {
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "structure": "lines"
    }
]