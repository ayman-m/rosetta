# Changelog

All notable changes to the rosetta-ce project will be documented in this file.

## [Unreleased]

## [1.8.2] - 2025-01-27

### Added
- Expanded cloud field coverage in `rosetta/schema/supported_fields.json`

### Changed
- `rosetta/schema/required_presets.json` now includes all supported fields for `syslog`, `cef`, `leef`, and `json`
- Updated cloud infrastructure examples in `README.md`

### Removed
- Deleted unused schema files: `rosetta/schema/required.txt`, `rosetta/schema/observables.txt`, `rosetta/schema.json`

## [1.8.0] - 2026-01-25

### Added - Extended Observables Support 🚀

This major update expands the `Observables` class from 42 fields to **270+ comprehensive security observable fields**, making Rosetta production-ready for modern security operations, SIEM integrations, and cloud-native environments.

#### Industry-Standard Field Naming
- Added **source_ip** / **destination_ip** (alongside existing local_ip / remote_ip)
- Added **source_port** / **destination_port** (alongside existing local_port / remote_port)
- Added **client_ip** / **server_ip** for client-server semantics
- Added **client_port** / **server_port**
- Added **public_ip** / **private_ip**
- Added **nat_source_ip** / **nat_destination_ip**
- Added **client_mac**, **server_hostname**, **client_hostname**
- Added **destination_hostname**, **source_hostname**

#### HTTP/API Fields (12 new fields)
- http_method, http_uri, http_status_code, http_user_agent
- http_host, http_referer
- api_endpoint, api_key, api_name
- request_id, response_time_ms, content_type

#### DNS/DHCP Fields (5 new fields)
- dns_query, dns_response, dns_server
- query_time_ms, lease_duration

#### Kubernetes/Container Fields (11 new fields)
- container_id, container_name, container_image
- pod_name, pod_uid, namespace
- cluster, node_name, service_account
- labels, annotations

#### Cloud Infrastructure Fields (12 new fields)
- cloud_provider, region, instance_id, instance_type
- vpc_id, subnet_id, security_groups, iam_role
- bucket_name, resource_id, resource_type, resource_arn

#### SSL/TLS Fields (7 new fields)
- ssl_cipher, ssl_version, tls_version
- certificate_cn, certificate_issuer
- ja3_hash, ja3s_hash

#### Threat Detection Fields (12 new fields)
- mitre_tactic, mitre_technique
- threat_score, threat_level, threat_name, threat_type
- signature_id, signature_name
- cve_id, cvss_score
- ioc_type, ioc_value

#### Process Extended Fields (7 new fields)
- parent_process_name, command_line
- executable_path, working_directory
- process_name, process_guid, ppid

#### File Extended Fields (7 new fields)
- file_path, file_size, file_type
- file_hash_sha256, file_hash_md5, file_hash_sha1
- file_owner

#### Email Extended Fields (9 new fields)
- sender, recipient, subject, message_id
- attachment_name, attachment_hash
- spf_result, dkim_result, dmarc_result

#### Authentication Fields (8 new fields)
- authentication_method, authentication_result
- mfa_method, mfa_result
- logon_type, session_id
- username, account_name

#### Firewall/IDS Fields (9 new fields)
- firewall_name, rule_name, rule_action
- zone_source, zone_destination
- tcp_flags, packets
- bytes_sent, bytes_received

#### Virtual Machine Fields (5 new fields)
- vm_id, vm_name, hypervisor_type
- cpu_usage, memory_usage

#### Database Extended Fields (5 new fields)
- query_text, execution_time_ms
- transaction_id, affected_rows, schema_name

#### Vulnerability/Compliance Fields (5 new fields)
- vulnerability_id, vulnerability_name
- scan_result, scan_type, compliance_status

#### Incident Response Fields (5 new fields)
- incident_id, incident_severity, incident_status
- playbook_id, alert_id

#### Common Fields (19 new fields)
- hostname, host, domain
- status, result, message, description
- timestamp, risk_score, priority
- category, tags
- malware_name, malware_type
- direction, geo_location, country

### Changed
- Version bumped to 1.8.0 (minor version for new features)
- Updated README.md with comprehensive field documentation
- All new fields support the same list-based pattern as existing fields

### Backward Compatibility
✅ **100% Backward Compatible** - All existing 42 fields remain unchanged. No breaking changes.

### Migration Notes
No migration needed. Simply update to rosetta-ce 1.8.0:
```bash
pip install --upgrade rosetta-ce
```

### Usage Examples

#### Example 1: Industry-Standard Network Fields
```python
from rosetta import Observables, Events

obs = Observables(
    source_ip=['192.168.1.100'],      # Attacker IP
    destination_ip=['10.10.20.5'],    # Target IP
    source_port=['54321'],
    destination_port=['443']
)

events = Events.json(count=5, observables=obs)
```

#### Example 2: Kubernetes Security
```python
obs = Observables(
    container_name=['nginx'],
    pod_name=['nginx-deployment-xyz'],
    namespace=['production'],
    cloud_provider=['AWS'],
    region=['us-east-1']
)

events = Events.cef(count=10, observables=obs)
```

#### Example 3: Threat Detection
```python
obs = Observables(
    mitre_tactic=['TA0001'],
    mitre_technique=['T1059'],
    threat_level=['high'],
    cve_id=['CVE-2021-44228'],
    cvss_score=['9.8']
)

events = Events.syslog(count=20, observables=obs)
```

### Testing
Run the included test script to validate all extended fields:
```bash
python3 test_extended_fields.py
```

See comprehensive examples:
```bash
python3 example_extended_observables.py
```

---

## [1.7.7] - 2025-01-XX

### Previous Release
- Base rosetta functionality with 42 observable fields
- Support for SYSLOG, CEF, LEEF, JSON, Windows Event formats
- Observable generators for IP, URL, SHA256, CVE, MITRE techniques
- Sender support for UDP, TCP, HTTP, HTTPS
- Format converter (CEF to JSON/LEEF)

---

[1.8.0]: https://github.com/ayman-m/rosetta/releases/tag/v1.8.0
[1.7.7]: https://github.com/ayman-m/rosetta/releases/tag/v1.7.7
