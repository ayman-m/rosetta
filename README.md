[![snyk](https://snyk.io/test/github/ayman-m/rosetta/badge.svg)](https://snyk.io/test/github/my-soc/Rosetta)
![codeql](https://github.com/ayman-m/rosetta/actions/workflows/github-code-scanning/codeql/badge.svg)
[![slack-community](https://img.shields.io/badge/Slack-4A154C?logo=slack&logoColor=white)](https://go-rosetta.slack.com)

# Rosetta

Rosetta is a Python library for generating realistic security telemetry and alerts at scale. It can:
- Generate observables/indicators (IPs, URLs, hashes, CVEs, MITRE ATT&CK techniques)
- Emit synthetic logs in multiple formats (SYSLOG, CEF, LEEF, JSON, Windows Event XML)
- Produce incident bundles composed of multiple event types
- Convert one log format to another (e.g., CEF to JSON/LEEF)
- Send synthetic logs to TCP/UDP/HTTP/HTTPS endpoints
- Validate fields against a schema and generate missing values heuristically
- Simulate database queries including SQL injection patterns
- Generate Kubernetes and cloud-native telemetry

## Installation

- Install from PyPI:
```sh
pip install rosetta-ce
```
- Install from source:
```sh
git clone https://github.com/ayman-m/rosetta.git
cd rosetta
python setup.py install
```

## Quick start

```python
from rosetta import Events, Observables, ObservableType, ObservableKnown

# Generate observables
bad_ips = Observables.generator(count=3, observable_type=ObservableType.IP, known=ObservableKnown.BAD)

# Inject custom observables and extra fields
observables = Observables(
    src_host=["web-01"],
    user=["alex"],
    url=["https://example.org"],
    custom_field=["custom_value"],
)

# Create events in different formats
syslog_events = Events.syslog(count=2, observables=observables)
cef_events = Events.cef(count=2, observables=observables)
leef_events = Events.leef(count=2, observables=observables)
json_events = Events.json(count=2, observables=observables)
win_events = Events.winevent(count=2, observables=observables)
```

## Observables

### Observable types

| Type | Description | Known Values |
|------|-------------|--------------|
| `IP` | IPv4 addresses | BAD (malicious), GOOD (benign) |
| `URL` | Web URLs | BAD (malicious), GOOD (benign) |
| `SHA256` | File hashes | BAD (malicious), GOOD (benign) |
| `CVE` | CVE identifiers | N/A |
| `TERMS` | MITRE ATT&CK techniques (280+ IDs) | N/A |

### Fetch or generate indicators
```python
from rosetta import Observables, ObservableType, ObservableKnown

bad_urls = Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.BAD)
good_hashes = Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.GOOD)
cves = Observables.generator(count=2, observable_type=ObservableType.CVE)
terms = Observables.generator(count=2, observable_type=ObservableType.TERMS)
```

### Provide your own observables
`Observables` accepts known fields and arbitrary extra fields via `**kwargs`.
```python
from rosetta import Observables

observables = Observables(
    local_ip=["192.168.10.10"],
    remote_ip=["1.1.1.1"],
    src_host=["abc"],
    dst_host=["xyz"],
    user=["ayman"],
    file_name=["test.zip"],
    custom_field=["custom_value"],
)
```

### Built-in observable fields

Rosetta supports **270+ observable fields** covering traditional and modern infrastructure.

| Category | Fields |
|----------|--------|
| Network (IPv4/IPv6) | `local_ip`, `remote_ip`, `local_ip_v6`, `remote_ip_v6`, `local_port`, `remote_port`, `protocol` |
| Network Extended | `source_ip`, `destination_ip`, `source_port`, `destination_port`, `client_ip`, `server_ip`, `client_port`, `server_port`, `public_ip`, `private_ip`, `nat_source_ip`, `nat_destination_ip`, `client_mac`, `server_hostname`, `client_hostname`, `destination_hostname`, `source_hostname` |
| Hosts & Domains | `src_host`, `dst_host`, `src_domain`, `dst_domain`, `url`, `hostname`, `host`, `domain` |
| HTTP/API | `http_method`, `http_uri`, `http_status_code`, `http_user_agent`, `http_host`, `http_referer`, `api_endpoint`, `api_key`, `api_name`, `request_id`, `response_time_ms`, `content_type` |
| DNS/DHCP | `dns_query`, `dns_response`, `dns_server`, `query_time_ms`, `lease_duration` |
| Kubernetes/Containers | `container_id`, `container_name`, `container_image`, `pod_name`, `pod_uid`, `namespace`, `cluster`, `node_name`, `service_account`, `labels`, `annotations` |
| Cloud Infrastructure | `cloud_provider`, `region`, `availability_zone`, `account_id`, `account_name`, `tenant_id`, `instance_id`, `instance_name`, `instance_type`, `ami_id`, `image_id`, `image_name`, `vpc_id`, `subnet_id`, `security_groups`, `iam_role`, `bucket_name`, `bucket_arn`, `resource_id`, `resource_name`, `resource_type`, `resource_arn`, `resource_attributes` |
| SSL/TLS | `ssl_cipher`, `ssl_version`, `tls_version`, `certificate_cn`, `certificate_issuer`, `ja3_hash`, `ja3s_hash` |
| Threat Detection | `mitre_tactic`, `mitre_technique`, `threat_score`, `threat_level`, `threat_name`, `threat_type`, `signature_id`, `signature_name`, `cve_id`, `cvss_score`, `ioc_type`, `ioc_value` |
| Users & Email | `user`, `sender_email`, `recipient_email`, `email_subject`, `email_body`, `sender`, `recipient`, `subject`, `message_id`, `attachment_name`, `attachment_hash`, `spf_result`, `dkim_result`, `dmarc_result` |
| Authentication | `authentication_method`, `authentication_result`, `mfa_method`, `mfa_result`, `logon_type`, `session_id`, `username`, `account_name` |
| Files | `file_name`, `file_hash`, `file_path`, `file_size`, `file_type`, `file_hash_sha256`, `file_hash_md5`, `file_hash_sha1`, `file_owner` |
| Processes | `win_process`, `win_child_process`, `unix_process`, `unix_child_process`, `win_cmd`, `unix_cmd`, `parent_process_name`, `command_line`, `executable_path`, `working_directory`, `process_name`, `process_guid`, `ppid` |
| Firewall/IDS | `firewall_name`, `rule_name`, `rule_action`, `zone_source`, `zone_destination`, `tcp_flags`, `packets`, `bytes_sent`, `bytes_received` |
| Virtual Machines | `vm_id`, `vm_name`, `hypervisor_type`, `cpu_usage`, `memory_usage` |
| Database | `query_type`, `database_name`, `query`, `query_text`, `execution_time_ms`, `transaction_id`, `affected_rows`, `schema_name` |
| Vulnerability/Compliance | `vulnerability_id`, `vulnerability_name`, `scan_result`, `scan_type`, `compliance_status` |
| Incident Response | `incident_id`, `incident_severity`, `incident_status`, `playbook_id`, `alert_id` |
| Security | `severity`, `action`, `event_id`, `error_code`, `technique`, `cve`, `terms` |
| Alerts & Incidents | `alert_types`, `alert_name`, `incident_types`, `analysts`, `action_status` |
| Common Fields | `status`, `result`, `message`, `description`, `timestamp`, `risk_score`, `priority`, `category`, `tags`, `malware_name`, `malware_type`, `direction`, `geo_location`, `country` |
| Other | `app`, `os`, `sensor`, `entry_type`, `inbound_bytes`, `outbound_bytes` |

**Industry-standard field naming**: Rosetta supports both traditional naming (`local_ip`, `remote_ip`) and industry-standard naming (`source_ip`, `destination_ip`, `client_ip`, `server_ip`) for better compatibility with modern SIEM platforms.

## Events

Rosetta supports generating events in multiple industry-standard log formats:

| Format | Description | Use Case |
|--------|-------------|----------|
| **SYSLOG** | RFC 5424 syslog format | Unix/Linux system logs, network devices |
| **CEF** | Common Event Format | SIEM integration (ArcSight, Splunk) |
| **LEEF** | Log Event Extended Format | IBM QRadar integration |
| **JSON** | Structured JSON format | Modern SIEM, Elasticsearch, cloud platforms |
| **Windows Event XML** | Windows Event Log format | Windows security monitoring, Sysmon |
| **Incidents** | Bundled multi-format events | Incident response testing, SOC training |

### SYSLOG
```python
from rosetta import Events

Events.syslog(count=1)
Events.syslog(count=1, observables=observables)
```

### CEF
```python
Events.cef(count=1, observables=observables)
Events.cef(count=1, observables=observables, required_fields="local_ip,local_port,remote_ip,remote_port,protocol,rule_id,action")
```

### LEEF
```python
Events.leef(count=1, observables=observables)
```

### Windows Event Log (XML)
```python
Events.winevent(count=1, observables=observables)
```

### JSON
```python
Events.json(count=1, observables=observables)
```

### Incidents (bundled events)
```python
Events.incidents(count=1, fields="id,type,duration,analyst,description,events", observables=observables)
```

### Supported incident types
Rosetta includes 11 predefined incident categories:
- Malware
- Phishing
- Access Violation
- Lateral Movement
- Port Scan
- SQL Injection
- Brute Force
- Control Avoidance
- Rogue Device
- Denial of Service
- Account Compromised

## Required fields and presets

Rosetta can require specific fields per event. You can pass `required_fields` directly, or rely on presets.

- Preset file: `rosetta/schema/required_presets.json`
- Keys: `syslog`, `cef`, `leef`, `json`, `winevent`

```python
# Explicit override
Events.syslog(count=1, required_fields="timestamp,hostname,username")

# Use presets (default behavior)
Events.syslog(count=1)
```

If the preset file is missing or empty, Rosetta falls back to built-in defaults.

## Field control and determinism

- If you supply values in `Observables`, those values are used verbatim for matching fields (deterministic control).
- If you do not supply `Observables`, values are generated by built-in generators and heuristics (random but type-aware).
- You can still control structure without observables using `required_fields`, plus `datetime_iso` and vendor/product/version
  parameters on CEF/LEEF/JSON.

```python
from rosetta import Events, Observables

# Deterministic values via Observables
obs = Observables(
    source_ip=["203.0.113.10"],
    destination_ip=["10.0.5.20"],
    user=["alice"],
    http_method=["POST"],
)
Events.json(count=2, observables=obs)

# Control structure without observables
Events.cef(count=1, required_fields="local_ip,local_port,remote_ip,remote_port,protocol,rule_id,action")
```

## Schema validation

Rosetta checks required fields and observables against a supported-fields list and emits warnings for unknown fields.

- Schema file: `rosetta/schema/supported_fields.json`
- Required field presets: `rosetta/schema/required_presets.json`
- Behavior: non-blocking warnings only

```python
from rosetta import Events, Observables

Events.syslog(count=1, observables=Observables(), required_fields="unknown_field")
# Warning: Field 'unknown_field' is not in schema/supported_fields.json
```

### Supported schema fields (1000+ fields)

Representative fields by category (all are supported; full list in `rosetta/schema/supported_fields.json`).

#### Identity & Authentication
`username`, `user`, `user_id`, `user_sid`, `user_dn`, `user_ou`, `user_type`, `user_role`, `user_group`, `actor_username`, `actor_sid`, `actor_id`, `actor_uid`, `actor_arn`, `actor_ip`, `target_username`, `target_user_sid`, `target_user_id`, `target_uid`, `admin_username`, `admin_ip`, `analyst_username`, `creator_username`, `creator_ip`, `display_name`, `full_name`, `email`, `department`, `title`, `manager`

#### Authentication & Sessions
`authentication_method`, `authentication_result`, `authentication_package`, `authentication_status`, `authorization_status`, `session_id`, `session_type`, `session_start`, `session_end`, `session_duration`, `session_timeout`, `token_id`, `token_expiry`, `token_elevation_type`, `mfa_method`, `mfa_result`, `logon_type`, `logon_process`, `logon_guid`, `logon_id`, `logon_time`, `logoff_time`, `login_type`, `login_time`, `last_login`, `last_logon`, `last_password_change`

#### Network & Connectivity
`client_ip`, `client_port`, `client_hostname`, `client_mac`, `server_ip`, `server_port`, `server_hostname`, `source_ip`, `source_port`, `source_mac`, `source_hostname`, `destination_ip`, `destination_port`, `destination_mac`, `destination_hostname`, `local_ip`, `local_port`, `remote_ip`, `remote_port`, `remote_host`, `assigned_ip`, `public_ip`, `private_ip`, `nat_source_ip`, `nat_destination_ip`, `scanner_ip`, `target_ip`, `target_port`, `target_hostname`

#### DNS & DHCP
`dns_server`, `dns_servers`, `dns_query`, `dns_response`, `dns_flags`, `dns_name`, `dnssec_validated`, `query_name`, `query_class`, `query_time_ms`, `query_count`, `response_data`, `response_ip`, `response_count`, `response_ttl`, `authoritative`, `recursion_desired`, `recursion_available`, `lease_duration`, `lease_start`, `lease_expiry`, `lease_state`, `scope_name`, `scope_id`

#### HTTP & Web
`http_method`, `http_uri`, `http_host`, `http_status_code`, `http_protocol`, `http_referer`, `http_user_agent`, `http_query_string`, `request_id`, `request_size`, `request_body_sample`, `request_headers`, `response_code`, `response_size`, `response_time_ms`, `response_body_sample`, `response_headers`, `content_type`, `content_length`, `user_agent`, `referer`, `cookie`, `cookies`, `url`, `url_category`, `url_categories`

#### API Gateway
`gateway_name`, `api_key`, `api_name`, `api_endpoint`, `api_operation`, `api_version`, `api_parameters`, `api_call`, `oauth_client_id`, `oauth_scope`, `rate_limit_policy`, `rate_limit_remaining`, `quota_policy`, `quota_remaining`, `backend_server`, `backend_response_time_ms`, `backend_status_code`, `cache_status`, `cache_hit`

#### Files & Storage
`file_name`, `file_path`, `file_type`, `file_size`, `file_hash`, `file_hash_md5`, `file_hash_sha1`, `file_hash_sha256`, `file_hash_imphash`, `file_owner`, `file_group`, `file_permissions`, `file_attributes`, `file_version`, `original_filename`, `creation_time`, `modification_time`, `deletion_time`, `access_time`, `old_hash`, `new_hash`, `old_size`, `new_size`, `old_permissions`, `new_permissions`

#### Processes & Execution
`process_id`, `process_name`, `process_guid`, `parent_process_name`, `parent_process_guid`, `parent_command_line`, `parent_image`, `pid`, `ppid`, `executable_path`, `command_line`, `command`, `arguments`, `args`, `working_directory`, `cwd`, `image`, `image_path`, `image_loaded`, `start_time`, `stop_time`, `exit_code`, `cpu_time`, `thread_count`, `handle_count`

#### Windows Events
`event_id`, `event_type`, `event_record_id`, `event_category`, `logon_id`, `linked_logon_id`, `virtual_account`, `elevated_token`, `mandatory_label`, `integrity_level`, `terminal_session_id`, `current_directory`, `source_pid`, `source_process_name`, `source_image`, `source_user`, `target_pid`, `target_process_name`, `target_image`, `granted_access`, `call_trace`

#### Registry
`registry_key`, `registry_value_name`, `registry_value_type`, `registry_value_data`, `old_value_type`, `old_value_data`, `new_value_type`, `new_value_data`, `target_object`, `details`, `new_name`

#### Services & Scheduled Tasks
`service_name`, `service_type`, `service_state`, `service_path`, `service_file_name`, `service_start_type`, `service_unit`, `service_account`, `task_name`, `task_content`, `task_id`, `task_status`, `task_result`, `trigger_type`, `trigger_value`, `run_level`, `enabled`, `schedule`, `last_run_time`, `next_run_time`

#### Modules & Drivers
`module_name`, `module_path`, `module_base_address`, `module_size`, `module_version`, `module_parameters`, `module_hash`, `driver_name`, `signature_status`, `signature_level`, `signed`, `signed_by`, `signer`, `load_reason`, `load_result`, `load_address`, `load_time`, `is_kernel_mode`

#### PowerShell & Scripts
`script_block_text`, `script_path`, `script_content`, `script_hash`, `script_content_hash`, `script_block_id`, `script_engine`, `host_application`, `engine_version`, `runspace_id`, `pipeline_id`, `interpreter`, `obfuscation_score`

#### Containers & Kubernetes
`container_id`, `container_name`, `container_image`, `namespace`, `pod_name`, `pod_uid`, `node_name`, `cluster`, `labels`, `annotations`, `resource_limits`, `security_context`, `service_account`, `restart_count`, `exit_code_previous`, `environment_variables`, `cgroup`, `namespace_pid`, `capabilities`

#### Cloud & Infrastructure
`cloud_provider`, `region`, `instance_id`, `instance_name`, `instance_type`, `ami_id`, `vpc_id`, `subnet_id`, `security_groups`, `iam_role`, `resource_type`, `resource_id`, `resource_name`, `resource_arn`, `bucket_name`, `bucket_arn`, `volume_id`, `volume_name`, `volume_type`, `volume_size`, `snapshot_id`, `snapshot_name`, `tags`

#### Virtual Machines
`hypervisor_type`, `vm_id`, `vm_name`, `vm_uuid`, `cpu_usage`, `memory_usage`, `cpu_count`, `memory_mb`, `disk_size_gb`, `network_adapters`, `template_name`, `resource_pool`, `datastore`, `target_vm`, `target_host`, `boot_time_ms`, `uptime_seconds`, `previous_state`

#### Database
`database_name`, `database_role`, `query_type`, `query_text`, `query`, `command_type`, `command_text`, `object_name`, `schema_name`, `execution_status`, `execution_time_ms`, `affected_rows`, `transaction_id`, `privilege`, `error_code`, `error_message`

#### Email & Messaging
`sender`, `recipient`, `sender_email`, `recipient_email`, `sender_domain`, `recipient_domain`, `subject`, `message_id`, `message_size`, `message_count`, `attachment_name`, `attachment_type`, `attachment_size`, `attachment_hash`, `attachment_count`, `attachment_names`, `attachment_types`, `attachment_hashes`, `spam_score`, `phishing_score`, `spf_result`, `dkim_result`, `dmarc_result`

#### Firewall & Network Security
`firewall_name`, `rule_id`, `rule_name`, `rule_type`, `rule_number`, `rule_action`, `acl_name`, `acl_type`, `action`, `action_taken`, `zone_source`, `zone_destination`, `interface_in`, `interface_out`, `input_interface`, `output_interface`, `source_network`, `destination_network`, `port_range`, `tcp_flags`, `packets`, `bytes`, `bytes_sent`, `bytes_received`

#### IDS/IPS & Threat Detection
`signature_id`, `signature_name`, `signature_category`, `attack_type`, `attack_vector`, `attack_category`, `attack_severity`, `threat_type`, `threat_name`, `threat_category`, `threat_score`, `threat_level`, `threat_severity`, `threat_indicator`, `threat_detected`, `detection_name`, `detection_type`, `mitre_tactic`, `mitre_technique`, `cve_id`, `cvss_score`, `cvss_vector`

#### Endpoint Detection
`agent_id`, `agent_version`, `scan_id`, `scan_type`, `scan_result`, `scan_status`, `scan_start`, `scan_end`, `scan_duration`, `finding_id`, `vulnerability_id`, `vulnerability_name`, `vulnerability_description`, `remediation`, `quarantine_id`, `quarantine_status`, `quarantine_path`, `quarantined`, `blocked`

#### SIEM & Incident Response
`incident_id`, `incident_name`, `incident_type`, `incident_severity`, `incident_status`, `alert_id`, `alert_type`, `alert_name`, `playbook_id`, `playbook_name`, `analyst_notes`, `confidence`, `risk_score`, `risk_level`, `severity`, `priority`

#### SSL/TLS
`ssl_protocol`, `ssl_version`, `ssl_cipher`, `ssl_subject`, `ssl_issuer`, `ssl_client_cert_cn`, `ssl_ja3_hash`, `ssl_ja3s_hash`, `tls_version`, `tls_cipher`, `cipher_suite`, `certificate_cn`, `certificate_serial`, `certificate_issuer`, `certificate_subject`, `certificate_validity_start`, `certificate_validity_end`, `certificate_chain_valid`, `certificate_revocation_status`, `ja3_hash`, `ja3s_hash`

#### VPN & Remote Access
`vpn_group`, `tunnel_type`, `tunnel_id`, `encryption_algorithm`, `idle_timeout`, `session_timeout`, `bytes_quota`, `client_version`

#### Wireless
`ssid`, `ap_name`, `ap_mac`, `bssid`, `eap_type`, `vlan_assigned`, `radio_type`, `channel`, `rssi`, `snr`, `roam_count`, `association_time`, `data_rate`, `power_save_mode`

#### Network Access Control
`identity_group`, `policy_matched`, `nas_ip`, `nas_port`, `calling_station_id`, `called_station_id`, `radius_attributes`, `switch_ip`, `switch_port`, `vlan_id`, `vlan_name`, `posture_status`, `endpoint_policy`

#### Data Loss Prevention
`data_classification`, `sensitive_data_flag`, `sensitive_data_types`, `sensitive_data_detected`, `sensitive_data_added`, `sensitive_data_removed`, `pattern_matched`, `bytes_inspected`, `dlp_verdict`, `dlp_violation`, `dlp_scan_result`, `masked_fields`, `channel_type`

#### Vulnerability Management
`scanner_ip`, `target_os`, `target_os_version`, `service_detected`, `service_version`, `banner`, `vulnerability_checks`, `vulnerabilities_found`, `vulnerabilities_critical`, `vulnerabilities_high`, `vulnerabilities_medium`, `vulnerabilities_low`, `vulnerabilities_info`, `compliance_score`, `exploit_available`, `patch_available`, `first_detected`, `last_detected`

#### Mobile Device Management
`device_type`, `device_id`, `device_name`, `enrollment_status`, `enrollment_method`, `enrollment_time`, `serial_number`, `imei`, `jailbreak_status`, `passcode_compliant`, `installed_apps_count`, `managed_apps_count`, `certificates_installed`, `profiles_installed`

#### Privileged Access Management
`vault_name`, `checkout_id`, `checkout_reason`, `checkout_time`, `checkin_time`, `session_duration_limit`, `recording_enabled`, `recording_id`, `target_account`, `target_account_type`, `target_system`, `credential_type`, `credential_name`

#### Application Logs
`application`, `application_name`, `application_version`, `environment`, `log_level`, `logger_name`, `message`, `exception_type`, `exception_message`, `stack_trace`, `thread_name`, `thread_id`, `span_id`, `trace_id`, `custom_fields`

#### Audit & Compliance
`audit_id`, `operation`, `operation_type`, `modification_type`, `change_type`, `change_description`, `change_reason`, `old_value`, `new_value`, `justification`, `approval_id`, `approval_status`, `approver`, `workflow_id`, `compliance_status`, `policy_name`, `policy_violation`

#### Metrics & Performance
`metric_name`, `metric_value`, `threshold`, `cpu_usage`, `memory_usage`, `disk_usage`, `throughput_bps`, `connection_count`, `response_time_ms`, `execution_time_ms`, `duration`, `jitter_ms`, `offset_ms`


## Heuristic value generation

When a field has no explicit value, Rosetta infers a reasonable value based on name patterns. This makes large schemas usable without hardcoding every field.

### Supported field patterns

| Category | Patterns |
|----------|----------|
| Network | `*_ip`, `*_ipv6`, `*_port`, `*_mac`, `*_domain`, `*_hostname`, `*_url` |
| Identity | `*_email`, `*_user`, `*_sid`, `*_arn` |
| Identifiers | `*_id`, `*_uuid`, `*_guid` |
| Hashing | `*_hash`, `*_md5`, `*_sha1`, `*_sha256` |
| Status | `*_status`, `*_result`, `*_outcome`, `*_verdict`, `*_action` |
| Metrics | `*_size`, `*_bytes`, `*_count`, `*_duration`, `*_ms`, `*_score`, `*_percent` |
| Time | `*_time`, `*_timestamp`, `*_date` |
| HTTP/API | `http_*`, `request_*`, `response_*`, `api_*` |
| DNS/DHCP | `dns_*`, `dhcp_*` |
| Authentication | `auth_*`, `mfa_*`, `token_*`, `session_*`, `role_*`, `permission_*` |
| Kubernetes | `namespace`, `pod_*`, `container_*`, `node_*`, `cluster`, `labels`, `annotations`, `service_account` |
| Threats | `vulnerability_*`, `cve`, `cvss_*`, `threat_*`, `mitre_*`, `ioc_*` |
| Email/SMTP | `sender_*`, `recipient_*`, `smtp_*`, `dkim_*`, `spf_*`, `dmarc_*` |
| Boolean | `is_*`, `*_enabled`, `*_flag` |

## Sender

Send synthetic events to TCP/UDP/HTTP/HTTPS endpoints using multi-threaded workers.

### Supported data types
- `SYSLOG`
- `CEF`
- `LEEF`
- `WINEVENT`
- `JSON`
- `INCIDENT`

### Destination formats
- UDP: `udp:127.0.0.1:514`
- TCP: `tcp:127.0.0.1:514`
- HTTP: `http://127.0.0.1:8000/endpoint`
- HTTPS: `https://127.0.0.1:8000/endpoint`

### Example
```python
from rosetta import Sender, WorkerTypeEnum

# UDP syslog
udp_worker = Sender(
    data_type=WorkerTypeEnum.SYSLOG,
    destination="udp:127.0.0.1:514",
    observables=observables,
    count=5,
    interval=2
)
udp_worker.start()

# HTTP JSON
http_worker = Sender(
    data_type=WorkerTypeEnum.JSON,
    destination="http://127.0.0.1:8000/logs",
    observables=observables,
    count=5,
    interval=2
)
http_worker.start()
```

## Converter

```python
from rosetta import Converter, ConverterToEnum, ConverterFromEnum

cef_log = "CEF:0|Security|IDS|1.0|Alert|10|src=192.168.0.1 dst=192.168.0.2 act=blocked"
converted = Converter.convert(from_type=ConverterFromEnum.CEF, to_type=ConverterToEnum.JSON, data=cef_log)
```

## Testing

```sh
python3 -m unittest discover -s tests
```

## Database telemetry

Rosetta can generate realistic database activity logs including normal operations and attack patterns.

### Supported query types
`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `ALTER`, `CREATE`, `DROP`, `TRUNCATE`, `GRANT`, `REVOKE`, `MERGE`, `CALL`

### Attack patterns included
- SQL injection queries
- Unauthorized data manipulation
- Privilege escalation attempts

## OWASP Top 10 attack simulation

Rosetta includes built-in OWASP Top 10 attack technique indicators:
- Injection (SQL, Command)
- Broken Authentication and Session Management
- Cross-Site Scripting (XSS)
- Broken Access Control
- Security Misconfiguration
- Insecure Cryptographic Storage
- Insufficient Transport Layer Protection
- Unvalidated Redirects and Forwards
- Using Components with Known Vulnerabilities
- Insufficient Logging and Monitoring

## Network protocols

Supported protocols for telemetry generation:
`TCP`, `UDP`, `HTTP`, `SSL`, `SQL`, `SSH`, `FTP`, `RTP`, `RDP`

## Windows telemetry

Rosetta generates realistic Windows endpoint data including:
- 18 common Windows processes (explorer.exe, svchost.exe, lsass.exe, etc.)
- PowerShell commands for attack simulation
- Windows Event Log XML templates (Sysmon, Security events)

## Examples

See the `examples/` directory for complete usage examples:
- `observables.py` - Generate indicators
- `events_formats.py` - Create events in different formats
- `incidents.py` - Build incident bundles
- `sender_tcp_udp_http.py` - Send events to endpoints
- `converter.py` - Convert between formats
- `k8s_fields.py` - Kubernetes field generation
- `presets_schema.py` - Schema validation

## Notes

- Some observable generators fetch from public sources. When offline, Rosetta falls back to synthetic values.
- Preset and schema files are generated from the CSV mapping in the project root and can be updated as your schema evolves.
