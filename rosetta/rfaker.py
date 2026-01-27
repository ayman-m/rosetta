import random
import requests
import warnings
import ipaddress
import csv
import hashlib
import itertools
import time
import json
from pathlib import Path
from string import Formatter
from enum import Enum
from functools import reduce
from faker import Faker
from datetime import datetime, timedelta
from typing import Optional, List
from rosetta.constants.sources import BAD_IP_SOURCES, GOOD_IP_SOURCES, BAD_URL_SOURCES, GOOD_URL_SOURCES, \
    BAD_SHA256_SOURCES, GOOD_SHA256_SOURCES, CVE_SOURCES, TERMS_SOURCES
from rosetta.constants.systems import OS_LIST, UNIX_CMD, WINDOWS_CMD, WIN_PROCESSES, WIN_EVENTS
from rosetta.constants.attributes import INCIDENTS_TYPES, SEVERITIES, ATTACK_TECHNIQUES
from rosetta.constants.sensors import ACTIONS, PROTOCOLS, TECHNIQUES, ERROR_CODE
from rosetta.constants.db import QUERY_TYPE, DATABASE_NAME, QUERY


def _load_supported_fields_list() -> List[str]:
    supported_path = Path(__file__).resolve().parent / "schema" / "supported_fields.json"
    try:
        with supported_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


SUPPORTED_FIELDS: List[str] = _load_supported_fields_list()


class ObservableType(Enum):
    IP = 'ip'
    URL = 'url'
    SHA256 = 'sha256'
    CVE = 'cve'
    TERMS = 'terms'


class ObservableKnown(Enum):
    BAD = 'bad'
    GOOD = 'good'


class Observables:
    def __init__(self, local_ip: list = None, remote_ip: Optional[list] = None, local_ip_v6: list = None,
                remote_ip_v6: Optional[list] = None, src_host: Optional[list] = None,
                dst_host: Optional[list] = None, src_domain: Optional[list] = None, dst_domain: Optional[list] = None,
                sender_email: Optional[list] = None, recipient_email: Optional[list] = None,
                email_subject: Optional[list] = None, email_body: Optional[list] = None,
                url: Optional[list] = None, local_port: Optional[list] = None, remote_port: Optional[list] = None,
                protocol: Optional[list] = None, inbound_bytes: Optional[list] = None,
                outbound_bytes: Optional[list] = None, app: Optional[list] = None, os: Optional[list] = None,
                user: Optional[list] = None, cve: Optional[list] = None, file_name: Optional[list] = None,
                file_hash: Optional[list] = None, win_cmd: Optional[list] = None, unix_cmd: Optional[list] = None,
                win_process: Optional[list] = None, win_child_process: Optional[list] = None,
                unix_process: Optional[list] = None, unix_child_process: Optional[list] = None,
                technique: Optional[list] = None, entry_type: Optional[list] = None, severity: Optional[list] = None,
                sensor: Optional[list] = None, action: Optional[list] = None, event_id: Optional[list] = None,
                error_code: Optional[list] = None, terms: Optional[list] = None, alert_types: Optional[list] = None,
                alert_name: Optional[list] = None, incident_types: Optional[list] = None,
                analysts: Optional[list] = None, action_status: Optional[list] = None, query_type: Optional[list] = None,
                database_name: Optional[list] = None, query: Optional[list] = None,
                # Network Extended (Industry-standard naming)
                source_ip: Optional[list] = None, destination_ip: Optional[list] = None,
                source_port: Optional[list] = None, destination_port: Optional[list] = None,
                client_ip: Optional[list] = None, server_ip: Optional[list] = None,
                client_port: Optional[list] = None, server_port: Optional[list] = None,
                public_ip: Optional[list] = None, private_ip: Optional[list] = None,
                nat_source_ip: Optional[list] = None, nat_destination_ip: Optional[list] = None,
                client_mac: Optional[list] = None, server_hostname: Optional[list] = None,
                client_hostname: Optional[list] = None, destination_hostname: Optional[list] = None,
                source_hostname: Optional[list] = None,
                # HTTP/API
                http_method: Optional[list] = None, http_uri: Optional[list] = None,
                http_status_code: Optional[list] = None, http_user_agent: Optional[list] = None,
                http_host: Optional[list] = None, http_referer: Optional[list] = None,
                api_endpoint: Optional[list] = None, api_key: Optional[list] = None,
                api_name: Optional[list] = None, request_id: Optional[list] = None,
                response_time_ms: Optional[list] = None, content_type: Optional[list] = None,
                # DNS/DHCP
                dns_query: Optional[list] = None, dns_response: Optional[list] = None,
                dns_server: Optional[list] = None, query_time_ms: Optional[list] = None,
                lease_duration: Optional[list] = None,
                # Kubernetes/Containers
                container_id: Optional[list] = None, container_name: Optional[list] = None,
                container_image: Optional[list] = None, pod_name: Optional[list] = None,
                pod_uid: Optional[list] = None, namespace: Optional[list] = None,
                cluster: Optional[list] = None, node_name: Optional[list] = None,
                service_account: Optional[list] = None, labels: Optional[list] = None,
                annotations: Optional[list] = None,
                # Cloud Infrastructure
                cloud_provider: Optional[list] = None, region: Optional[list] = None,
                instance_id: Optional[list] = None, instance_type: Optional[list] = None,
                vpc_id: Optional[list] = None, subnet_id: Optional[list] = None,
                security_groups: Optional[list] = None, iam_role: Optional[list] = None,
                bucket_name: Optional[list] = None, resource_id: Optional[list] = None,
                resource_type: Optional[list] = None, resource_arn: Optional[list] = None,
                # SSL/TLS
                ssl_cipher: Optional[list] = None, ssl_version: Optional[list] = None,
                tls_version: Optional[list] = None, certificate_cn: Optional[list] = None,
                certificate_issuer: Optional[list] = None, ja3_hash: Optional[list] = None,
                ja3s_hash: Optional[list] = None,
                # Threat Detection
                mitre_tactic: Optional[list] = None, mitre_technique: Optional[list] = None,
                threat_score: Optional[list] = None, threat_level: Optional[list] = None,
                threat_name: Optional[list] = None, threat_type: Optional[list] = None,
                signature_id: Optional[list] = None, signature_name: Optional[list] = None,
                cve_id: Optional[list] = None, cvss_score: Optional[list] = None,
                ioc_type: Optional[list] = None, ioc_value: Optional[list] = None,
                # Process Extended
                parent_process_name: Optional[list] = None, command_line: Optional[list] = None,
                executable_path: Optional[list] = None, working_directory: Optional[list] = None,
                process_name: Optional[list] = None, process_guid: Optional[list] = None,
                ppid: Optional[list] = None,
                # File Extended
                file_path: Optional[list] = None, file_size: Optional[list] = None,
                file_type: Optional[list] = None, file_hash_sha256: Optional[list] = None,
                file_hash_md5: Optional[list] = None, file_hash_sha1: Optional[list] = None,
                file_owner: Optional[list] = None,
                # Email Extended
                sender: Optional[list] = None, recipient: Optional[list] = None,
                subject: Optional[list] = None, message_id: Optional[list] = None,
                attachment_name: Optional[list] = None, attachment_hash: Optional[list] = None,
                spf_result: Optional[list] = None, dkim_result: Optional[list] = None,
                dmarc_result: Optional[list] = None,
                # Authentication
                authentication_method: Optional[list] = None, authentication_result: Optional[list] = None,
                mfa_method: Optional[list] = None, mfa_result: Optional[list] = None,
                logon_type: Optional[list] = None, session_id: Optional[list] = None,
                username: Optional[list] = None, account_name: Optional[list] = None,
                # Firewall/IDS
                firewall_name: Optional[list] = None, rule_name: Optional[list] = None,
                rule_action: Optional[list] = None, zone_source: Optional[list] = None,
                zone_destination: Optional[list] = None, tcp_flags: Optional[list] = None,
                packets: Optional[list] = None, bytes_sent: Optional[list] = None,
                bytes_received: Optional[list] = None,
                # Virtual Machines
                vm_id: Optional[list] = None, vm_name: Optional[list] = None,
                hypervisor_type: Optional[list] = None, cpu_usage: Optional[list] = None,
                memory_usage: Optional[list] = None,
                # Database Extended
                query_text: Optional[list] = None, execution_time_ms: Optional[list] = None,
                transaction_id: Optional[list] = None, affected_rows: Optional[list] = None,
                schema_name: Optional[list] = None,
                # Vulnerability/Compliance
                vulnerability_id: Optional[list] = None, vulnerability_name: Optional[list] = None,
                scan_result: Optional[list] = None, scan_type: Optional[list] = None,
                compliance_status: Optional[list] = None,
                # Incident Response
                incident_id: Optional[list] = None, incident_severity: Optional[list] = None,
                incident_status: Optional[list] = None, playbook_id: Optional[list] = None,
                alert_id: Optional[list] = None,
                # Additional commonly used
                hostname: Optional[list] = None, host: Optional[list] = None,
                domain: Optional[list] = None, status: Optional[list] = None,
                result: Optional[list] = None, message: Optional[list] = None,
                description: Optional[list] = None, timestamp: Optional[list] = None,
                risk_score: Optional[list] = None, priority: Optional[list] = None,
                category: Optional[list] = None, tags: Optional[list] = None,
                malware_name: Optional[list] = None, malware_type: Optional[list] = None,
                direction: Optional[list] = None, geo_location: Optional[list] = None,
                country: Optional[list] = None, **kwargs):
        # Original fields
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.local_ip_v6 = local_ip_v6
        self.remote_ip_v6 = remote_ip_v6
        self.src_host = src_host
        self.dst_host = dst_host
        self.src_domain = src_domain
        self.dst_domain = dst_domain
        self.sender_email = sender_email
        self.recipient_email = recipient_email
        self.email_subject = email_subject
        self.email_body = email_body
        self.url = url
        self.local_port = local_port
        self.remote_port = remote_port
        self.protocol = protocol
        self.inbound_bytes = inbound_bytes
        self.outbound_bytes = outbound_bytes
        self.app = app
        self.os = os
        self.user = user
        self.cve = cve
        self.file_name = file_name
        self.file_hash = file_hash
        self.win_cmd = win_cmd
        self.unix_cmd = unix_cmd
        self.win_process = win_process
        self.win_child_process = win_child_process
        self.unix_process = unix_process
        self.unix_child_process = unix_child_process
        self.technique = technique
        self.entry_type = entry_type
        self.severity = severity
        self.sensor = sensor
        self.action = action
        self.event_id = event_id
        self.error_code = error_code
        self.terms = terms
        self.incident_types = incident_types
        self.analysts = analysts
        self.alert_types = alert_types
        self.alert_name = alert_name
        self.action_status = action_status
        self.query_type = query_type
        self.database_name = database_name
        self.query = query

        # Network Extended (Industry-standard naming)
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.public_ip = public_ip
        self.private_ip = private_ip
        self.nat_source_ip = nat_source_ip
        self.nat_destination_ip = nat_destination_ip
        self.client_mac = client_mac
        self.server_hostname = server_hostname
        self.client_hostname = client_hostname
        self.destination_hostname = destination_hostname
        self.source_hostname = source_hostname

        # HTTP/API
        self.http_method = http_method
        self.http_uri = http_uri
        self.http_status_code = http_status_code
        self.http_user_agent = http_user_agent
        self.http_host = http_host
        self.http_referer = http_referer
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.api_name = api_name
        self.request_id = request_id
        self.response_time_ms = response_time_ms
        self.content_type = content_type

        # DNS/DHCP
        self.dns_query = dns_query
        self.dns_response = dns_response
        self.dns_server = dns_server
        self.query_time_ms = query_time_ms
        self.lease_duration = lease_duration

        # Kubernetes/Containers
        self.container_id = container_id
        self.container_name = container_name
        self.container_image = container_image
        self.pod_name = pod_name
        self.pod_uid = pod_uid
        self.namespace = namespace
        self.cluster = cluster
        self.node_name = node_name
        self.service_account = service_account
        self.labels = labels
        self.annotations = annotations

        # Cloud Infrastructure
        self.cloud_provider = cloud_provider
        self.region = region
        self.instance_id = instance_id
        self.instance_type = instance_type
        self.vpc_id = vpc_id
        self.subnet_id = subnet_id
        self.security_groups = security_groups
        self.iam_role = iam_role
        self.bucket_name = bucket_name
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.resource_arn = resource_arn

        # SSL/TLS
        self.ssl_cipher = ssl_cipher
        self.ssl_version = ssl_version
        self.tls_version = tls_version
        self.certificate_cn = certificate_cn
        self.certificate_issuer = certificate_issuer
        self.ja3_hash = ja3_hash
        self.ja3s_hash = ja3s_hash

        # Threat Detection
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self.threat_score = threat_score
        self.threat_level = threat_level
        self.threat_name = threat_name
        self.threat_type = threat_type
        self.signature_id = signature_id
        self.signature_name = signature_name
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.ioc_type = ioc_type
        self.ioc_value = ioc_value

        # Process Extended
        self.parent_process_name = parent_process_name
        self.command_line = command_line
        self.executable_path = executable_path
        self.working_directory = working_directory
        self.process_name = process_name
        self.process_guid = process_guid
        self.ppid = ppid

        # File Extended
        self.file_path = file_path
        self.file_size = file_size
        self.file_type = file_type
        self.file_hash_sha256 = file_hash_sha256
        self.file_hash_md5 = file_hash_md5
        self.file_hash_sha1 = file_hash_sha1
        self.file_owner = file_owner

        # Email Extended
        self.sender = sender
        self.recipient = recipient
        self.subject = subject
        self.message_id = message_id
        self.attachment_name = attachment_name
        self.attachment_hash = attachment_hash
        self.spf_result = spf_result
        self.dkim_result = dkim_result
        self.dmarc_result = dmarc_result

        # Authentication
        self.authentication_method = authentication_method
        self.authentication_result = authentication_result
        self.mfa_method = mfa_method
        self.mfa_result = mfa_result
        self.logon_type = logon_type
        self.session_id = session_id
        self.username = username
        self.account_name = account_name

        # Firewall/IDS
        self.firewall_name = firewall_name
        self.rule_name = rule_name
        self.rule_action = rule_action
        self.zone_source = zone_source
        self.zone_destination = zone_destination
        self.tcp_flags = tcp_flags
        self.packets = packets
        self.bytes_sent = bytes_sent
        self.bytes_received = bytes_received

        # Virtual Machines
        self.vm_id = vm_id
        self.vm_name = vm_name
        self.hypervisor_type = hypervisor_type
        self.cpu_usage = cpu_usage
        self.memory_usage = memory_usage

        # Database Extended
        self.query_text = query_text
        self.execution_time_ms = execution_time_ms
        self.transaction_id = transaction_id
        self.affected_rows = affected_rows
        self.schema_name = schema_name

        # Vulnerability/Compliance
        self.vulnerability_id = vulnerability_id
        self.vulnerability_name = vulnerability_name
        self.scan_result = scan_result
        self.scan_type = scan_type
        self.compliance_status = compliance_status

        # Incident Response
        self.incident_id = incident_id
        self.incident_severity = incident_severity
        self.incident_status = incident_status
        self.playbook_id = playbook_id
        self.alert_id = alert_id

        # Additional commonly used
        self.hostname = hostname
        self.host = host
        self.domain = domain
        self.status = status
        self.result = result
        self.message = message
        self.description = description
        self.timestamp = timestamp
        self.risk_score = risk_score
        self.priority = priority
        self.category = category
        self.tags = tags
        self.malware_name = malware_name
        self.malware_type = malware_type
        self.direction = direction
        self.geo_location = geo_location
        self.country = country

        # Handle any additional kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)
    @staticmethod
    def _get_observables_from_source(source: dict) -> list:
        """
        Fetches observables from a given source and returns them as a list.

        Args:
        - source: A dictionary containing information about the source, including its type, URL, structure, and value
                column or key.

        Returns:
        - A list of observables fetched from the source.

        Raises:
        - Exception: If the HTTP status code of the response is not 200 OK.
        """
        results = []
        source_type = source.get('type')
        response = requests.get(source['url'])
        if response.status_code != 200:
            raise Exception(f"Failed to get data from {source['url']}, status code {response.status_code}")
        if source['structure'] == 'lines':
            results = [line.strip() for line in response.text.strip().split("\n") if not line.startswith("#")]
        elif source['structure'] == 'csv':
            rows = csv.reader(filter(lambda line: not line.startswith('#'), response.text.strip().split('\n')),
                            delimiter=source['delimiter'])
            for row in rows:
                results.append(row[source['value_column']])
        elif source['structure'] == 'json':
            results = reduce(lambda d, key: d[key] if key != source['value_key'].split('.')[-1] else [i[key]
                                                                                                    for i in d],
                            source['value_key'].split('.'), response.json())
        random.shuffle(results)
        if source_type == 'subnet':
            ip_addresses = []
            for subnet in results:
                for ip in ipaddress.IPv4Network(subnet):
                    ip_addresses.append(str(ip))
                if len(ip_addresses) > 1000:
                    break
            return ip_addresses
        return results

    @staticmethod
    def _create_faker():
        """
        Returns:
            Faker instance.
        """
        return Faker()

    @classmethod
    def generator(cls, count: int, observable_type: ObservableType,
                known: ObservableKnown = ObservableKnown.BAD) -> List[str]:
        """
        Generates a list of observable values based on the given observable type and known status, with a desired count.
        The function attempts to obtain the values from sources defined in configuration files. If the function fails to
        retrieve values from any configured source, it generates fake values using Faker library.

        Args:
        - count: The number of observables to generate.
        - observable_type: The type of observable to generate (e.g., IP, URL, SHA256, CVE, Terms).
        - known: The known status of the observable (e.g., BAD, GOOD).

        Returns:
        - A list of generated observables.

        Raises:
        - Exception: If the function fails to retrieve data from any configured source with an HTTP status code other
            than 200.
        """
        faker = cls._create_faker()
        gen_observables = []
        if observable_type == ObservableType.IP and known == ObservableKnown.BAD:
            for source in BAD_IP_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of a bad ip , generating a random IP.")
                for i in range(count):
                    gen_observables.append(faker.ipv4())
        elif observable_type == ObservableType.IP and known == ObservableKnown.GOOD:
            for source in GOOD_IP_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of a good ip , generating a random IP.")
                for i in range(count):
                    gen_observables.append(faker.ipv4())
        elif observable_type == ObservableType.URL and known == ObservableKnown.BAD:
            for source in BAD_URL_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of a bad url , generating a random url.")
                for i in range(count):
                    gen_observables.append(faker.url())
        elif observable_type == ObservableType.URL and known == ObservableKnown.GOOD:
            for source in GOOD_URL_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of a good url , generating a random url.")
                for i in range(count):
                    gen_observables.append(faker.url())
        elif observable_type == ObservableType.SHA256 and known == ObservableKnown.BAD:
            for source in BAD_SHA256_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of a bad hash , generating a random hash.")
                for i in range(count):
                    random_string = faker.text(max_nb_chars=50)
                    gen_observables.append(hashlib.sha256(random_string.encode()).hexdigest())
        elif observable_type == ObservableType.SHA256 and known == ObservableKnown.GOOD:
            for source in GOOD_SHA256_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of a good hash , generating a random hash.")
                for i in range(count):
                    random_string = faker.text(max_nb_chars=50)
                    gen_observables.append(hashlib.sha256(random_string.encode()).hexdigest())
        elif observable_type == ObservableType.CVE:
            for source in CVE_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of a cve , generating a random cve.")
                for i in range(count):
                    fake_cve = "CVE-" + faker.numerify(text="####-####")
                    gen_observables.append(fake_cve)
        elif observable_type == ObservableType.TERMS:
            for source in TERMS_SOURCES:
                try:
                    gen_observables = cls._get_observables_from_source(source)[:count]
                    break
                except Exception as e:
                    warnings.warn(f"Failed to connect to source: {source['url']} with error: {e}.")
                    continue
            if not gen_observables:
                warnings.warn(f"No source of terms , generating random terms.")
                for i in range(count):
                    gen_observables.append(faker.sentence(nb_words=5))
        return gen_observables


class Events:

    faker = Faker()
    field_timings = {}
    required_presets = {}
    supported_fields = set()
    warned_fields = set()

    @classmethod
    def get_supported_fields(cls) -> List[str]:
        return list(SUPPORTED_FIELDS)

    @classmethod
    def _load_required_presets(cls):
        if cls.required_presets:
            return
        presets_path = Path(__file__).resolve().parent / "schema" / "required_presets.json"
        try:
            with presets_path.open("r", encoding="utf-8") as handle:
                cls.required_presets = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError):
            cls.required_presets = {}

    @classmethod
    def _get_required_fields(cls, data_type: str) -> list:
        cls._load_required_presets()
        return cls.required_presets.get(data_type, [])

    @staticmethod
    def _fallback_required_fields(data_type: str) -> list:
        fallback_map = {
            "syslog": ["pid", "host", "user", "unix_process", "unix_cmd"],
            "cef": ["local_ip", "local_port", "remote_ip", "remote_port", "protocol", "rule_id", "action"],
            "leef": ["local_ip", "local_port", "host", "url", "protocol", "response_code", "action"],
            "winevent": [
                "process_id",
                "new_process_id",
                "thread_id",
                "target_pid",
                "subject_login_id",
                "win_user_id",
                "destination_login_id",
                "privilege_list",
                "win_process",
                "src_host",
                "user",
                "win_cmd",
                "source_network_address",
                "local_port",
                "transmitted_services",
                "file_name",
                "src_domain",
            ],
            "json": ["user", "host"],
        }
        return fallback_map.get(data_type, [])

    @classmethod
    def _required_fields_or_fallback(cls, data_type: str) -> list:
        required_fields = cls._get_required_fields(data_type)
        if required_fields:
            return required_fields
        return cls._fallback_required_fields(data_type)

    @classmethod
    def _load_supported_fields(cls):
        if cls.supported_fields:
            return
        supported_path = Path(__file__).resolve().parent / "schema" / "supported_fields.json"
        try:
            with supported_path.open("r", encoding="utf-8") as handle:
                cls.supported_fields = set(json.load(handle))
        except (FileNotFoundError, json.JSONDecodeError):
            cls.supported_fields = set()

    @classmethod
    def _validate_fields(cls, required_fields_list: list, observables_dict: dict):
        cls._load_supported_fields()
        if not cls.supported_fields:
            return
        to_check = set(required_fields_list)
        to_check.update(observables_dict.keys())
        unknown = sorted(field for field in to_check if field not in cls.supported_fields)
        for field in unknown:
            if field in cls.warned_fields:
                continue
            warnings.warn(f"Field '{field}' is not in schema/supported_fields.json; generated value may be generic.")
            cls.warned_fields.add(field)

    @staticmethod
    def _set_field(field):
        """
        Returns:
            Field value.
        """

        faker = Events.faker

        # Define default generators for each field
        default_generators = {
            "pid": lambda: faker.random_int(min=1000, max=65535),
            "src_host": faker.hostname,
            "dst_host": faker.hostname,
            "user": faker.user_name,
            "unix_process": lambda: "sudo",
            "unix_child_process": lambda: "sudo",
            "unix_cmd": lambda: random.choice(UNIX_CMD),
            "technique": lambda: random.choice(ATTACK_TECHNIQUES),
            "entry_type": lambda: faker.sentence(nb_words=2),
            "sensor": lambda: faker.sentence(nb_words=1),
            "event_id": lambda: faker.random_int(min=10, max=1073741824),
            "error_code": lambda: faker.random_int(min=1000, max=5000),
            "terms": lambda: faker.sentence(nb_words=10),
            "alert_types": lambda: faker.sentence(nb_words=1),
            "action_status": lambda: random.choice(ACTIONS),
            "severity": lambda: random.choice(SEVERITIES),
            "local_ip": faker.ipv4,
            "local_port": lambda: faker.random_int(min=1024, max=65535),
            "remote_ip": lambda: Observables.generator(
                observable_type=ObservableType.IP,
                known=ObservableKnown.BAD,
                count=1
            )[0],
            "local_ip_v6": faker.ipv6,
            "remote_ip_v6": faker.ipv6,
            "remote_port": lambda: faker.random_int(min=1024, max=65535),
            "dst_url": lambda: Observables.generator(
                observable_type=ObservableType.URL,
                known=ObservableKnown.BAD,
                count=1
            )[0],
            "inbound_bytes": lambda: faker.random_int(min=10, max=1073741824),
            "outbound_bytes": lambda: faker.random_int(min=10, max=1073741824),
            "app": lambda: faker.sentence(nb_words=2),
            "os": lambda: random.choice(OS_LIST),
            "protocol": lambda: random.choice(PROTOCOLS),
            "rule_id": lambda: faker.random_int(min=1, max=200),
            "action": lambda: random.choice(ACTIONS),
            "src_domain": faker.domain_name,
            "dst_domain": faker.domain_name,
            "sender_email": faker.email,
            "recipient_email": faker.email,
            "email_subject": lambda: faker.sentence(nb_words=6),
            "email_body": lambda: faker.sentence(nb_words=50),
            "attachment_hash": lambda: Observables.generator(
                observable_type=ObservableType.SHA256,
                known=ObservableKnown.BAD,
                count=1
            )[0],
            "spam_score": lambda: faker.random_int(min=1, max=5),
            "method": lambda: random.choice(TECHNIQUES).get('mechanism'),
            "url": lambda: random.choice(TECHNIQUES).get('indicator'),
            "user_agent": faker.user_agent,
            "referer": lambda: Observables.generator(
                observable_type=ObservableType.URL,
                known=ObservableKnown.BAD,
                count=1
            )[0],
            "response_code": lambda: random.choice(ERROR_CODE),
            "response_size": lambda: faker.random_int(min=100, max=10000),
            "attack_type": lambda: random.choice(TECHNIQUES).get('technique'),
            "cookies": lambda: f"{faker.word()}={faker.uuid4()}",
            "guid": faker.uuid4,
            "transmitted_services": lambda: faker.sentence(nb_words=5),
            "process_id": faker.random_int,
            "new_process_id": faker.random_int,
            "thread_id": faker.random_int,
            "target_pid": faker.random_int,
            "subject_login_id": faker.random_int,
            "win_user_id": lambda: "S-1-" + str(faker.random_int()),
            "destination_login_id": faker.random_int,
            "privilege_list": lambda: faker.sentence(nb_words=5),
            "event_record_id": lambda: faker.random_int(min=1, max=999),
            "win_process": lambda: random.choice(WIN_PROCESSES),
            "win_cmd": lambda: random.choice(WINDOWS_CMD),
            "win_child_process": lambda: random.choice(WIN_PROCESSES),
            "source_network_address": faker.ipv4_private,
            "file_name": faker.file_name,
            "cve": lambda: Observables.generator(
                observable_type=ObservableType.CVE,
                count=1
            )[0],
            "file_hash": lambda: Observables.generator(
                observable_type=ObservableType.SHA256,
                known=ObservableKnown.BAD,
                count=1
            )[0],
            "incident_types": lambda: random.choice(INCIDENTS_TYPES),
            "analysts": lambda: [faker.unique.first_name() for _ in range(10)],
            "duration": lambda: random.randint(1, 5),
            "log_id": faker.uuid4,
            "alert_name": lambda: faker.sentence(nb_words=4),
            "query_type": lambda: random.choice(QUERY_TYPE),
            "database_name": lambda: random.choice(DATABASE_NAME),
            "query": lambda: random.choice(QUERY),
        }

        if field in default_generators:
            generator = default_generators[field]
            field_value = generator() if callable(generator) else generator()
        else:
            field_value = Events._infer_field_value(field, faker)

        return field_value

    @staticmethod
    def _infer_field_value(field, faker):
        field_lower = field.lower()
        now = datetime.now().isoformat()

        if field_lower in {"true", "false"}:
            return random.choice([True, False])
        if field_lower.startswith("is_") or field_lower.endswith("_enabled") or field_lower.endswith("_flag"):
            return random.choice([True, False])
        if field_lower.startswith("auth_") or field_lower.startswith("mfa_"):
            return random.choice(["success", "failure", "challenge"])
        if field_lower.startswith("token_") or field_lower.endswith("_token"):
            return faker.uuid4()
        if field_lower.startswith("session_"):
            return faker.uuid4()
        if field_lower.startswith("role_") or field_lower.endswith("_role"):
            return faker.job()
        if field_lower.startswith("group_") or field_lower.endswith("_group"):
            return faker.word()
        if field_lower.startswith("entitlement") or field_lower.startswith("permission"):
            return faker.word()
        if field_lower.endswith("_ip") or field_lower in {"ip", "ip_address"}:
            return faker.ipv4()
        if "ipv6" in field_lower or field_lower.endswith("_ip_v6") or field_lower.endswith("_ipv6"):
            return faker.ipv6()
        if field_lower.endswith("_port"):
            return faker.random_int(min=1, max=65535)
        if field_lower.endswith("_port_name"):
            return random.choice(["http", "https", "ssh", "rdp", "smtp"])
        if field_lower.endswith("_mac") or "mac_address" in field_lower:
            return faker.mac_address()
        if field_lower.endswith("_domain") or field_lower == "domain":
            return faker.domain_name()
        if field_lower.endswith("_hostname") or field_lower in {"hostname", "host_name"}:
            return faker.hostname()
        if field_lower in {"host", "server", "server_name"}:
            return faker.hostname()
        if field_lower.endswith("_url") or field_lower == "url" or "uri" in field_lower:
            return faker.url()
        if field_lower.startswith("dns_"):
            if "response" in field_lower:
                return faker.ipv4()
            return faker.domain_name()
        if field_lower.startswith("dhcp_") or "lease_" in field_lower:
            return now
        if field_lower.endswith("_email") or "email" in field_lower:
            return faker.email()
        if field_lower.endswith("_user") or field_lower.endswith("_username") or field_lower == "username":
            return faker.user_name()
        if field_lower.endswith("_role"):
            return faker.job()
        if field_lower.endswith("_type") or field_lower.endswith("_category"):
            return faker.word()
        if field_lower.endswith("_name"):
            return faker.word()
        if field_lower.startswith("api_"):
            if field_lower.endswith("_key"):
                return faker.uuid4()
            if field_lower.endswith("_endpoint") or field_lower.endswith("_operation"):
                return f"/{faker.word()}"
            return faker.word()
        if field_lower.startswith("http_") or field_lower.startswith("request_") or field_lower.startswith("response_"):
            if "method" in field_lower:
                return random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"])
            if "status" in field_lower or "code" in field_lower:
                return random.choice([200, 201, 204, 301, 302, 400, 401, 403, 404, 429, 500, 502])
            if "header" in field_lower:
                return {"x-request-id": faker.uuid4()}
            if "size" in field_lower or "length" in field_lower:
                return faker.random_int(min=0, max=10485760)
            if "path" in field_lower or "uri" in field_lower:
                return f"/{faker.word()}/{faker.word()}"
            return faker.sentence(nb_words=6)
        if field_lower.startswith("cookie") or field_lower.endswith("_cookie"):
            return f"{faker.word()}={faker.uuid4()}"
        if field_lower.endswith("_id") or field_lower.endswith("_guid") or field_lower.endswith("_uuid"):
            return faker.uuid4()
        if field_lower.endswith("_sid"):
            return f"S-1-{faker.random_int(min=1000, max=999999999)}"
        if field_lower.endswith("_path") or field_lower.endswith("_directory") or field_lower == "cwd":
            return faker.file_path()
        if "file_name" in field_lower or field_lower.endswith("_filename"):
            return faker.file_name()
        if "file_type" in field_lower:
            return faker.file_extension()
        if field_lower.endswith("_time") or field_lower.endswith("_timestamp") or field_lower.endswith("_date"):
            return now
        if field_lower.endswith("_duration") or field_lower.endswith("_ms"):
            return faker.random_int(min=1, max=600000)
        if field_lower.endswith("_count") or field_lower.endswith("_total"):
            return faker.random_int(min=0, max=10000)
        if field_lower.startswith("scan_") or field_lower.endswith("_scan") or "scan_result" in field_lower:
            return random.choice(["pass", "fail", "partial", "unknown"])
        if field_lower.startswith("finding_"):
            return faker.uuid4()
        if field_lower.startswith("vulnerability") or field_lower.startswith("cve") or field_lower.startswith("cvss"):
            if "score" in field_lower:
                return round(faker.pyfloat(min_value=0, max_value=10), 1)
            if "vector" in field_lower:
                return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            return f"CVE-{faker.numerify('####')}-{faker.numerify('####')}"
        if field_lower.endswith("_size") or "bytes" in field_lower:
            return faker.random_int(min=0, max=1073741824)
        if field_lower.endswith("_ratio") or field_lower.endswith("_percent") or field_lower.endswith("_percentage"):
            return faker.random_int(min=0, max=100)
        if "hash" in field_lower:
            if "md5" in field_lower:
                return hashlib.md5(faker.text(max_nb_chars=32).encode()).hexdigest()
            if "sha1" in field_lower:
                return hashlib.sha1(faker.text(max_nb_chars=32).encode()).hexdigest()
            return hashlib.sha256(faker.text(max_nb_chars=64).encode()).hexdigest()
        if field_lower.endswith("_protocol"):
            return random.choice(["tcp", "udp", "http", "https", "tls"])
        if field_lower.endswith("_method"):
            return random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"])
        if field_lower.endswith("_status"):
            return random.choice(["success", "failure", "unknown"])
        if field_lower.startswith("alert_") or field_lower.startswith("incident_") or field_lower.startswith("rule_"):
            if field_lower.endswith("_id"):
                return faker.uuid4()
            if field_lower.endswith("_severity"):
                return random.choice(["low", "medium", "high", "critical"])
            if field_lower.endswith("_type"):
                return faker.word()
            return faker.sentence(nb_words=4)
        if field_lower.startswith("threat_") or field_lower.startswith("signature_"):
            return faker.word()
        if field_lower.startswith("mitre_"):
            return random.choice(["TA0001", "TA0002", "T1059", "T1105"])
        if field_lower.startswith("ioc_"):
            return faker.uuid4()
        if field_lower.startswith("resource_") or field_lower.startswith("instance_"):
            return faker.uuid4()
        if field_lower.startswith("bucket_") or field_lower.startswith("vpc_") or field_lower.startswith("subnet_"):
            return faker.uuid4()
        if field_lower.startswith("security_group") or field_lower.endswith("_arn"):
            return faker.uuid4()
        if field_lower.startswith("k8s_") or field_lower.startswith("pod_") or field_lower.startswith("container_"):
            if "image" in field_lower:
                return f"{faker.word()}/{faker.word()}:{faker.numerify('##.#')}"
            if "id" in field_lower or field_lower.endswith("_uid"):
                return faker.uuid4()
            return faker.slug()
        if field_lower in {"namespace", "namespace_name"} or field_lower.startswith("namespace_"):
            return random.choice(["default", "kube-system", "prod", "staging", "dev"])
        if field_lower.startswith("node_") or field_lower.endswith("_node"):
            return faker.hostname()
        if field_lower.startswith("cluster"):
            return f"cluster-{faker.word()}"
        if field_lower == "labels" or field_lower.startswith("labels_"):
            return {"app": faker.word(), "tier": random.choice(["frontend", "backend"]), "env": random.choice(["prod", "staging"])}
        if field_lower == "annotations" or field_lower.startswith("annotations_"):
            return {"owner": faker.user_name(), "team": faker.word()}
        if field_lower.startswith("service_account"):
            return f"sa-{faker.word()}"
        if field_lower == "tags":
            return {faker.word(): faker.word()}
        if field_lower.startswith("sender_") or field_lower.startswith("recipient_"):
            if "domain" in field_lower:
                return faker.domain_name()
            return faker.email()
        if field_lower.startswith("smtp_"):
            return random.choice([250, 421, 450, 451, 452, 500, 550, 554])
        if field_lower.startswith("dkim_") or field_lower.startswith("spf_") or field_lower.startswith("dmarc_"):
            return random.choice(["pass", "fail", "softfail", "neutral"])
        if field_lower.endswith("_result") or field_lower.endswith("_outcome") or field_lower.endswith("_verdict"):
            return random.choice(["allowed", "blocked", "detected", "failed", "passed"])
        if field_lower.endswith("_action"):
            return random.choice(["allow", "deny", "drop", "block", "alert"])
        if field_lower.endswith("_status"):
            return random.choice(["success", "failure", "unknown"])
        if field_lower.endswith("_version"):
            return faker.numerify(text="##.##.#")
        if field_lower.endswith("_code"):
            return faker.random_int(min=1, max=9999)
        if field_lower.endswith("_score"):
            return faker.random_int(min=0, max=100)
        if field_lower.endswith("_level") or field_lower == "severity":
            return random.choice(["low", "medium", "high", "critical"])
        if field_lower.endswith("_reason"):
            return faker.sentence(nb_words=6)
        if field_lower.endswith("_message") or field_lower == "message":
            return faker.sentence(nb_words=12)
        if field_lower.endswith("_subject"):
            return faker.sentence(nb_words=6)
        if field_lower.endswith("_body") or "content" in field_lower:
            return faker.sentence(nb_words=20)
        if field_lower.endswith("_command") or field_lower.endswith("_cmd"):
            return faker.sentence(nb_words=4)
        if field_lower.endswith("_query"):
            return faker.sentence(nb_words=5)
        if field_lower.endswith("_ip_range") or field_lower.endswith("_port_range"):
            return f"{faker.random_int(min=1, max=65535)}-{faker.random_int(min=1, max=65535)}"
        if field_lower.endswith("_version"):
            return faker.numerify(text="##.##.#")
        if field_lower.endswith("_algorithm") or "cipher" in field_lower:
            return random.choice(["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"])
        if field_lower.endswith("_ip_address"):
            return faker.ipv4()

        return faker.word()
    
    @classmethod
    def syslog(
        cls,
        count: int,
        datetime_iso: Optional[datetime] = None,
        observables: Optional['Observables'] = None,
        required_fields: Optional[str] = None
    ) -> List[str]:
        """
        Generate fake syslog messages with per-message randomization.

        Args:
            count (int): Number of syslog messages to generate.
            datetime_iso (Optional[datetime]): Starting datetime for the messages.
            observables (Optional[Observables]): Observables object with predefined values.
            required_fields (Optional[str]): Comma-separated string of required fields.

        Returns:
            List[str]: A list of generated syslog messages.
        """
        syslog_messages = []
        faker = Events.faker

        # Predefine default datetime if not provided
        if datetime_iso is None:
            datetime_iso = datetime.now() - timedelta(hours=1)
            datetime_iso += timedelta(seconds=faker.random_int(min=0, max=3599))

        required_fields_list = required_fields.split(",") if required_fields else cls._required_fields_or_fallback("syslog")

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}
        cls._validate_fields(required_fields_list, observables_dict)

        # Precompute constant fields (if any)
        # For syslog, most fields may vary per message, so we may not have many constants
        constant_fields = {}

        # Generate syslog messages
        for i in range(count):
            # Update datetime for each log
            current_time = (datetime_iso + timedelta(seconds=i + 1)).strftime('%b %d %H:%M:%S')

            # Generate required fields per message
            event_fields = {}
            for field in required_fields_list:
                value = None
                if field in observables_dict and observables_dict[field]:
                    obs_value = observables_dict[field]
                    value = random.choice(obs_value) if isinstance(obs_value, list) else obs_value
                else:
                    value = Events._set_field(field)
                event_fields[field] = value

            # Generate extra fields per message
            extra_fields = []
            for key, value in observables_dict.items():
                if value and key not in required_fields_list:
                    val = random.choice(value) if isinstance(value, list) else value
                    extra_fields.append(str(val))

            # Build the syslog message
            syslog_message_parts = [f"{current_time}"]

            # Insert required fields
            syslog_message_parts.extend(str(event_fields[field]) for field in required_fields_list)

            # Append additional observables not in required fields
            syslog_message_parts.extend(extra_fields)

            syslog_messages.append(" ".join(syslog_message_parts))

        return syslog_messages
    
    @classmethod
    def cef(
        cls,
        count: int,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        datetime_iso: Optional[datetime] = None,
        observables: Optional['Observables'] = None,
        required_fields: Optional[str] = None
    ) -> List[str]:
        cef_messages = []
        faker = Events.faker
        vendor = vendor or faker.company()
        product = product or faker.word()
        version = version or faker.numerify("1.0.#")
        datetime_iso = datetime_iso or datetime.now() - timedelta(hours=1)
        required_fields_list = required_fields.split(",") if required_fields else cls._required_fields_or_fallback("cef")

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}
        cls._validate_fields(required_fields_list, observables_dict)

        # Generate events
        for i in range(count):
            current_datetime = datetime_iso + timedelta(seconds=i)
            log_id = faker.uuid4()
            severity = 'low'  # Or generate per message if needed

            # Generate field values per message
            event_fields = {}
            for field in required_fields_list:
                value = None
                if field in observables_dict and observables_dict[field]:
                    obs_value = observables_dict[field]
                    if isinstance(obs_value, list):
                        value = random.choice(obs_value)
                    else:
                        value = obs_value
                else:
                    value = Events._set_field(field)
                event_fields[field] = value

            # Generate extra fields per message
            extra_fields = []
            for key, value in observables_dict.items():
                if value and key not in required_fields_list:
                    val = random.choice(value) if isinstance(value, list) else value
                    extra_fields.append(f"{key}={val}")

            extra_fields_str = " " + " ".join(extra_fields) if extra_fields else ""

            # Build the CEF message
            cef_message = (
                f"CEF:0|{vendor}|{product}|{version}|{log_id}|{current_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}|{severity}|"
                + " ".join([f"{field}={event_fields[field]}" for field in required_fields_list])
            )
            cef_message += extra_fields_str
            cef_messages.append(cef_message)

        return cef_messages
   
    @classmethod
    def leef(
        cls,
        count: int,
        datetime_iso: Optional[datetime] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        observables: Optional['Observables'] = None,
        required_fields: Optional[str] = None
    ) -> List[str]:
        """
        Generates optimized fake LEEF (Log Event Extended Format) messages with per-message randomization.
        """
        leef_messages = []
        faker = Events.faker
        vendor = vendor or faker.company()
        product = product or faker.word()
        version = version or faker.numerify("1.0.#")

        # Set starting datetime and default fields if necessary
        datetime_iso = datetime_iso or datetime.now() - timedelta(hours=1)
        required_fields_list = required_fields.split(",") if required_fields else cls._required_fields_or_fallback("leef")

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}
        cls._validate_fields(required_fields_list, observables_dict)

        # Precompute constant fields
        # Event ID and severity might change per event; move inside the loop if needed
        constant_fields = {
            'vendor': vendor,
            'product': product,
            'version': version,
        }

        # Generate messages
        for i in range(count):
            current_datetime = (datetime_iso + timedelta(seconds=i)).strftime('%b %d %H:%M:%S')

            # Generate per-message fields
            # Event ID and severity could be variable
            event_id = Events._set_field("event_id")
            severity = Events._set_field("severity")

            # Generate required fields per message
            event_fields = {}
            for field in required_fields_list:
                value = None
                if field in observables_dict and observables_dict[field]:
                    obs_value = observables_dict[field]
                    value = random.choice(obs_value) if isinstance(obs_value, list) else obs_value
                else:
                    value = Events._set_field(field)
                event_fields[field] = value

            # Generate extra fields per message
            extra_fields = []
            for key, value in observables_dict.items():
                if value and key not in required_fields_list:
                    val = random.choice(value) if isinstance(value, list) else value
                    extra_fields.append(f"  {key}={val}")

            # Build the LEEF message
            leef_message = (
                f"LEEF:1.0|{constant_fields['vendor']}|{constant_fields['product']}|{constant_fields['version']}|{event_id}|"
                f"severity={severity}  devTime={current_datetime}"
                + "".join(f"  {field}={event_fields[field]}" for field in required_fields_list)
                + "".join(extra_fields)
            )

            leef_messages.append(leef_message)

        return leef_messages

    
    @classmethod
    def winevent(
        cls,
        count: int,
        datetime_iso: Optional[datetime] = None,
        observables: Optional['Observables'] = None
    ) -> List[str]:
        """
        Generates fake Windows Event Log messages with per-message randomization.

        Args:
            count (int): The number of fake messages to generate.
            datetime_iso (Optional[datetime]): The starting datetime for the messages.
            observables (Optional[Observables]): An observables object with predefined values.

        Returns:
            List[str]: A list of fake Windows Event Log messages.
        """
        winevent_messages = []
        faker = Events.faker

        # Set starting datetime if not provided
        if datetime_iso is None:
            datetime_iso = datetime.now() - timedelta(hours=1)
            datetime_iso += timedelta(seconds=faker.random_int(min=0, max=3599))

        required_fields_list = cls._required_fields_or_fallback("winevent")

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}
        cls._validate_fields(required_fields_list, observables_dict)

        # Precompute constant fields (if any)
        constant_fields = {
            # Add any fields that are constant across events
        }

        # Generate events
        for i in range(count):
            # Update datetime for each event
            current_datetime = datetime_iso + timedelta(seconds=i + 1)
            system_time = current_datetime.strftime('%Y-%m-%d %H:%M:%S')

            # Generate per-event fields
            event_fields = {}

            # Generate required fields per message
            for field in required_fields_list:
                value = None
                if field in observables_dict and observables_dict[field]:
                    obs_value = observables_dict[field]
                    value = random.choice(obs_value) if isinstance(obs_value, list) else obs_value
                else:
                    value = Events._set_field(field)
                event_fields[field] = value

            # Generate extra fields per message
            for key, value in observables_dict.items():
                if value and key not in required_fields_list:
                    val = random.choice(value) if isinstance(value, list) else value
                    event_fields[key] = val

            # Generate per-event fields that are not in observables
            guid = faker.uuid4()

            # Use event_id from observables if available
            if 'event_id' in observables_dict and observables_dict['event_id']:
                event_record_id = (
                    random.choice(observables_dict['event_id'])
                    if isinstance(observables_dict['event_id'], list)
                    else observables_dict['event_id']
                )
            else:
                event_record_id = Events._set_field('event_id')

            # Prepare event fields
            event_fields.update({
                'guid': guid,
                'system_time': system_time,
                'event_record_id': event_record_id,
            })

            # Combine with any constant fields
            event_fields.update(constant_fields)

            # Select a random event template
            unformatted_event = random.choice(WIN_EVENTS)

            # Ensure all template fields exist to avoid KeyError
            for _, field_name, _, _ in Formatter().parse(unformatted_event):
                if not field_name:
                    continue
                if field_name not in event_fields:
                    event_fields[field_name] = Events._set_field(field_name)

            # Format the event with all fields
            win_event = unformatted_event.format(**event_fields)

            winevent_messages.append(win_event)

        return winevent_messages
    
    @classmethod
    def json(
        cls,
        count: int,
        datetime_iso: Optional[datetime] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        observables: Optional['Observables'] = None,
        required_fields: Optional[str] = None
    ) -> List[dict]:
        """
        Generate fake JSON messages representing discovered vulnerabilities with per-message randomization.

        Args:
            count (int): Number of JSON messages to generate.
            datetime_iso (Optional[datetime]): Starting datetime for the messages.
            vendor (Optional[str]): Vendor name.
            product (Optional[str]): Product name.
            version (Optional[str]): Product version.
            observables (Optional[Observables]): Observables object with predefined values.
            required_fields (Optional[str]): Comma-separated string of required fields.

        Returns:
            List[dict]: A list of generated JSON messages.
        """
        json_messages = []
        faker = Events.faker

        # Precompute vendor, product, and version details
        vendor = vendor or faker.company()
        product = product or "UnknownProduct"
        version = version or faker.numerify("1.0.#")

        # Set initial datetime
        datetime_iso = datetime_iso or datetime.now() - timedelta(hours=1)

        if required_fields:
            required_fields_list = required_fields.split(",")
        else:
            required_fields_list = cls._required_fields_or_fallback("json")
            if product == "VulnScanner" and required_fields_list == ["user", "host"]:
                required_fields_list = ["cve_id", "host", "file_hash"]

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}
        cls._validate_fields(required_fields_list, observables_dict)

        # Precompute constant fields
        constant_fields = {
            'vendor': vendor,
            'product': product,
            'version': version,
        }

        # Generate JSON events
        for i in range(count):
            # Adjust datetime for each message
            current_datetime = datetime_iso + timedelta(seconds=i)
            datetime_str = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

            # Generate variable fields per message
            event_fields = {
                'datetime_iso': datetime_str,
                'severity': Events._set_field('severity'),
            }

            # Generate required fields per message
            for field in required_fields_list:
                value = None
                if field in observables_dict and observables_dict[field]:
                    obs_value = observables_dict[field]
                    value = random.choice(obs_value) if isinstance(obs_value, list) else obs_value
                else:
                    value = Events._set_field(field)
                event_fields[field] = value

            # Include additional observables not in required fields
            for key, value in observables_dict.items():
                if value and key not in required_fields_list:
                    val = random.choice(value) if isinstance(value, list) else value
                    event_fields[key] = val

            # Combine all fields into the event
            event = {**constant_fields, **event_fields}

            # Append generated event to the list
            json_messages.append(event)

        return json_messages

    @classmethod
    def incidents(cls, count, fields: Optional[str] = None, datetime_iso: Optional[datetime] = None,
                vendor: Optional[str] = None, product: Optional[str] = None, version: Optional[str] = None,
                observables: Optional[Observables] = None, required_fields: Optional[str] = None) -> List[dict]:
        """
        Generates a list of fake incident data.

        Args:
            count (int): The number of incidents to generate.
            fields (str, optional): Comma-separated incident fields to include. If None, all fields are included.
            vendor, product, version (Optional[str]): Details about the event source.
            datetime_iso (Optional[datetime]): Base timestamp for the incidents.
            observables (Optional[Observables]): Optional observables object to provide values.
            required_fields (Optional[str]): Required fields for the events.

        Returns:
            List[Dict]: A list of incident dictionaries.
        """
        incidents = []
        faker =  Events.faker
        datetime_iso = datetime_iso or datetime.now() - timedelta(hours=1)

        # Generate analyst list if not provided in observables
        incident_types = observables.incident_types if observables and observables.incident_types else INCIDENTS_TYPES
        analysts = observables.analysts if observables and observables.analysts else [faker.unique.first_name() for _ in range(10)]
        severities = observables.severity if observables and observables.severity else [faker.random_int(min=1, max=5) for _ in range(10)]

        incident_type_cycle = itertools.cycle(incident_types)
        for i in range(count):
            incident_id = i + 1  # Simplify unique ID generation
            duration = random.randint(1, 5)
            incident_type = next(incident_type_cycle)
            analyst = random.choice(analysts)
            severity =  random.choice(severities)
            description = Events._set_field('terms')

            # Add base fields
            incident = {}
            field_list = fields.split(',') if fields else ['id', 'duration', 'type', 'analyst', 'severity', 'description', 'events']
            if 'id' in field_list:
                incident['id'] = incident_id
            if 'duration' in field_list:
                incident['duration'] = duration
            if 'type' in field_list:
                incident['type'] = incident_type
            if 'analyst' in field_list:
                incident['analyst'] = analyst
            if 'severity' in field_list:
                incident['severity'] = severity
            if 'description' in field_list:
                incident['description'] = description

            # Generate associated events for each incident
            if 'events' in field_list:
                incident['events'] = [
                    {"event": cls.syslog(count=1, datetime_iso=datetime_iso, observables=observables, required_fields=required_fields)[0]},
                    {"event": cls.cef(count=1, datetime_iso=datetime_iso, vendor=vendor, product=product, version=version, observables=observables, required_fields=required_fields)[0]},
                    {"event": cls.leef(count=1, datetime_iso=datetime_iso, vendor=vendor, product=product, version=version, observables=observables, required_fields=required_fields)[0]},
                    {"event": cls.winevent(count=1, datetime_iso=datetime_iso, observables=observables)[0]},
                    {"event": cls.json(count=1, datetime_iso=datetime_iso, vendor=vendor, product=product, version=version, observables=observables, required_fields=required_fields)[0]}
                ]
            
            incidents.append(incident)

        return incidents
