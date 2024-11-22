import random
import requests
import warnings
import ipaddress
import csv
import hashlib
import itertools
import time
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
                database_name: Optional[list] = None, query: Optional[list] = None):
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
            field_value = faker.word()

        return field_value
    
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

        # Set default required fields
        required_fields_list = required_fields.split(",") if required_fields else [
            "pid", "host", "user", "unix_process", "unix_cmd"
        ]

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}

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
        required_fields_list = required_fields.split(",") if required_fields else [
            "local_ip", "local_port", "remote_ip", "remote_port", "protocol", "rule_id", "action"
        ]

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}

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
        required_fields_list = required_fields.split(",") if required_fields else [
            "local_ip", "local_port", "host", "url", "protocol", "response_code", "action"
        ]

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}

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

        # Define required fields
        required_fields_list = [
            "process_id",
            "new_process_id",
            "thread_id",
            "target_pid",
            "subject_login_id",
            "user_id",
            "destination_login_id",
            "privilege_list",
            "win_process",
            "src_host",
            "user_name",
            "cmd",
            "source_network_address",
            "local_port",
            "transmitted_services",
            "file_name",
            "src_domain"
        ]

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}

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

        # Set required fields
        if required_fields:
            required_fields_list = required_fields.split(",")
        else:
            required_fields_list = (
                ["cve_id", "host", "file_hash"] if product == "VulnScanner" else ["user", "host"]
            )

        # Convert observables to a dictionary for easy access
        observables_dict = vars(observables) if observables else {}

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

        incident_type_cycle = itertools.cycle(incident_types)
        for i in range(count):
            incident_id = i + 1  # Simplify unique ID generation
            duration = random.randint(1, 5)
            incident_type = next(incident_type_cycle)
            analyst = random.choice(analysts)
            severity = Events._set_field('severity', observables) or faker.random_int(min=1, max=5)
            description = Events._set_field('terms', observables) or faker.sentence(nb_words=10)

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
