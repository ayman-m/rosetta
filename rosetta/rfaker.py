import random
import requests
import warnings
import ipaddress
import json
import csv
import hashlib
from enum import Enum
from functools import reduce
from faker import Faker
from datetime import datetime, timedelta
from typing import Optional, List
from rosetta.constants.sources import BAD_IP_SOURCES, GOOD_IP_SOURCES, BAD_URL_SOURCES, GOOD_URL_SOURCES, \
    BAD_SHA256_SOURCES, GOOD_SHA256_SOURCES, CVE_SOURCES, TERMS_SOURCES
from rosetta.constants.systems import UNIX_CMD, WINDOWS_CMD, WIN_PROCESSES, WIN_EVENTS
from rosetta.constants.attributes import INCIDENTS_TYPES, SEVERITIES
from rosetta.constants.sensors import ACTIONS, PROTOCOLS, TECHNIQUES, ERROR_CODE


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
                 url: Optional[list] = None, source_port: Optional[list] = None, remote_port: Optional[list] = None,
                 protocol: Optional[list] = None, inbound_bytes: Optional[list] = None,
                 outbound_bytes: Optional[list] = None, app: Optional[list] = None, os: Optional[list] = None,
                 user: Optional[list] = None, cve: Optional[list] = None, file_name: Optional[list] = None,
                 file_hash: Optional[list] = None, win_cmd: Optional[list] = None, unix_cmd: Optional[list] = None,
                 win_process: Optional[list] = None, unix_process: Optional[list] = None,
                 technique: Optional[list] = None, entry_type: Optional[list] = None, severity: Optional[list] = None,
                 sensor: Optional[list] = None, action: Optional[list] = None, event_id: Optional[list] = None,
                 error_code: Optional[list] = None, terms: Optional[list] = None, alert_types: Optional[list] = None,
                 alert_name: Optional[list] = None, incident_types: Optional[list] = None,
                 analysts: Optional[list] = None, action_status: Optional[list] = None):
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
        self.source_port = source_port
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
        self.unix_process = unix_process
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
        if observable_type == ObservableType.IP and known == ObservableKnown.GOOD:
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
        if observable_type == ObservableType.URL and known == ObservableKnown.BAD:
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
        if observable_type == ObservableType.URL and known == ObservableKnown.GOOD:
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
        if observable_type == ObservableType.SHA256 and known == ObservableKnown.BAD:
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
        if observable_type == ObservableType.SHA256 and known == ObservableKnown.GOOD:
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
        if observable_type == ObservableType.CVE:
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
        if observable_type == ObservableType.TERMS:
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

    @staticmethod
    def _create_faker():
        """
        Returns:
            Faker instance.
        """
        return Faker()

    @staticmethod
    def _create_generator():
        """
        Returns:
            Faker instance.
        """
        return Observables()

    @classmethod
    def set_field(cls, field, observables: Optional[Observables] = None):
        """
        Returns:
            Field value.
        """
        field_value = None
        faker = cls._create_faker()
        if field == "pid":
            field_value = faker.random_int(min=1000, max=65535)
        if field == "host":
            field_value = random.choice(observables.src_host) if observables and observables.src_host \
                else faker.hostname()
        if field == "user":
            field_value = random.choice(observables.user) if observables and observables.user \
                else faker.user_name()
        if field == "unix_process":
            field_value = random.choice(observables.unix_process) if observables and observables.unix_process \
                else "sudo"
        if field == "unix_cmd":
            field_value = random.choice(observables.unix_cmd) if observables and observables.unix_cmd \
                else random.choice(UNIX_CMD)
        if field == "severity":
            field_value = random.choice(observables.severity) if observables and observables.severity \
                else faker.choice(SEVERITIES)
        if field == "local_ip":
            field_value = random.choice(observables.local_ip) if observables and observables.local_ip \
                    else faker.ipv4()
        if field == "local_port":
            field_value = faker.random_int(min=1024, max=65535)
        if field == "remote_ip":
            field_value = random.choice(observables.remote_ip) if observables and observables.remote_ip \
                    else Observables.generator(observable_type=ObservableType.IP, known=ObservableKnown.BAD, count=1)[0]
        if field == "remote_port":
            field_value = random.choice(observables.remote_port) if observables and observables.remote_port \
                    else faker.random_int(min=1024, max=65535)
        if field == "dst_url":
            field_value = random.choice(observables.url) if observables and observables.url \
                    else Observables.generator(observable_type=ObservableType.URL, known=ObservableKnown.BAD, count=1)
        if field == "inbound_bytes":
            field_value = random.choice(observables.inbound_bytes) if observables and observables.inbound_bytes \
                    else faker.random_int(min=10, max=1073741824)
        if field == "outbound_bytes":
            field_value = random.choice(observables.outbound_bytes) if observables and observables.outbound_bytes \
                    else faker.random_int(min=10, max=1073741824)
        if field == "protocol":
            field_value = random.choice(observables.protocol) if observables and observables.protocol \
                    else random.choice(PROTOCOLS)
        if field == "rule_id":
            field_value = random.choice(observables.event_id) if observables and observables.event_id \
                    else faker.random_int(min=1, max=200)
        if field == "action":
            field_value = random.choice(observables.action) if observables and observables.action \
                    else random.choice(ACTIONS)
        if field == "src_domain":
            field_value = random.choice(observables.src_domain) if observables and observables.src_domain \
                    else faker.domain_name()
        if field == "sender_email":
            field_value = random.choice(observables.sender_email) if observables and observables.sender_email \
                    else faker.email()
        if field == "recipient_email":
            field_value = random.choice(observables.recipient_email) if observables and observables.recipient_email \
                    else faker.email()
        if field == "email_subject":
            field_value = random.choice(observables.email_subject) if observables and observables.email_subject \
                    else faker.sentence(nb_words=6)
        if field == "email_body":
            field_value = random.choice(observables.email_body) if observables and observables.email_body else \
                    faker.sentence(nb_words=50)
        if field == "attachment_hash":
            field_value = random.choice(observables.file_hash) if observables and observables.file_hash \
                    else Observables.generator(observable_type=ObservableType.SHA256, known=ObservableKnown.BAD,
                                               count=1)
        if field == "spam_score":
            field_value = faker.random_int(min=1, max=5)
        if field == "method":
            field_value = random.choice(observables.technique).get('mechanism') if observables and \
                    observables.technique else random.choice(TECHNIQUES).get('mechanism')
        if field == "url":
            field_value = random.choice(observables.technique).get('indicator') if observables and \
                    observables.technique else random.choice(TECHNIQUES).get('indicator')
        if field == "user_agent":
            field_value = faker.user_agent()
        if field == "referer":
            field_value = random.choice(observables.url) if observables and observables.url \
                    else Observables.generator(observable_type=ObservableType.URL, known=ObservableKnown.BAD, count=1)
        if field == "response_code":
            field_value = random.choice(observables.error_code) if observables and observables.error_code \
                    else random.choice(ERROR_CODE)
        if field == "response_size":
            field_value = faker.random_int(min=100, max=10000)
        if field == "attack_type":
            field_value = random.choice(observables.technique).get('technique') if observables and \
                    observables.technique else random.choice(TECHNIQUES).get('technique')
        if field == "cookies":
            field_value = f"{faker.word()}={faker.uuid4()}"
        if field == "guid":
            field_value = faker.uuid4()
        if field == "transmitted_services":
            field_value = faker.sentence(nb_words=5)
        if field == "process_id":
            field_value = faker.random_int()
        if field == "new_process_id":
            field_value = faker.random_int()
        if field == "thread_id":
            field_value = faker.random_int()
        if field == "target_pid":
            field_value = faker.random_int()
        if field == "subject_login_id":
            field_value = faker.random_int()
        if field == "win_user_id":
            field_value = "S-1-" + str(faker.random_int())
        if field == "destination_login_id":
            field_value = faker.random_int()
        if field == "privilege_list":
            field_value = faker.sentence(nb_words=5)
        if field == "event_record_id":
            field_value = random.choice(observables.event_id) if observables and observables.event_id \
                else faker.random.randint(1, 999)
        if field == "win_process":
            field_value = random.choice(observables.win_process) if observables and observables.win_process \
                else random.choice(WIN_PROCESSES)
        if field == "win_cmd":
            field_value = random.choice(observables.win_cmd) if observables and observables.win_cmd \
                else random.choice(WINDOWS_CMD)
        if field == "source_network_address":
            field_value = random.choice(observables.local_ip) if observables and observables.local_ip \
                else faker.ipv4_private()
        if field == "file_name":
            field_value = random.choice(observables.file_name) if observables and observables.file_name \
                else faker.file_name()
        if field == "cve_id":
            field_value = random.choice(observables.cve) if observables and observables.cve \
                    else Observables.generator(observable_type=ObservableType.CVE, count=1)
        if field == "file_hash":
            field_value = random.choice(observables.file_hash) if observables and observables.file_hash \
                    else Observables.generator(observable_type=ObservableType.SHA256, known=ObservableKnown.BAD,
                                               count=1)
        if field == "incident_types":
            field_value = random.choice(observables.incident_types) if observables and observables.incident_types \
                else INCIDENTS_TYPES
        if field == "analysts":
            field_value = random.choice(observables.analysts) if observables and observables.analysts \
                else [faker.unique.first_name() for _ in range(10)]
        if field == "duration":
            field_value = random.randint(1, 5)
        if field == "log_id":
            field_value = faker.uuid4()
        if field == "alert_name":
            field_value = random.choice(observables.alert_name) if observables and observables.alert_name \
                else faker.sentence(nb_words=4)
        return field_value

    @classmethod
    def syslog(cls, count: int, datetime_iso: Optional[datetime] = None, observables: Optional[Observables] = None,
               required_fields: Optional[str] = None) -> List[str]:
        """
        Generate fake syslog messages.

        Args:
            count: The number of syslog messages to generate.
            datetime_iso: Optional. The starting datetime_iso for the syslog messages. If not provided, a random time during
            the past hour from now will be used.
            observables: Optional. An observables object. If not provided, random objservable will be generated
            and used.
            required_fields: Optional. A list of fields that are required to present in the generated data, whether from
            observables or randomely.
        Returns:
            A list of syslog messages.

        Examples:
            >>> Events.syslog(5)
            ['Jan 01 05:32:48 myhostname sudo[1023]: username : COMMAND ; cat /etc/shadow',
             'Jan 01 05:17:59 myhostname sudo[2019]: username : COMMAND ; find / -name \'*.log\' -exec rm -f {} \\;',
             'Jan 01 05:46:16 myhostname sudo[3132]: username : COMMAND ; dd if=/dev/zero of=/dev/sda',
             'Jan 01 05:08:08 myhostname sudo[4111]: username : COMMAND ; chmod -R 777 /',
             'Jan 01 05:59:41 myhostname sudo[5195]: username : COMMAND ; chown -R nobody:nogroup /']

        """
        syslog_messages = []
        faker = cls._create_faker()
        if datetime_iso is None:
            datetime_iso = datetime.now() - timedelta(hours=1)
            datetime_iso += timedelta(seconds=faker.random_int(min=0, max=3599))
        if not required_fields:
            required_fields = "pid,host,user,unix_process,unix_cmd"
        for i in range(count):
            datetime_iso += timedelta(seconds=1)
            syslog_message = f"{datetime_iso.strftime('%Y-%m-%d %H:%M:%S')}"
            for field in required_fields.split(","):
                syslog_message += f" {cls.set_field(field, observables)}"
            if observables:
                for observable, observable_value in vars(observables).items():
                    if observable_value and observable not in required_fields.split(","):
                        syslog_message += f" {random.choice(observable_value)}"
            syslog_messages.append(syslog_message)
        return syslog_messages

    @classmethod
    def cef(cls, count: int, vendor: Optional[str] = None, product: Optional[str] = None,
            version: Optional[str] = None, datetime_iso: Optional[datetime] = None,
            observables: Optional[Observables] = None, required_fields: Optional[str] = None) -> List[str]:
        """
        Generates fake CEF (Common Event Format) messages.

        Args:
            count: The number of CEF messages to generate.
            datetime_iso: Optional. The starting datetime_iso for the syslog messages. If not provided, a random time during.
            vendor: Optional. The vendor.
            product: Optional. The product value options include:
            - Firewall
            - EmailGW
            version: Optional. The version.
            observables: Optional. An observables object. If not provided, random objservable will be generated
            and used.
            required_fields: Optional. A list of fields that are required to present in the generated data, whether from
            observables or randomely.
        Returns:
            A list of fake CEF messages in string format.

        Raises:
            None.

        Example Usage:
            >>> Events.cef(3)
            ['CEF:0|Acme|Firewall|1.0.0|ddab6607-1c35-4e81-a54a-99b1c9b77e49|Firewall ALLOW UDP traffic
            from example.com:61434 to 23.216.45.109:47983|1|src=example.com spt=61434 dst=23.216.45.109
            dpt=47983 proto=UDP act=ALLOW',
             'CEF:0|Acme|Firewall|1.0.0|25b41f8f-8a63-4162-a69c-cb43f8c8e49f|Firewall DENY TCP traffic
             from example.com:11460 to 184.72.194.90:3087|8|src=example.com spt=11460 dst=184.72.194.90
             dpt=3087 proto=TCP act=DENY',
             'CEF:0|Acme|Firewall|1.0.0|a3faedaa-5109-4849-b9ec-1ad6c5f8a5ec|Firewall ALLOW TCP traffic
             from example.com:25068 to 81.171.9.216:6157|2|src=example.com spt=25068 dst=81.171.9.216
             dpt=6157 proto=TCP act=ALLOW']
        """
        cef_messages = []
        faker = cls._create_faker()
        vendor = vendor or faker.company()
        version = version or faker.numerify("1.0.#")
        if datetime_iso is None:
            datetime_iso = datetime.now() - timedelta(hours=1)
            datetime_iso += timedelta(seconds=faker.random_int(min=0, max=3599))
        if not required_fields:
            if product == "Firewall":
                required_fields = "local_ip,local_port,remote_ip,remote_port,dst_url,inbound_bytes," \
                          "outbound_bytes,protocol,rule_id,action"
            elif product == "EmailGW":
                required_fields = "local_ip,src_domain,sender_email,recipient_email,email_subject,email_body," \
                                  "attachment_hash,spam_score,action"
            else:
                required_fields = "local_ip,local_port,remote_ip,remote_port,protocol,rule_id,action"
        for i in range(count):
            datetime_iso += timedelta(seconds=1)
            cef_message = f"CEF:0|{vendor}|{product}|{version}|{cls.set_field('log_id', observables)}|{datetime_iso}" \
                          f"|{cls.set_field('severity', observables)}|"
            for field in required_fields.split(","):
                cef_message += f" {field}={cls.set_field(field, observables)}"
            if observables:
                for observable, observable_value in vars(observables).items():
                    if observable_value and observable not in required_fields.split(","):
                        cef_message += f" {observable}={random.choice(observable_value)}"
            cef_messages.append(cef_message)
        return cef_messages

    @classmethod
    def leef(cls, count, datetime_iso: Optional[datetime] = None, vendor: Optional[str] = None,
             product: Optional[str] = None, version: Optional[str] = None,
             observables: Optional[Observables] = None, required_fields: Optional[str] = None) -> List[str]:
        """
        Generates fake LEEF (Log Event Extended Format) messages.

        Parameters:
            count (int): The number of LEEF messages to generate.
            datetime_iso: Optional. The starting datetime_iso for the syslog messages. If not provided, a random time during.
            vendor: Optional. The vendor.
            product: Optional. The product.
            version: Optional. The version.
            observables: An observables object. If not provided, random objservable will be generated and used.
            required_fields: Optional. A list of fields that are required to present in the generated data, whether from
            observables or randomely.

        Returns:
            A list of generated LEEF messages.

        Example:
            To generate 10 fake LEEF messages:
            ```
            >>> messages = Events.leef(count=2)
            >>> print(messages)
            ['LEEF:1.0|Leef|Payment Portal|1.0|192.168.0.1|mycomputer|08:00:27:da:2e:2e|08:00:27:da:2e:2f|src=10.0.0.1
             dst=mycomputer spt=60918 dpt=443 request=https://example.com/?q=<script>alert("xss")</script>
             method=GET proto=HTTP/1.1 status=200 request_size=5119 response_size=6472
             user_agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)
             Chrome/93.0.4577.63 Safari/537.36',
             'LEEF:1.0|Leef|Payment Portal|1.0|192.168.0.1|mycomputer|08:00:27:da:2e:2e|08:00:27:da:2e:2f|src=10.0.0.2
              dst=mycomputer spt=57251 dpt=443 request=https://example.com/admin.php?sessionid=12345 method=POST
               proto=HTTP/1.1 status=404 request_size=1216 response_size=9729 user_agent=Mozilla/5.0
               (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3']
        """
        leef_messages = []
        faker = cls._create_faker()
        vendor = vendor or faker.company()
        version = version or faker.numerify("1.0.#")
        if datetime_iso is None:
            datetime_iso = datetime.now() - timedelta(hours=1)
            datetime_iso += timedelta(seconds=faker.random_int(min=0, max=3599))
        if not required_fields:
            if product == "WAF":
                required_fields = "local_ip,local_port,host,method,url,protocol," \
                                  "user_agent,referer,response_code,response_size,rule_id,action,attack_type,cookies"
            else:
                required_fields = "local_ip,local_port,host,url,protocol,response_code,action"
        for i in range(count):
            datetime_iso += timedelta(seconds=1)
            leef_message = f"LEEF:1.0|{vendor}|{product}|{version}|deviceEventDate={datetime_iso}|" \
                           f"severity={cls.set_field('severity', observables)}|"
            for field in required_fields.split(","):
                leef_message += f" {field}={cls.set_field(field, observables)}"
            if observables:
                for observable, observable_value in vars(observables).items():
                    if observable_value and observable not in required_fields.split(","):
                        leef_message += f" {observable}={random.choice(observable_value)}"
            leef_messages.append(leef_message)
        return leef_messages

    @classmethod
    def winevent(cls, count, datetime_iso: Optional[datetime] = None, observables: Optional[Observables] = None) -> \
            List[str]:
        """
        Generates fake Windows Event Log messages.

        Args:
            count (int): The number of fake messages to generate.
            datetime_iso: Optional. The starting datetime_iso for the syslog messages. If not provided, a random time during
            observables: An observables object. If not provided, random objservable will be generated and used.

        Returns:
            list: A list of fake Windows Event Log messages.

        Examples:
            >>> Events.winevent(1)
            ['<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">...</Event>', ...]
        """
        winevent_messages = []
        faker = cls._create_faker()
        if datetime_iso is None:
            datetime_iso = datetime.now() - timedelta(hours=1)
            datetime_iso += timedelta(seconds=faker.random_int(min=0, max=3599))
        for i in range(count):
            datetime_iso += timedelta(seconds=1)
            guid = faker.uuid4()
            local_port = faker.random_int(min=1024, max=65535)
            transmitted_services = faker.sentence(nb_words=5)
            system_time = datetime_iso
            process_id = faker.random_int()
            new_process_id = faker.random_int()
            thread_id = faker.random_int()
            target_pid = faker.random_int()
            domain_name = faker.domain_name()
            subject_login_id = faker.random_int()
            user_id = "S-1-" + str(faker.random_int())
            destination_login_id = faker.random_int()
            privilege_list = faker.sentence(nb_words=5)
            event_record_id = random.choice(observables.event_id) if observables and observables.event_id \
                else faker.random.randint(1, 999)
            process_name = random.choice(observables.win_process) if observables and observables.win_process \
                else random.choice(WIN_PROCESSES)
            host = random.choice(observables.src_host) if observables and observables.src_host \
                else faker.hostname()
            user_name = random.choice(observables.user) if observables and observables.user \
                else faker.user_name()
            cmd = random.choice(observables.win_cmd) if observables and observables.win_cmd \
                else random.choice(WINDOWS_CMD)
            source_network_address = random.choice(observables.local_ip) if observables and observables.local_ip \
                else faker.ipv4_private()
            file_name = random.choice(observables.file_name) if observables and observables.file_name \
                else faker.file_name()
            unformatted_event = random.choice(WIN_EVENTS)
            win_event = unformatted_event.format(guid=guid, system_time=system_time, event_record_id=event_record_id,
                                                 process_id=process_id, process_name=process_name,
                                                 new_process_id=new_process_id, thread_id=thread_id,
                                                 target_pid=target_pid, host=host, user_id=user_id, user_name=user_name,
                                                 domain_name=domain_name, subject_login_id=subject_login_id,
                                                 privilege_list=privilege_list, cmd=cmd,
                                                 destination_login_id=destination_login_id,
                                                 source_network_address=source_network_address, source_port=local_port,
                                                 transmitted_services=transmitted_services, file_name=file_name)
            winevent_messages.append(win_event)
        return winevent_messages

    @classmethod
    def json(cls, count, datetime_iso: Optional[datetime] = None, vendor: Optional[str] = None,
             product: Optional[str] = None, version: Optional[str] = None, observables: Optional[Observables] = None,
             required_fields: Optional[str] = None) -> List[dict]:
        """
        Generate fake JSON messages representing discovered vulnerabilities.

        Args:
            count (int): The number of JSON messages to generate.
            datetime_iso: Optional. The starting datetime_iso for the syslog messages. If not provided, a random time during.
            vendor: Optional. The vendor.
            product: Optional. The product value options include:
            - VulnScanner
            version: Optional. The version.
            observables: An observables object. If not provided, random objservable will be generated and used.
            required_fields: Optional. A list of fields that are required to present in the generated data, whether from
            observables or randomely.
        Returns:
            List[Dict[str, Union[str, int]]]: A list of dictionaries representing the generated JSON messages.

        Example:
            >>> fake_messages = json(5)
            >>> len(fake_messages)
            5
            >>> isinstance(fake_messages[0], dict)
            True

        """
        json_messages = []
        faker = cls._create_faker()
        vendor = vendor or faker.company()
        version = version or faker.numerify("1.0.#")
        if datetime_iso is None:
            datetime_iso = datetime.now() - timedelta(hours=1)
            datetime_iso += timedelta(seconds=faker.random_int(min=0, max=3599))
        if not required_fields:
            if product == "VulnScanner":
                required_fields = "cve_id,host,file_hash"
            else:
                required_fields = "user,host"
        for i in range(count):
            datetime_iso += timedelta(seconds=1)
            event = {
                'vendor': vendor,
                'product': product,
                'version': version,
                'datetime_iso': str(datetime_iso),
                'severity': cls.set_field("severity", observables)
            }
            for field in required_fields.split(","):
                event[field] = cls.set_field(field, observables)
            if observables:
                for observable, observable_value in vars(observables).items():
                    if observable_value and observable not in required_fields.split(","):
                        event[observable] = random.choice(observable_value)
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
            fields (str, optional): A comma-separated list of incident fields to include in the output. If None,
                all fields will be included. Valid options are: 'id', 'duration', 'type', 'analyst', 'severity',
                'description', 'events'.
            vendor: Optional. The vendor.
            product: Optional. The product.
            version: Optional. The version.
            datetime_iso: Optional. The starting datetime_iso for the syslog messages. If not provided, a random time during
            observables: An observables object. If not provided, random objservable will be generated and used.
            required_fields: Optional. A list of fields that are required to present in the generated data, whether from
            observables or randomely.

        Returns:
            List[Dict]: A list of incident dictionaries. Each dictionary contains the following fields:
                - 'id' (int): A unique identifier for the incident.
                - 'type' (str): The type of incident.
                - 'duration' (int): The duration of the incident in hours.
                - 'analyst' (str): The name of the analyst assigned to the incident.
                - 'severity' (str, optional): The severity of the incident. Only included if 'severity' is specified
                    in the 'fields' argument.
                - 'description' (str, optional): A brief description of the incident. Only included if 'description' is
                    specified in the 'fields' argument.
                - 'events' (List[Dict], optional): A list of event dictionaries associated with the incident.

        Example:
            >>> incidents(count=3, fields='id,type,severity')
            [
                {'id': 1, 'type': 'Lateral Movement', 'severity': 'Critical'},
                {'id': 2, 'type': 'Access Violation', 'severity': 'High'},
                {'id': 3, 'type': 'Account Compromised', 'severity': 'Low'}
            ]
        """
        incidents = []
        faker = cls._create_faker()

        incident_ids = set()

        incident_types = observables.incident_types if observables and observables.incident_types \
            else INCIDENTS_TYPES
        analysts = observables.analysts if observables and observables.analysts \
            else [faker.unique.first_name() for _ in range(10)]
        analyst_incident_map = {}
        for analyst in analysts:
            mapped_incident_type = incident_types.pop(0)
            analyst_incident_map[analyst] = mapped_incident_type
            incident_types.append(mapped_incident_type)
        for i in range(count):
            incident = {}
            duration = random.randint(1, 5)
            while True:
                incident_id = random.randint(1, count)
                if incident_id not in incident_ids:
                    incident_ids.add(incident_id)
                    break
            incident_type = random.choice(incident_types)
            analyst = random.choice(analysts)
            severity = random.choice(observables.severity) if observables and observables.severity \
                else faker.random_int(min=1, max=5)
            description = random.choice(observables.terms) if observables and observables.terms \
                else Observables.generator(observable_type=ObservableType.TERMS, known=ObservableKnown.BAD, count=1000)
            if analyst in analyst_incident_map and random.randint(1, 100) == 2:
                incident_type = analyst_incident_map[analyst]
                duration = random.randint(1, 2)
            if fields:
                field_list = fields.split(',')
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
                    incident_description = faker.paragraph(nb_sentences=1, ext_word_list=description)
                    incident['description'] = incident_description
                if 'events' in field_list:
                    incident['events'] = [
                        {"event": cls.syslog(count=1, datetime_iso=datetime_iso, observables=observables,
                                             required_fields=required_fields)[0]},
                        {"event": cls.cef(count=1, datetime_iso=datetime_iso, vendor=vendor, product=product, version=version
                                          , observables=observables, required_fields=required_fields)[0]},
                        {"event": cls.leef(count=1, datetime_iso=datetime_iso, vendor=vendor, product=product,
                                           version=version, observables=observables, required_fields=required_fields)[0]},
                        {"event": cls.winevent(count=1, datetime_iso=datetime_iso, observables=observables)[0]},
                        {"event": cls.json(count=1, datetime_iso=datetime_iso, vendor=vendor, product=product,
                                           version=version, observables=observables,
                                           required_fields=required_fields)[0]}
                    ]
            else:
                incident = {
                    "id": incident_id,
                    "type": incident_type,
                    "duration": duration,
                    "analyst": analyst
                }
            incidents.append(incident)
        return incidents
