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
from typing import Optional, List
from rosetta.constants.sources import BAD_IP_SOURCES, GOOD_IP_SOURCES, BAD_URL_SOURCES, GOOD_URL_SOURCES, \
    BAD_SHA256_SOURCES, GOOD_SHA256_SOURCES, CVE_SOURCES, TERMS_SOURCES
from rosetta.constants.systems import UNIX_CMD, WINDOWS_CMD, WIN_PROCESSES, WIN_EVENTS, INCIDENTS_TYPES
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
    def __init__(self, src_ip: list = None, dst_ip: Optional[list] = None, src_host: Optional[list] = None,
                 dst_host: Optional[list] = None, url: Optional[list] = None, port: Optional[list] = None,
                 protocol: Optional[list] = None, app: Optional[list] = None, os: Optional[list] = None,
                 user: Optional[list] = None, cve: Optional[list] = None, file_name: Optional[list] = None,
                 file_hash: Optional[list] = None, cmd: Optional[list] = None, process: Optional[list] = None,
                 technique: Optional[list] = None, entry_type: Optional[list] = None, severity: Optional[list] = None,
                 sensor: Optional[list] = None, action: Optional[list] = None, event_id: Optional[list] = None,
                 error_code: Optional[list] = None, terms: Optional[list] = None, incident_types: Optional[list] = None,
                 analysts: Optional[list] = None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_host = src_host
        self.dst_host = dst_host
        self.url = url
        self.port = port
        self.protocol = protocol
        self.app = app
        self.os = os
        self.user = user
        self.cve = cve
        self.file_name = file_name
        self.file_hash = file_hash
        self.cmd = cmd
        self.process = process
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
        - Exception: If the function fails to retrieve data from any configured source with a HTTP status code other
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
    def syslog(cls, count: int, observables: Optional[Observables] = None) -> List[str]:
        """
        Generate fake syslog messages.

        Args:
            count: The number of syslog messages to generate.
            observables: An observables object. If not provided, random objservable will be generated and used.

        Returns:
            A list of syslog messages.

        Examples:
            >>> Events.syslog(5)
            ['Jan 01 05:32:48 myhostname sudo[1023]: username : COMMAND ; cat /etc/shadow',
             'Feb 03 10:17:59 myhostname sudo[2019]: username : COMMAND ; find / -name \'*.log\' -exec rm -f {} \\;',
             'Mar 12 22:46:16 myhostname sudo[3132]: username : COMMAND ; dd if=/dev/zero of=/dev/sda',
             'Apr 07 02:08:08 myhostname sudo[4111]: username : COMMAND ; chmod -R 777 /',
             'May 30 16:59:41 myhostname sudo[5195]: username : COMMAND ; chown -R nobody:nogroup /']

        """
        syslog_messages = []
        faker = cls._create_faker()

        for i in range(count):
            timestamp = faker.date_time_this_year()
            pid = faker.random_int(min=1000, max=65535)
            action = "COMMAND"
            host = random.choice(observables.src_host) if observables and observables.src_host \
                else faker.hostname()
            user = random.choice(observables.user) if observables and observables.user \
                else faker.user_name()
            process = random.choice(observables.process) if observables and observables.process \
                else "sudo"
            command = random.choice(observables.cmd) if observables and observables.cmd \
                else random.choice(UNIX_CMD)
            syslog_messages.append(f"{timestamp.strftime('%b %d %H:%M:%S')} {host} {process}[{pid}]: {user}"
                                   f" : {action} ; {command}")
        return syslog_messages

    @classmethod
    def cef(cls, count: int, observables: Optional[Observables] = None) -> List[str]:
        """
        Generates fake CEF (Common Event Format) messages.

        Args:
            count: The number of CEF messages to generate.
            observables: An observables object. If not provided, random objservable will be generated and used.
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
        version = faker.numerify("1.0.#")
        for i in range(count):
            uuid = faker.uuid4()
            vendor = faker.company()
            src_port = faker.random_int(min=1024, max=65535)
            host = random.choice(observables.src_host) if observables and observables.src_host \
                else faker.hostname()
            dst_ip = random.choice(observables.dst_ip) if observables and observables.dst_ip \
                else Observables.generator(observable_type=ObservableType.IP, known=ObservableKnown.BAD, count=1)
            url = random.choice(observables.url) if observables and observables.url \
                else Observables.generator(observable_type=ObservableType.URL, known=ObservableKnown.BAD, count=1)
            dst_port = random.choice(observables.port) if observables and observables.port \
                else faker.random_int(min=1024, max=65535)
            protocol = random.choice(observables.protocol) if observables and observables.protocol \
                else random.choice(PROTOCOLS)
            action = random.choice(observables.action) if observables and observables.action \
                else random.choice(ACTIONS)
            event_id = random.choice(observables.event_id) if observables and observables.event_id \
                else faker.random_int(min=1, max=10)
            event_description = f"Firewall {action} {protocol} traffic from {host}:{src_port} to {dst_ip}:{dst_port}"
            cef_messages.append(f"CEF:0|{vendor}|Firewall|{version}|{uuid}|{event_description}|"
                                f"{event_id}|src={host} spt={src_port} dst={dst_ip} url={url} "
                                f"dpt={dst_port} proto={protocol} act={action}")
        return cef_messages

    @classmethod
    def leef(cls, count, observables: Optional[Observables] = None) -> List[str]:
        """
        Generates fake LEEF (Log Event Extended Format) messages.

        Parameters:
            count (int): The number of LEEF messages to generate.
            observables: An observables object. If not provided, random objservable will be generated and used.

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

        for i in range(count):
            src_port = faker.random_int(min=1024, max=65535)
            request_size = faker.random_int(min=100, max=10000)
            response_size = faker.random_int(min=100, max=10000)
            user_agent = faker.user_agent()
            host = random.choice(observables.src_host) if observables and observables.src_host \
                else faker.hostname()
            src_ip = random.choice(observables.src_ip) if observables and observables.src_ip \
                else faker.ipv4()
            url = random.choice(observables.technique).get('indicator') if observables and observables.technique \
                else random.choice(TECHNIQUES).get('indicator')
            file_hash = random.choice(observables.file_hash) if observables and observables.file_hash \
                else Observables.generator(observable_type=ObservableType.SHA256, known=ObservableKnown.BAD, count=1)
            method = random.choice(observables.technique).get('mechanism') if observables and observables.technique \
                else random.choice(TECHNIQUES).get('mechanism')
            error_code = random.choice(observables.error_code) if observables and observables.error_code \
                else random.choice(ERROR_CODE)

            leef_log = f"LEEF:1.0|Leef|Payment Portal|1.0|{faker.ipv4()}|{host}|{faker.mac_address()}|" \
                       f"{faker.mac_address()}|"
            leef_log += f"src={src_ip} dst={host} spt={src_port} dpt=443 request={url} "
            leef_log += f"method={method} proto=HTTP/1.1 status={str(error_code)} hash={file_hash}"
            leef_log += f"request_size={request_size} " \
                        f"response_size={response_size} "
            leef_log += f"user_agent={user_agent}"
            leef_messages.append(leef_log)
        return leef_messages

    @classmethod
    def winevent(cls, count, observables: Optional[Observables] = None) -> List[str]:
        """
        Generates fake Windows Event Log messages.

        Args:
            count (int): The number of fake messages to generate.
            observables: An observables object. If not provided, random objservable will be generated and used.

        Returns:
            list: A list of fake Windows Event Log messages.

        Examples:
            >>> Events.winevent(1)
            ['<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">...</Event>', ...]
        """
        winevent_messages = []
        faker = cls._create_faker()

        for i in range(count):
            guid = faker.uuid4()
            src_port = faker.random_int(min=1024, max=65535)
            transmitted_services = faker.sentence(nb_words=5)
            system_time = faker.date_time_this_year().isoformat()
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
            process_name = random.choice(observables.process) if observables and observables.process \
                else random.choice(WIN_PROCESSES)
            host = random.choice(observables.src_host) if observables and observables.src_host \
                else faker.hostname()
            user_name = random.choice(observables.user) if observables and observables.src_host \
                else faker.user_name()
            cmd = random.choice(observables.cmd) if observables and observables.cmd \
                else random.choice(WINDOWS_CMD)
            source_network_address = random.choice(observables.src_ip) if observables and observables.src_ip \
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
                                                 source_network_address=source_network_address, source_port=src_port,
                                                 transmitted_services=transmitted_services, file_name=file_name)
            winevent_messages.append(win_event)
        return winevent_messages

    @classmethod
    def json(cls, count, observables: Optional[Observables] = None) -> List[dict]:
        """
        Generate fake JSON messages representing discovered vulnerabilities.

        Args:
            count (int): The number of JSON messages to generate.
            observables: An observables object. If not provided, random objservable will be generated and used.
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
        for i in range(count):
            system_time = faker.date_time_this_year().isoformat()
            cve_id = random.choice(observables.cve) if observables and observables.cve \
                else Observables.generator(observable_type=ObservableType.CVE, count=1)
            host = random.choice(observables.src_host) if observables and observables.src_host \
                else faker.hostname()
            severity = random.choice(observables.severity) if observables and observables.severity \
                else faker.random_int(min=1, max=5)
            file_hash = random.choice(observables.file_hash) if observables and observables.file_hash \
                else Observables.generator(observable_type=ObservableType.SHA256, known=ObservableKnown.BAD, count=1)
            event = {
                'event_type': 'vulnerability_discovered',
                'timestamp': system_time,
                'severity': severity,
                'host': host,
                'file_hash': file_hash,
                'cve': cve_id
            }
            json_messages.append(event)
        return json_messages

    @classmethod
    def incidents(cls, count, fields: Optional[str] = None, observables: Optional[Observables] = None) -> List[dict]:
        """
        Generates a list of fake incident data.

        Args:
            count (int): The number of incidents to generate.
            fields (str, optional): A comma-separated list of incident fields to include in the output. If None,
                all fields will be included. Valid options are: 'id', 'duration', 'type', 'analyst', 'severity',
                'description', 'events'.
            observables: An observables object. If not provided, random objservable will be generated and used.

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
                        {"event": cls.syslog(count=1, observables=observables)[0]},
                        {"event": cls.cef(count=1, observables=observables)[0]},
                        {"event": cls.leef(count=1, observables=observables)[0]},
                        {"event": cls.winevent(count=1, observables=observables)[0]},
                        {"event": cls.json(count=1, observables=observables)[0]}
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
