[![snyk](https://snyk.io/test/github/ayman-m/rosetta/badge.svg)](https://snyk.io/test/github/my-soc/Rosetta)
![codeql](https://github.com/ayman-m/rosetta/actions/workflows/github-code-scanning/codeql/badge.svg)
[![slack-community](https://img.shields.io/badge/Slack-4A154C?logo=slack&logoColor=white)](https://go-rosetta.slack.com)

# Rosetta

Rosetta is a Python package that can be used to fake security logs and alerts for testing different detection and response use cases. It provides the following functions:
- Generate bad and random observables/indicators that include IP Addresses, Urls, File hashes , CVE's and more
- Fake log messages in different formats like CEF, LEEF and JSON.
- Convert one log format into another, for example from CEF to LEEF.
- Send the fake log message to different log management and analytics tools.

## Installation

- You can install rosetta via pip:
```sh
pip install rosetta-ce
```
- Or you can install it from the source code:
```sh
git clone https://github.com/ayman-m/rosetta.git
cd rosetta
python setup.py install
```
- Once installed, you can import the library in your Python code like this:
```python
from rosetta import Observables, Events
```

## Usage
Here are some examples of how to use Rosetta:
```python
from rosetta import Converter, ConverterToEnum, ConverterFromEnum, Events, ObservableType, ObservableKnown, \
    Observables, Sender, WorkerTypeEnum

# Example usage of the Converter class to convert a CEF log into a LEEF log.
converted_log = Converter.convert(from_type=ConverterFromEnum.CEF, to_type=ConverterToEnum.LEEF,
                                  data="cef_log=CEF:0|Security|Intrusion Detection System|1.0|Alert|10|src=192.168.0.1 dst=192.168.0.2 act=blocked")
print(
    converted_log)  # {'message': 'converted', 'data': 'LEEF=1.0!Vendor=Security!Product=Intrusion Detection System!Version=1.0!EventID=Alert!Name=10!src=192.168.0.1!dst=192.168.0.2!act=blocked'}

# Example usage of the Observables class to generate bad IP indicators.
bad_ip = Observables.generator(count=2, observable_type=ObservableType.IP, known=ObservableKnown.BAD)
print(bad_ip)  # ['ip1', 'ip2']

# Example usage of the Observables class to generate good IP indicators.
good_ip = Observables.generator(count=2, observable_type=ObservableType.IP, known=ObservableKnown.GOOD)
print(good_ip)  # ['ip1', 'ip2']

# Example usage of the Observables class to generate bad URL indicators.
bad_url = Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.BAD)
print(bad_url)  # ['url1', 'url2']

# Example usage of the Observables class to generate good URL indicators.
good_url = Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.GOOD)
print(good_url)  # ['url1', 'url2']

# Example usage of the Observables class to generate bad Hash indicators.
bad_hash = Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.BAD)
print(bad_hash)  # ['hash1', 'hash2']

# Example usage of the Observables class to generate good Hash indicators.
good_hash = Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.GOOD)
print(good_hash)  # ['hash1', 'hash2']

# Example usage of the Observables class to generate CVE indicators.
cve = Observables.generator(count=2, observable_type=ObservableType.CVE)
print(cve)  # Example: ['CVE-2023-2136', 'CVE-2023-29582']

# Example usage of the Observables class to generate random Terms.
terms = Observables.generator(count=2, observable_type=ObservableType.TERMS)
print(terms)  # Example: ['Create or Modify System Process', 'Stage Capabilities: Drive-by Target']


# You can create an instance of the Observables class to contain your own observables that are to be used in the fake security events
src_ip, dst_ip, src_host, dst_host = ["192.168.10.10", "192.168.10.20"], ["1.1.1.1", "1.1.1.2"], ["abc"], ["xyz", "wlv"]
url, port = ["https://example.org", "https://wikipedia.com"], ["555", "666"]
protocol, app = ["ftp", "dns", "ssl"], ["explorer.exe", "chrome.exe"]
user = ["ayman", "mahmoud"]
file_name, file_hash = ["test.zip", "image.ps"], ["719283fd5600eb631c23b290530e4dac9029bae72f15299711edbc800e8e02b2"]
cmd, process = ["sudo restart", "systemctl stop firewalld"], ["bind", "crond"]
severity = ["high", "critical"]
sensor = ["fw", "edr"]
action = ["block", "allow"]
observables_list = Observables(src_ip=src_ip, dst_ip=dst_ip, src_host=src_host, dst_host=dst_host, url=url, port=port,
                               protocol=protocol, app=app, user=user, file_name=file_name, file_hash=file_hash, cmd=cmd,
                               process=process, severity=severity, sensor=sensor, action=action)

# Example usage of the Events class to generate generic SYSLOG events.
generic_syslog_with_random_observables = Events.syslog(count=1)
print(generic_syslog_with_random_observables)  # ['Jan 20 16:04:53 db-88.zuniga.net sudo[34675]: ryansandy : COMMAND ; iptables -F']
generic_syslog_with_my_observables = Events.syslog(count=1, observables=observables_list)
print(generic_syslog_with_my_observables)  # ['Apr 07 10:21:43 abc crond[17458]: ayman : COMMAND ; sudo restart']


# Example usage of the Events class to generate CEF events.
generic_cef_with_my_observables = Events.cef(count=1, observables=observables_list)
print(generic_cef_with_my_observables)  # ['CEF:0|Novak LLC|Firewall|1.0.6|3019ab69-2d0e-4b3f-a240-4e8c93042dc3|Firewall allow dns traffic from abc:33504 to 1.1.1.1:666|5|src=abc spt=33504 dst=1.1.1.1 url=https://example.org dpt=666 proto=dns act=allow']


leef_with_my_observables = Events.leef(count=1, observables=observables_list)
print(leef_with_my_observables)  # ["LEEF:1.0|Leef|Payment Portal|1.0|210.12.108.86|abc|9a:1e:9d:00:4c:ba|3b:a0:4b:24:f7:59|src=192.168.10.10 dst=abc spt=61549 dpt=443 request=https://example.com/search.php?q=<script>alert('xss')</script> method=Web-GET proto=HTTP/1.1 status=500 hash=719283fd5600eb631c23b290530e4dac9029bae72f15299711edbc800e8e02b2request_size=6173 response_size=8611 user_agent=Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_5 like Mac OS X) AppleWebKit/536.1 (KHTML, like Gecko) FxiOS/12.1s4879.0 Mobile/00Y135 Safari/536.1"]

winevent_with_my_observables = Events.winevent(count=1, observables=observables_list)
print(winevent_with_my_observables)  # ['<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="5fc4a88c-97b0-4061-adc3-052159c10ef4"/><EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2023-04-07T18:45:17"/><EventRecordID>575</EventRecordID><Correlation/><Execution ProcessID="1071" ThreadID="5317" Channel="Security"/><Computer>abc</Computer><Security UserID="S-1-2915"/><EventData><Data Name="SubjectUserSid">S-1-2915</Data><Data Name="SubjectUserName">mahmoud</Data><Data Name="SubjectDomainName">johnson.org</Data><Data Name="SubjectLogonId">S-1-2915</Data><Data Name="NewProcessId">3371</Data><Data Name="ProcessId">1071</Data><Data Name="CommandLine">sudo restart</Data><Data Name="TargetUserSid">S-1-2915</Data><Data Name="TargetUserName">mahmoud</Data><Data Name="TargetDomainName">johnson.org</Data><Data Name="TargetLogonId">S-1-2915</Data><Data Name="LogonType">3</Data></EventData></Event>']

json_with_my_observables = Events.json(count=1, observables=observables_list)
print(json_with_my_observables) # [{'event_type': 'vulnerability_discovered', 'timestamp': '2023-02-12T16:28:46', 'severity': 'high', 'host': 'abc', 'file_hash': '719283fd5600eb631c23b290530e4dac9029bae72f15299711edbc800e8e02b2', 'cve': ['CVE-3941-1955']}]

incident_with_my_observables = Events.incidents(count=1, fields="id,type,duration,analyst,description,events", observables=observables_list)
print(incident_with_my_observables) # [{'id': 1, 'duration': 2, 'type': 'Lateral Movement', 'analyst': 'Elizabeth', 'description': 'Software Discovery Forge Web Credentials: SAML Tokens Escape to Host System Binary Proxy Execution: Control Panel Hide Artifacts: Process Argument Spoofing Office Application Startup: Add-ins Compromise Infrastructure: Botnet.', 'events': [{'event': 'Apr 09 19:39:57 abc bind[56294]: ayman : COMMAND ; systemctl stop firewalld'}, {'event': 'CEF:0|Todd, Guzman and Morales|Firewall|1.0.4|afe3d30f-cff4-4084-a7a3-7de9ea21d0e9|Firewall block dns traffic from abc:26806 to 1.1.1.1:555|10|src=abc spt=26806 dst=1.1.1.1 url=https://example.org dpt=555 proto=dns act=block'}, {'event': 'LEEF:1.0|Leef|Payment Portal|1.0|19.90.247.108|abc|d4:27:4c:a7:40:50|2a:3f:f3:37:81:eb|src=192.168.10.20 dst=abc spt=47335 dpt=443 request=https://example.com/index.php method=Web-GET proto=HTTP/1.1 status=500 hash=719283fd5600eb631c23b290530e4dac9029bae72f15299711edbc800e8e02b2request_size=3640 response_size=4766 user_agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_1) AppleWebKit/533.0 (KHTML, like Gecko) Chrome/47.0.819.0 Safari/533.0'}, {'event': '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="67eb0bb0-ab24-43ce-b7f1-6d6a6bb0ac27"/><EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2023-01-15T04:07:58"/><EventRecordID>38</EventRecordID><Correlation/><Execution ProcessID="7182" ThreadID="7703" Channel="Security"/><Computer>abc</Computer><Security UserID="S-1-7181"/><EventData><Data Name="SubjectUserSid">S-1-7181</Data><Data Name="SubjectUserName">mahmoud</Data><Data Name="SubjectDomainName">johnson.net</Data><Data Name="SubjectLogonId">9638</Data><Data Name="PrivilegeList">Through moment tonight.</Data></EventData></Event>'}, {'event': {'event_type': 'vulnerability_discovered', 'timestamp': '2023-01-18T23:49:45', 'severity': 'critical', 'host': 'abc', 'file_hash': '719283fd5600eb631c23b290530e4dac9029bae72f15299711edbc800e8e02b2', 'cve': ['CVE-2023-29067']}}]}]

# Example usage of the Sender class to send faked events to log analysis tool.
worker = Sender(data_type=WorkerTypeEnum.SYSLOG, destination="udp:127.0.0.1:514", observables=observables_list, count=5, interval=2)
worker.start()

# Starting worker: worker_2023-04-26 17:50:15.671101
# Worker: worker_2023-04-26 17:50:15.671101 sending log message to 127.0.0.1 
# Worker: worker_2023-04-26 17:50:15.671101 sending log message to 127.0.0.1 
# Worker: worker_2023-04-26 17:50:15.671101 sending log message to 127.0.0.1 
# Worker: worker_2023-04-26 17:50:15.671101 sending log message to 127.0.0.1 
# Worker: worker_2023-04-26 17:50:15.671101 sending log message to 127.0.0.1 

```
