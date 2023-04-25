from rosetta import RConverter, RConverterToEnum, RConverterFromEnum, Events, ObservableType, ObservableKnown, \
    Observables, RSender, WorkerTypeEnum
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

#test = RConverter.converter(from_type=RConverterFromEnum.CEF, to_type=RConverterToEnum.LEEF, data="cef_log=CEF:0|Security|Intrusion Detection System|1.0|Alert|10|src=192.168.0.1 dst=192.168.0.2 act=blocked")
#test = Observables.generator(count=2, observable_type=ObservableType.IP, known=ObservableKnown.BAD)
#test = Observables.generator(count=2, observable_type=ObservableType.IP, known=ObservableKnown.GOOD)
#test = Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.BAD)
#test = Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.GOOD)
#test = Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.BAD)
#test = Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.GOOD)
#test = Observables.generator(count=2, observable_type=ObservableType.CVE)
#test = Observables.generator(count=2, observable_type=ObservableType.TERMS)
#test = Events.syslog(count=2)
#test = Events.syslog(count=2, observables=observables_list)
#test = Events.cef(count=2)
#test = Events.cef(count=2, observables=observables_list)
#test = Events.leef(count=2)
#test = Events.leef(count=2, observables=observables_list)
#test = Events.winevent(count=2)
#test = Events.winevent(count=2, observables=observables_list)

#test = Events.json(count=2)
#test = Events.json(count=2, observables=observables_list)

#test = Events.incidents(count=2)
#test = Events.incidents(count=2, observables=observables_list)
#test = Events.incidents(count=1, fields="duration,type,events", observables=observables_list)

#print (test)

worker = RSender(data_type=WorkerTypeEnum.SYSLOG, destination="udp:127.0.0.1:514", count=5, interval=2)
worker.start()
