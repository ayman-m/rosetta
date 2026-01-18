from rosetta import Events, Observables

observables = Observables(
    src_host=["web-01"],
    user=["alex"],
    url=["https://example.org"],
    local_ip=["10.0.0.5"],
    remote_ip=["1.1.1.1"],
    protocol=["https"],
)

print("SYSLOG:", Events.syslog(count=1, observables=observables)[0])
print("CEF:", Events.cef(count=1, observables=observables)[0])
print("LEEF:", Events.leef(count=1, observables=observables)[0])
print("JSON:", Events.json(count=1, observables=observables)[0])
print("WINEVENT:", Events.winevent(count=1, observables=observables)[0])
