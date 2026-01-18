from rosetta import Events, Observables

observables = Observables(
    src_host=["soc-host"],
    user=["jordan"],
    url=["https://example.org"],
    incident_types=["Phishing"],
    severity=["high"],
)

incidents = Events.incidents(count=2, fields="id,type,duration,analyst,description,events", observables=observables)
for incident in incidents:
    print(incident)
