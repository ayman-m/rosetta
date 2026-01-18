from rosetta import Events, Observables

# Presets are loaded from rosetta/schema/required_presets.json
print("SYSLOG preset count:", len(Events._get_required_fields("syslog")))
print("WINEVENT preset count:", len(Events._get_required_fields("winevent")))

# Schema validation warns on unknown fields (non-blocking)
Events.syslog(count=1, observables=Observables(), required_fields="unknown_field")
