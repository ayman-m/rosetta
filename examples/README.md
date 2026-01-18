# Rosetta examples

Run any example from the project root:

```sh
PYTHONPATH=. python3 examples/observables.py
```

Examples:
- `observables.py`: generate indicators from sources or fallback data
- `events_formats.py`: create SYSLOG/CEF/LEEF/JSON/Winevent outputs
- `incidents.py`: build incident bundles
- `sender_tcp_udp_http.py`: send events to TCP/UDP/HTTP endpoints
- `converter.py`: convert CEF to JSON/LEEF
- `presets_schema.py`: show required field presets and schema validation warnings
- `k8s_fields.py`: demonstrate Kubernetes-specific field inference

Notes:
- If you installed the package, you can omit `PYTHONPATH=.`.
- `sender_tcp_udp_http.py` expects live listeners; otherwise it will log connection errors.
