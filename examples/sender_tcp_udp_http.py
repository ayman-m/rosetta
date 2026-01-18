from rosetta import Sender, WorkerTypeEnum, Observables

observables = Observables(src_host=["sender-host"], user=["sam"], url=["https://example.org"])

# UDP syslog
udp_worker = Sender(
    data_type=WorkerTypeEnum.SYSLOG,
    destination="udp:127.0.0.1:514",
    observables=observables,
    count=2,
    interval=1,
)

# TCP syslog
tcp_worker = Sender(
    data_type=WorkerTypeEnum.SYSLOG,
    destination="tcp:127.0.0.1:514",
    observables=observables,
    count=2,
    interval=1,
)

# HTTP JSON
http_worker = Sender(
    data_type=WorkerTypeEnum.JSON,
    destination="http://127.0.0.1:8000/logs",
    observables=observables,
    count=2,
    interval=1,
)

# Start workers (make sure endpoints are available).
udp_worker.start()
tcp_worker.start()
http_worker.start()
