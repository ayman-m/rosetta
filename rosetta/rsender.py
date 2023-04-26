import datetime
import time
import threading
import socket
import requests
import warnings
from enum import Enum
from typing import Optional
from urllib3.exceptions import InsecureRequestWarning

from rosetta.rfaker import Observables, Events


class WorkerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    INCIDENT = 'incident'


class Sender:
    """
    A class for sending fake data to a destination via a TCP or UDP socket or HTTP request.

    Args:
        worker_name (str): Name of the worker.
        data_type (WorkerTypeEnum): Type of the data to send.
        count (int): Number of messages to send.
        interval (int): Time interval (in seconds) between each message sent.
        destination (str): Destination address in the format <protocol>://<ip_address>:<port>.
        observables (Observables): Host name or IP address to use for fake data.
        fields (str): Comma-separated list of incident fields to include in the fake data.

    Attributes:
        thread (threading.Thread): Thread object for the worker.
        worker_name (str): Name of the worker.
        data_type (WorkerTypeEnum): Type of the data to send.
        count (int): Number of messages to send.
        interval (int): Time interval (in seconds) between each message sent.
        destination (str): Destination address in the format <protocol>://<ip_address>:<port>.
        created_at (datetime): Timestamp of when the worker was created.
        status (str): Status of the worker (Running, Stopped, Connection Error).
        observables (list): Host name or IP address to use for fake data.
        fields (str): Comma-separated list of incident fields to include in the fake data.

    Methods:
        start() -> str:
            Starts the worker thread.

            Returns:
                str: Current status of the worker (Running, Stopped).

        stop() -> str:
            Stops the worker thread.

            Returns:
                str: Current status of the worker (Running, Stopped).

        send_data() -> None:
            Sends fake data to the destination address.

            Returns:
                None.
    """

    def __init__(self, data_type: WorkerTypeEnum, destination: str,
                 worker_name: Optional[str] = 'worker_'+str(datetime.datetime.now()), count: Optional[int] = 1,
                 interval: Optional[int] = 1, observables: Optional[Observables] = None, fields: Optional[str] = None,
                 verify_ssl: Optional[bool] = None):
        """
        Constructor for DataSenderWorker class.

        :param data_type: A value from the WorkerTypeEnum indicating the type of data to send. Options include:
            - WorkerTypeEnum.SYSLOG
            - WorkerTypeEnum.CEF
            - WorkerTypeEnum.LEEF
            - WorkerTypeEnum.WINEVENT
            - WorkerTypeEnum.JSON
            - WorkerTypeEnum. INCIDENT
        :param destination: str, destination address and port in the format <scheme>://<address>:<port>.
        :param worker_name: str, name of the worker.
        :param count: int, number of times to send the data.
        :param interval: int, time interval between two consecutive data sends.
        :param observables: Observables, list of observables.
        :param fields: str, comma-separated list of fields to include in incident data.
        :param verify_ssl: bool, handling ssl verification errors.

        :return: None
        """
        self.thread = None
        self.worker_name = worker_name
        self.data_type = data_type
        self.count = count
        self.interval = interval
        self.destination = destination
        self.created_at = datetime.datetime.now()
        self.status = "Stopped"
        self.observables = observables
        self.fields = fields
        self.verify_ssl = verify_ssl

    def start(self) -> str:
        """
        Starts the worker thread.

        Returns:
            str: Current status of the worker (Running, Stopped).
        """
        if self.status == "Stopped":
            self.thread = threading.Thread(target=self.send_data, args=())
            self.status = "Running"
            print(f"Starting worker: {self.worker_name}")
            self.thread.start()
        return self.status

    def stop(self) -> str:
        """
        Stops the worker thread.

        Returns:
            str: Current status of the worker (Running, Stopped).
        """
        if self.status == "Running":
            self.thread.join()
            self.status = "Stopped"
        return self.status

    def send_data(self) -> None:
        """
        Sends fake data to the destination address.

        Returns:
            None.
        """
        fake_message = None
        while self.status == "Running" and self.count > 0:
            try:
                self.count -= 1
                if self.data_type in [WorkerTypeEnum.SYSLOG, WorkerTypeEnum.CEF, WorkerTypeEnum.LEEF]:
                    if self.data_type == WorkerTypeEnum.SYSLOG:
                        fake_message = Events.syslog(count=1, observables=self.observables)
                    if self.data_type == WorkerTypeEnum.CEF:
                        fake_message = Events.cef(count=1, observables=self.observables)
                    if self.data_type == WorkerTypeEnum.LEEF:
                        fake_message = Events.leef(count=1, observables=self.observables)
                    ip_address = self.destination.split(':')[1]
                    port = self.destination.split(':')[2]
                    if 'tcp' in self.destination:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.connect((ip_address, int(port)))
                        print(f"Worker: {self.worker_name} sending log message to {ip_address} ")
                        sock.sendall(fake_message[0].encode())
                        sock.close()
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(5)
                        print(f"Worker: {self.worker_name} sending log message to {ip_address} ")
                        sock.sendto(fake_message[0].encode(), (ip_address, int(port)))
                elif self.data_type in [WorkerTypeEnum.JSON, WorkerTypeEnum.INCIDENT]:
                    if self.data_type == WorkerTypeEnum.JSON:
                        fake_message = Events.json(count=1, observables=self.observables)
                    if self.data_type == WorkerTypeEnum.INCIDENT:
                        fake_message = [{
                            "alert": Events.incidents(count=1, observables=self.observables, fields=self.fields)
                        }]
                    if '://' not in self.destination:
                        url = 'http://' + self.destination
                    else:
                        url = self.destination
                    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
                    print(f"Worker: {self.worker_name} sending log message to {url} ")
                    response = requests.post(url, json=fake_message[0], timeout=(2, 5), verify=self.verify_ssl)
                    response.raise_for_status()
            except (ConnectionRefusedError, socket.timeout, requests.exceptions.RequestException) as e:
                print(f"Connection error: {e}")
                self.status = "Connection Error"
                break
            except requests.exceptions.SSLError as e:
                print(f"SSL error: {e}")
                self.status = "SSL Error"
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                self.status = "Stopped"
                break
            time.sleep(self.interval)
        if self.status == "Running":
            self.status = "Stopped"
