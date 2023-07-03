from datetime import datetime
import time
import threading
import socket
import requests
import warnings
from typing import Optional
from urllib3.exceptions import InsecureRequestWarning

from rosetta.rfaker import Observables, Events


class Sender:
    """
    A class for sending fake data to a destination via a TCP or UDP socket or HTTP request.

    Args:
        worker_name (str): Name of the worker.
        data_type (str): Type of the data to send.
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

    def __init__(self, data_type: str, destination: str, headers: Optional[dict] = None,
                 worker_name: Optional[str] = 'worker_'+str(datetime.now()), count: Optional[int] = 1,
                 interval: Optional[int] = 1, vendor: Optional[str] = None, product: Optional[str] = None,
                 version: Optional[str] = None, required_fields: Optional[str] = None,
                 observables: Optional[Observables] = None, fields: Optional[str] = None,
                 verify_ssl: Optional[bool] = None, datetime_obj: Optional[datetime] = None,
                 data_json: Optional[dict] = None, data_text: Optional[str] = None):
        """
        Constructor for DataSenderWorker class.

        :param data_type: A value from the WorkerTypeEnum indicating the type of data to send. Options include:
            - SYSLOG
            - CEF
            - LEEF
            - WINEVENT
            - JSON
            - INCIDENT
        :param destination: str, destination address and port in the format <scheme>://<address>:<port>.
        :param worker_name: str, name of the worker.
        :param count: int, number of times to send the data.
        :param interval: int, time interval between two consecutive data sends.
        :param vendor: Optional. The vendor.
        :param product: Optional. The product.
        :param version: Optional. The version.
        :param required_fields: Optional. A list of fields that are required to present in the generated data, whether
         from observables or randomely.
        :param observables: Optional. Observables, list of observables.
        :param fields: Optional. comma-separated list of fields to include in incident data.
        :param verify_ssl: Optional. handling ssl verification errors.
        :param datetime_obj: Optional. time to start from.
        :param data_json: Optional. JSON data to send.
        :param data_text: Optional. Text data to send.

        :return: None
        """
        if headers is None:
            self.headers = {}
        else:
            self.headers = headers
        self.thread = None
        self.worker_name = worker_name
        self.data_type = data_type
        self.count = count
        self.interval = interval
        self.vendor = vendor
        self.product = product
        self.version = version
        self.required_fields = required_fields
        self.destination = destination
        self.created_at = datetime.now()
        self.status = "Stopped"
        self.observables = observables
        self.fields = fields
        self.verify_ssl = verify_ssl
        self.datetime_obj = datetime_obj
        self.data_json = data_json
        self.data_text = data_text

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
                if self.data_type in ["SYSLOG", "CEF", "LEEF"]:
                    if self.data_text:
                        fake_message = [self.data_text]
                    else:
                        if self.data_type == "SYSLOG":
                            fake_message = Events.syslog(count=1, datetime_iso=self.datetime_obj,
                                                         observables=self.observables, required_fields=self.required_fields)
                        if self.data_type == "CEF":
                            fake_message = Events.cef(count=1, datetime_iso=self.datetime_obj, vendor=self.vendor,
                                                      product=self.product, version=self.version,
                                                      required_fields=self.required_fields, observables=self.observables)
                        if self.data_type == "LEEF":
                            fake_message = Events.leef(count=1, datetime_iso=self.datetime_obj, vendor=self.vendor,
                                                       product=self.product, version=self.version,
                                                       required_fields=self.required_fields,
                                                       observables=self.observables)
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
                elif self.data_type in ["JSON", "INCIDENT"]:
                    if self.data_json:
                        fake_message = [self.data_json]
                    else:
                        if self.data_type == "JSON":
                            fake_message = Events.json(count=1, datetime_iso=self.datetime_obj,
                                                       observables=self.observables, vendor=self.vendor,
                                                       product=self.product, version=self.version,
                                                       required_fields=self.required_fields,)
                        if self.data_type == "INCIDENT":
                            fake_message = [{
                                "alert": Events.incidents(count=1, observables=self.observables, vendor=self.vendor,
                                                          version=self.version, product=self.product,
                                                          datetime_iso=self.datetime_obj,
                                                          required_fields=self.required_fields, fields=self.fields)
                            }]
                    if '://' not in self.destination:
                        url = 'http://' + self.destination
                    else:
                        url = self.destination
                    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
                    print(f"Worker: {self.worker_name} sending log message to {url} ")
                    response = requests.post(url, json=fake_message[0], timeout=(2, 5), headers=self.headers,
                                             verify=self.verify_ssl)
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
