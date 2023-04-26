import unittest
from unittest.mock import patch
from rosetta.rsender import Sender, WorkerTypeEnum
from rosetta.rfaker import Observables

src_ip, dst_ip, src_host, dst_host = ["192.168.10.10"], ["1.1.1.1"], ["abc"], ["xyz"]
url, port = ["https://example.org"], ["555"]
protocol, app = ["ftp"], ["chrome.exe"]
user = ["ayman"]
file_name, file_hash = ["test.zip"], ["719283fd5600eb631c23b290530e4dac9029bae72f15299711edbc800e8e02b2"]
cmd, process = ["sudo restart"], ["bind"]
severity = ["high", "critical"]
sensor = ["fw"]
action = ["block"]
incident_types = ["Phishing"]

observables_list = Observables(src_ip=src_ip, dst_ip=dst_ip, src_host=src_host, dst_host=dst_host, url=url, port=port,
                               protocol=protocol, app=app, user=user, file_name=file_name, file_hash=file_hash, cmd=cmd,
                               process=process, severity=severity, sensor=sensor, action=action,
                               incident_types=incident_types)


class TestRSender(unittest.TestCase):

    def setUp(self):
        self.worker = Sender(
            data_type=WorkerTypeEnum.SYSLOG,
            destination='tcp://127.0.0.1:514',
            count=1,
            interval=1,
            observables=observables_list
        )

    def tearDown(self):
        self.worker.stop()

    def test_start(self):
        self.worker.start()
        self.assertEqual(self.worker.status, 'Running')

    def test_stop(self):
        self.worker.start()
        self.worker.stop()
        self.assertEqual(self.worker.status, 'Stopped')

    @patch('rosetta.rsender.RSender.send_data')
    def test_send_data(self, mock_send_data):
        self.worker.start()
        mock_send_data.assert_called()


if __name__ == '__main__':
    unittest.main()
