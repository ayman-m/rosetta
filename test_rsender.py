import unittest
from unittest.mock import patch
from rosetta.rsender import RSender, WorkerTypeEnum


class TestRSender(unittest.TestCase):

    def setUp(self):
        self.worker = RSender(
            data_type=WorkerTypeEnum.SYSLOG,
            destination='tcp://127.0.0.1:514',
            count=1,
            interval=1,
            host='localhost'
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
