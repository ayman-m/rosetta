import unittest
from rosetta.rfaker import RFaker


class TestRFaker(unittest.TestCase):

    def test_syslog_messages(self):
        fake_messages = RFaker.syslog_messages(count=10, host='localhost')
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn(' localhost ', message)

    def test_cef_messages(self):
        fake_messages = RFaker.cef_messages(count=10, host='localhost')
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn('from localhost', message)

    def test_leef_messages(self):
        fake_messages = RFaker.leef_messages(count=10, host='localhost')
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn('|localhost|', message)

    def test_json_messages(self):
        fake_messages = RFaker.json_messages(count=10, host='localhost')
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn("localhost", message['host'])


if __name__ == '__main__':
    unittest.main()
