import unittest
from rosetta.rfaker import Events, Observables, ObservableType, ObservableKnown

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


class TestObservables(unittest.TestCase):
    def test_generator(self):
        generated_bad_ip = Observables.generator(count=2, observable_type=ObservableType.IP,
                                                 known=ObservableKnown.BAD)
        self.assertTrue(isinstance(generated_bad_ip, list))
        self.assertEqual(len(generated_bad_ip), 2)
        generated_good_ip = Observables.generator(count=1, observable_type=ObservableType.IP,
                                                  known=ObservableKnown.GOOD)
        self.assertTrue(isinstance(generated_good_ip, list))
        self.assertEqual(len(generated_good_ip), 1)
        generated_bad_url = Observables.generator(count=3, observable_type=ObservableType.URL,
                                                  known=ObservableKnown.BAD)
        self.assertTrue(isinstance(generated_bad_url, list))
        self.assertEqual(len(generated_bad_url), 3)
        generated_good_url = Observables.generator(count=4, observable_type=ObservableType.URL,
                                                   known=ObservableKnown.GOOD)
        self.assertTrue(isinstance(generated_good_url, list))
        self.assertEqual(len(generated_good_url), 4)
        generated_bad_hash = Observables.generator(count=2, observable_type=ObservableType.SHA256,
                                                   known=ObservableKnown.BAD)
        self.assertTrue(isinstance(generated_bad_hash, list))
        self.assertEqual(len(generated_bad_hash), 2)
        generated_good_hash = Observables.generator(count=1, observable_type=ObservableType.SHA256,
                                                    known=ObservableKnown.GOOD)
        self.assertTrue(isinstance(generated_good_hash, list))
        self.assertEqual(len(generated_good_hash), 1)
        generated_term = Observables.generator(count=1, observable_type=ObservableType.TERMS)
        self.assertTrue(isinstance(generated_term, list))
        self.assertEqual(len(generated_term), 1)
        generated_cve = Observables.generator(count=1, observable_type=ObservableType.CVE)
        self.assertTrue(isinstance(generated_cve, list))
        self.assertEqual(len(generated_cve), 1)
        for message in generated_cve:
            self.assertIn('CVE', message)


class TestRFaker(unittest.TestCase):

    def test_syslog(self):
        fake_messages = Events.syslog(count=2, observables=observables_list)
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 2)
        for message in fake_messages:
            self.assertIn(observables_list.src_host[0], message)

    def test_cef(self):
        fake_messages = Events.cef(count=2, observables=observables_list)
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 2)
        for message in fake_messages:
            self.assertIn(f'from {observables_list.src_host[0]}', message)

    def test_leef(self):
        fake_messages = Events.leef(count=2, observables=observables_list)
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 2)
        for message in fake_messages:
            self.assertIn(f'|{observables_list.src_host[0]}|', message)

    def test_winevent(self):
        fake_messages = Events.winevent(count=2, observables=observables_list)
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 2)
        for message in fake_messages:
            self.assertIn(f"{observables_list.src_host[0]}", message)

    def test_json(self):
        fake_messages = Events.json(count=2, observables=observables_list)
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 2)
        for message in fake_messages:
            self.assertIn(f"{observables_list.src_host[0]}", message['host'])

    def test_incidents(self):
        fake_messages = Events.incidents(count=2, observables=observables_list)
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 2)
        for message in fake_messages:
            self.assertIn(f"{observables_list.incident_types[0]}", message['type'])


if __name__ == '__main__':
    unittest.main()
