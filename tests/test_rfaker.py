import unittest
import time
from rosetta.rfaker import Events, Observables, ObservableType, ObservableKnown

local_ip, remote_ip, src_host, dst_host = ["192.168.10.10","192.168.10.11","192.168.10.12"], ["1.1.1.1","1.1.1.2","1.1.1.3"], ["abc"], ["xyz"]
url, remote_port = ["https://example.org"], ["555","556","557","558"]
protocol, app = ["ftp"], ["chrome.exe"]
user = ["ayman"]
file_name, file_hash = ["test.zip"], ["719283fd5600eb631c23b290530e4dac9029bae72f15299711edbc800e8e02b2"]
unix_cmd, unix_process = ["sudo restart"], ["bind"]
severity = ["high", "critical"]
sensor = ["fw"]
action = ["block"]
incident_types = ["Phishing"]


observables_list = Observables(local_ip=local_ip, remote_ip=remote_ip, src_host=src_host, dst_host=dst_host, url=url, remote_port=remote_port,
                               protocol=protocol, app=app, user=user, file_name=file_name, file_hash=file_hash, unix_cmd=unix_cmd,
                               unix_process=unix_process, severity=severity, sensor=sensor, action=action,
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

    @classmethod
    def tearDownClass(cls):
        # After all tests have run, print the field timings
        field_timings = Events.field_timings

        # Calculate average time per field
        for field, data in field_timings.items():
            total_time = data['total_time']
            count = data['count']
            average_time = total_time / count if count > 0 else 0
            data['average_time'] = average_time

        # Sort fields by total_time
        sorted_fields = sorted(
            field_timings.items(),
            key=lambda item: item[1]['total_time'],
            reverse=True
        )

        # Print the timing data
        print("\nField Timing Analysis:")
        for field, data in sorted_fields:
            print(f"Field: {field}")
            print(f"  Total Time: {data['total_time']:.6f} seconds")
            print(f"  Count: {data['count']}")
            print(f"  Average Time: {data['average_time']:.6f} seconds\n")


    def test_syslog(self):
        start_time = time.time()
        fake_messages = Events.syslog(count=10, observables=observables_list)
        end_time = time.time()
        latency = end_time - start_time
        print(f"Syslog generation latency for 10 logs: {latency:.4f} seconds")

        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn(observables_list.src_host[0], message)

    def test_cef(self):
        start_time = time.time()
        fake_messages = Events.cef(
            count=10,
            observables=observables_list,
            required_fields="local_ip,local_port,remote_ip,remote_port,protocol,rule_id,action"
        )
        end_time = time.time()
        latency = end_time - start_time
        print(f"CEF generation latency for 10 logs: {latency:.4f} seconds")
        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn(observables_list.src_host[0], message)

    def test_leef(self):
        start_time = time.time()
        fake_messages = Events.leef(count=10, observables=observables_list)
        end_time = time.time()
        latency = end_time - start_time
        print(f"LEEF generation latency for 10 logs: {latency:.4f} seconds")

        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn(observables_list.src_host[0], message)


    def test_json(self):
        start_time = time.time()
        fake_messages = Events.json(count=10, observables=observables_list)
        end_time = time.time()
        latency = end_time - start_time
        print(f"JSON generation latency for 10 logs: {latency:.4f} seconds")

        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn(observables_list.src_host[0], str(message))

    def test_winevent(self):
        start_time = time.time()
        fake_messages = Events.winevent(count=10, observables=observables_list)
        end_time = time.time()
        latency = end_time - start_time
        print(f"Windows Event generation latency for 10 logs: {latency:.4f} seconds")

        self.assertTrue(isinstance(fake_messages, list))
        self.assertEqual(len(fake_messages), 10)
        for message in fake_messages:
            self.assertIn(observables_list.src_host[0], message)


if __name__ == '__main__':
    unittest.main()
