import unittest
from rosetta.rconverter import RConverter, RConverterToEnum, RConverterFromEnum


class TestRConverter(unittest.TestCase):

    def test_converter(self):
        cef_log = "CEF:0|Security|Intrusion Detection System|1.0|Alert|10|src=192.168.0.1 dst=192.168.0.2 act=blocked"
        expected_json = {
            'message': 'converted',
            'data': {
                'version': 'CEF:0',
                'device_vendor': 'Security',
                'device_product': 'Intrusion Detection System',
                'device_version': '1.0',
                'device_event_class_id': 'Alert',
                'name': '10',
                'extensions': {
                    'src': '192.168.0.1',
                    'dst': '192.168.0.2',
                    'act': 'blocked'
                }
            }
        }

        result = RConverter.converter(from_type=RConverterFromEnum.CEF, to_type=RConverterToEnum.JSON, data=cef_log)
        self.assertEqual(result, expected_json)


if __name__ == '__main__':
    unittest.main()
