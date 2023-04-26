from enum import Enum


class ConverterFromEnum(Enum):
    CEF = 'cef'


class ConverterToEnum(Enum):
    JSON = 'json'
    LEEF = 'leef'


class Converter:
    @classmethod
    def convert(cls, from_type: ConverterFromEnum, to_type: ConverterToEnum, data: str) -> dict:
        """
        Converts a CEF log message to JSON format.

        Args:
            from_type (ConverterFromEnum): The "from" data type, currently supported options are CEF.
            to_type (to_type): The "to" data type, currently supported options are JSON and LEEF.
            data (str): The data message to be converted.

        Returns:
            str: The converted data message.

        Raises:
            ValueError: If the data message is invalid.

        Example:
            >>> data = "CEF:0|Security|threatmanager|1.0|100|detected an attack|10|src=192.168.1.1 dst=192.168.1.2"
            >>> Converter.convert(from_type=ConverterFromEnum.CEF, to_type=ConverterToEnum.JSON, data=data)
            '{"message": "converted", "data": {"version": "0", "device_vendor": "Security", "device_product":
            "threatmanager", "device_version": "1.0", "device_event_class_id": "100", "name": "detected an attack",
            "extensions": {"src": "192.168.1.1", "dst": "192.168.1.2"}}}'
        """
        converted_data = None
        if from_type == ConverterFromEnum.CEF:

            parts = data.split('|')
            if len(parts) < 6:
                raise ValueError('Invalid CEF log format')

            if to_type == ConverterToEnum.JSON:
                converted_data = {
                    'version': parts[0],
                    'device_vendor': parts[1],
                    'device_product': parts[2],
                    'device_version': parts[3],
                    'device_event_class_id': parts[4],
                    'name': parts[5],
                    'extensions': {}
                }
                if len(parts) > 6:
                    for ext in parts[6].split(' '):
                        key, value = ext.split('=', 1)
                        converted_data['extensions'][key] = value

            elif to_type == ConverterToEnum.LEEF:
                leef_dict = {
                    'LEEF': '1.0',
                    'Vendor': parts[1],
                    'Product': parts[2],
                    'Version': parts[3],
                    'EventID': parts[4],
                    'Name': parts[5]
                }
                if len(parts) > 6:
                    for ext in parts[6].split(' '):
                        key, value = ext.split('=', 1)
                        leef_dict[key] = value
                converted_data = '!'.join([f"{k}={v}" for k, v in leef_dict.items()])
        if converted_data:
            return {
                "message": "converted",
                "data": converted_data
            }
        else:
            return {
                "message": "inputs invalid",
                "data": converted_data
            }
