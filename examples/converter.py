from rosetta import Converter, ConverterToEnum, ConverterFromEnum

cef_log = "CEF:0|Security|IDS|1.0|Alert|10|src=192.168.0.1 dst=192.168.0.2 act=blocked"

json_output = Converter.convert(from_type=ConverterFromEnum.CEF, to_type=ConverterToEnum.JSON, data=cef_log)
leef_output = Converter.convert(from_type=ConverterFromEnum.CEF, to_type=ConverterToEnum.LEEF, data=cef_log)

print("JSON:", json_output)
print("LEEF:", leef_output)
