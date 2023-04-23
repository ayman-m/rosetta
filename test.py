from rosetta import RConverter, RConverterToEnum, RConverterFromEnum, RFaker, ObservableType, ObservableKnown, Observables

#test = RConverter.converter(from_type=RConverterFromEnum.CEF, to_type=RConverterToEnum.LEEF, data="cef_log=CEF:0|Security|Intrusion Detection System|1.0|Alert|10|src=192.168.0.1 dst=192.168.0.2 act=blocked")
#test = Observables.generator(count=1, observable_type=ObservableType.IP, known=ObservableKnown.BAD)
#test = Observables.generator(count=2, observable_type=ObservableType.IP, known=ObservableKnown.GOOD)
#test = Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.BAD)
#test = Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.GOOD)
#test = Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.BAD)
#test = Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.GOOD)
#test = Observables.generator(count=2, observable_type=ObservableType.CVE)
test = Observables.generator(count=2, observable_type=ObservableType.TERMS)

print (test)