from rosetta import Observables, ObservableType, ObservableKnown

# Generate indicators (may fetch from sources if online; otherwise fallback values are used).
print("bad_ips:", Observables.generator(count=2, observable_type=ObservableType.IP, known=ObservableKnown.BAD))
print("good_ips:", Observables.generator(count=2, observable_type=ObservableType.IP, known=ObservableKnown.GOOD))
print("bad_urls:", Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.BAD))
print("good_urls:", Observables.generator(count=2, observable_type=ObservableType.URL, known=ObservableKnown.GOOD))
print("bad_hashes:", Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.BAD))
print("good_hashes:", Observables.generator(count=2, observable_type=ObservableType.SHA256, known=ObservableKnown.GOOD))
print("cves:", Observables.generator(count=2, observable_type=ObservableType.CVE))
print("terms:", Observables.generator(count=2, observable_type=ObservableType.TERMS))
