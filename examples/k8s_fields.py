from rosetta import Events

fields = [
    "namespace",
    "pod_name",
    "container_name",
    "container_image",
    "labels",
    "annotations",
    "service_account",
    "node_name",
    "cluster",
]

for field in fields:
    value = Events._infer_field_value(field, Events.faker)
    print(f"{field} -> {value}")
