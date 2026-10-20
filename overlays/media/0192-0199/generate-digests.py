"""Author immutable domain-separation vectors independently of the JS encoder.

The common sample is deliberately an encoding probe, not a typed protocol body.
Complete typed examples are in the wire corpus.
"""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent


def canonical(value):
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return (
            "{"
            + ",".join(canonical(key) + ":" + canonical(value[key]) for key in keys)
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(map(canonical, value)) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


body = {
    "version": 1,
    "probe": {"\ue000": "BMP", "😀": "non-BMP", "text": "é\n\t", "empty": ""},
    "values": [
        None,
        False,
        True,
        0,
        1,
        9007199254740991,
        "18446744073709551615",
        "YQ==",
    ],
}
rows = []
for domain in json.loads((HERE / "registry.json").read_text())["digestDomains"]:
    message = ("BRC-OUTPUT/1/" + domain + "\0" + canonical(body)).encode("utf-8")
    rows.append(
        {
            "domain": domain,
            "preimage": message.hex(),
            "sha256": hashlib.sha256(message).hexdigest(),
        }
    )
result = {
    "version": 1,
    "kind": "encoding-probe-not-protocol-body",
    "body": body,
    "canonical": canonical(body),
    "vectors": rows,
}
(HERE / "digest-vectors.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + "\n"
)
