"""Verify a correlated delivery report in the JMAP submission after trusted routing."""

import argparse
import json
import os
from email import policy
from email.parser import BytesParser
from pathlib import Path
import ssl
from urllib.parse import quote
from urllib.request import Request, urlopen

# Python accepts hyphens in a script name but not in an import statement.
import runpy

matching_report = runpy.run_path(Path(__file__).with_name("verify-dsn.py"))["matching_report"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("checkpoint", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    saved = json.loads(args.checkpoint.read_text())
    context = ssl.create_default_context(cafile=config["TLSCert"])
    origin = config["PublicOrigin"]
    auth = {"Authorization": "Bearer " + config["Token"]}
    with urlopen(Request(origin + "/.well-known/jmap", headers=auth), context=context, timeout=20) as response:
        session = json.load(response)
    account = config["AccountID"]
    recipient = os.environ["JMAP_RECIPIENT"]

    def call(method, **values):
        request = Request(session["apiUrl"], headers={**auth, "Content-Type": "application/json"}, data=json.dumps({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
            "methodCalls": [[method, {"accountId": account, **values}, "verify"]],
        }).encode())
        with urlopen(request, context=context, timeout=20) as response:
            (name, result, _), = json.load(response)["methodResponses"]
        assert name == method, (method, result.get("type"))
        return result

    changes = call("EmailSubmission/changes", sinceState=saved["state"])
    assert changes["updated"] == [saved["submissionId"]]
    submission, = call("EmailSubmission/get", ids=[saved["submissionId"]])["list"]
    assert submission["deliveryStatus"][recipient]["delivered"] == "yes"
    assert submission["deliveryStatus"][recipient]["displayed"] == "unknown"
    blob, = submission["dsnBlobIds"]
    url = session["downloadUrl"]
    for name, value in (("accountId", account), ("blobId", blob), ("type", "message/rfc822"), ("name", "delivery.eml")):
        url = url.replace("{" + name + "}", quote(value, safe=""))
    with urlopen(Request(url, headers=auth), context=context, timeout=20) as response:
        message = BytesParser(policy=policy.default).parsebytes(response.read())
    assert matching_report(message, saved["reportKey"], recipient)
    repeated = call("EmailSubmission/changes", sinceState=changes["newState"])
    assert repeated["updated"] == [] and repeated["newState"] == changes["newState"]
    print("Verified correlated delivery status, submission delta and exact DSN download")


if __name__ == "__main__":
    main()
