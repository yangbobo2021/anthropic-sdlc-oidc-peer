"""Translate one loopback AWS Query exchange to a real scoped OpenBao JWT role."""

from base64 import urlsafe_b64decode
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs
from urllib.request import Request, urlopen
from xml.etree.ElementTree import Element, SubElement, tostring

ISSUER = "token.actions.githubusercontent.com"
CASE = os.environ["TEST_CASE"]
ARN = os.environ["ROLE_ARN"]
REGION = os.environ["REGION"]
RUN = os.environ["GITHUB_RUN_ID"]
REPOSITORY = os.environ["GITHUB_REPOSITORY"]
ROOT = Path(os.environ["RUNNER_TEMP"]) / "sdlc0080"
TEMPLATE = Path(__file__).with_name("trust.example.json")
NAMESPACE = "https://sts.amazonaws.com/doc/2011-06-15/"


def bao(path, payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    request = Request(
        os.environ["BAO_ADDR"] + "/v1/" + path,
        headers=headers,
        data=json.dumps(payload).encode() if payload is not None else None,
    )
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else {}


def create_role(name, aud, sub, policies):
    role = {
        "role_type": "jwt",
        "user_claim": "sub",
        "bound_audiences": [aud],
        "bound_subject": sub,
        "token_policies": policies,
        "token_ttl": 120,
        "token_explicit_max_ttl": 120,
        "token_no_default_policy": True,
    }
    status, _ = bao("auth/jwt/role/" + name, role, os.environ["BAO_TOKEN"])
    assert status == 204, status


def target_policy():
    example = TEMPLATE.read_bytes()
    statement, = json.loads(example)["Statement"]
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Principal"]["Federated"].endswith(f":oidc-provider/{ISSUER}")
    conditions = statement["Condition"]["StringEquals"]
    aud, sub = conditions[f"{ISSUER}:aud"], conditions[f"{ISSUER}:sub"]
    owner, repository = REPOSITORY.split("/")
    replacements = {
        "EXAMPLE_ORG": owner,
        "OWNER_ID": os.environ["GITHUB_REPOSITORY_OWNER_ID"],
        "EXAMPLE_REPOSITORY": repository,
        "REPOSITORY_ID": os.environ["GITHUB_REPOSITORY_ID"],
    }
    for old, new in replacements.items():
        sub = sub.replace(old, new)
    expected_aud, expected_sub = aud, sub
    changes = {
        "reject-audience": (aud + ".invalid", sub),
        "reject-repository": (aud, sub.replace("@" + replacements["REPOSITORY_ID"] + ":", "@1:", 1)),
        "reject-environment": (aud, sub.replace("environment:production", "environment:staging", 1)),
        "reject-workflow": (aud, sub.replace("/verify-oidc.yml@", "/untrusted-fixture.yml@", 1)),
        "reject-workflow-ref": (aud, sub.replace("@refs/heads/main", "@refs/heads/untrusted-fixture", 1)),
    }
    assert CASE == "allow" or CASE in changes
    target_aud, target_sub = changes.get(CASE, (aud, sub))
    assert (target_aud, target_sub) == (aud, sub) if CASE == "allow" else (target_aud, target_sub) != (aud, sub)
    create_role("identity-control", expected_aud, expected_sub, ["deploy-service"])
    create_role("deployment", target_aud, target_sub, ["deploy-service"])
    return expected_aud, expected_sub, target_aud, target_sub, sha256(example).hexdigest()


def login(role, jwt):
    return bao("auth/jwt/login", {"role": role, "jwt": jwt})


def write_receipt(value):
    (ROOT / "receipt.json").write_text(json.dumps(value, sort_keys=True) + "\n")


class STS(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def reply(self, http, body, content_type):
        self.send_response(http)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(200 if self.path == "/health" else 404, b"", "text/plain")

    def error_response(self, status, code, message):
        root = Element("ErrorResponse", xmlns=NAMESPACE)
        error = SubElement(root, "Error")
        for tag, value in (("Type", "Sender"), ("Code", code), ("Message", message)):
            SubElement(error, tag).text = value
        SubElement(root, "RequestId").text = "sdlc0080-" + RUN
        self.reply(status, tostring(root), "text/xml")

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if self.path != "/" or not 0 < size < 40000 or self.headers.get("Authorization"):
            self.error_response(400, "InvalidRequest", "Unexpected STS request")
            return
        values = parse_qs(self.rfile.read(size).decode(), strict_parsing=True)
        require = {
            "Action": ["AssumeRoleWithWebIdentity"], "Version": ["2011-06-15"],
            "RoleArn": [ARN], "RoleSessionName": ["sdlc-" + RUN],
        }
        if any(values.get(key) != value for key, value in require.items()) or len(values.get("WebIdentityToken", [])) != 1:
            self.error_response(400, "InvalidRequest", "Unexpected STS operation parameters")
            return

        jwt = values["WebIdentityToken"][0]
        expected_aud, expected_sub, target_aud, target_sub, template_sha = POLICY
        control_status, _ = login("identity-control", jwt)
        if control_status != 200:
            write_receipt({"case": CASE, "issuer_control_http": control_status})
            self.error_response(403, "InvalidIdentityToken", "Issuer control did not accept the token")
            return
        encoded = jwt.split(".")[1]
        claims = json.loads(urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        assert claims["aud"] == expected_aud and claims["sub"] == expected_sub
        assert claims["iss"] == "https://" + ISSUER and claims["run_id"] == RUN
        assert claims["repository"] == REPOSITORY and claims["ref"] == "refs/heads/main"
        status, result = login("deployment", jwt)
        receipt = {
            "case": CASE, "method": "AssumeRoleWithWebIdentity", "region": REGION,
            "request_signed": False, "issuer_control_http": control_status, "target_login_http": status,
            "trust_template_sha256": template_sha, "role": ARN, "returned_arn": None,
            "claims": {key: claims[key] for key in (
                "iss", "aud", "sub", "ref", "ref_protected", "repository_id",
                "environment", "job_workflow_ref", "job_workflow_sha", "run_id",
            )},
        }
        receipt["mismatched_target_fields"] = [
            key for key, actual, intended in (("aud", claims["aud"], target_aud), ("sub", claims["sub"], target_sub))
            if actual != intended
        ]
        if status != 200:
            receipt["sts_http"] = 403
            write_receipt(receipt)
            self.error_response(403, "AccessDenied", "Loopback OpenBao rejected the selected target role")
            return

        auth = result["auth"]
        token = auth["client_token"]
        lease = auth["lease_duration"]
        assert 0 < lease <= 120 and auth["token_policies"] == ["deploy-service"]
        approved = "secret/data/sdlc0080/deployment"
        body = {"data": {"run": RUN, "commit": claims["job_workflow_sha"], "service": "synthetic-service"}}
        put, _ = bao(approved, body, token)
        read, value = bao(approved, token=token)
        forbidden = {
            path: bao(f"secret/data/{path}", body, token)[0]
            for path in ("sdlc0080/staging", "unrelated/deployment")
        }
        returned_arn = ARN.replace(":iam:", ":sts:").replace(":role/", ":assumed-role/") + "/sdlc-" + RUN
        receipt.update({
            "sts_http": 200, "returned_arn": returned_arn, "lease_seconds": lease,
            "target_write_http": put, "target_read_http": read, "forbidden": forbidden,
            "target_receipt": value["data"]["data"] if read == 200 else None,
        })
        write_receipt(receipt)
        root = Element("AssumeRoleWithWebIdentityResponse", xmlns=NAMESPACE)
        result_node = SubElement(root, "AssumeRoleWithWebIdentityResult")
        principal = SubElement(result_node, "AssumedRoleUser")
        SubElement(principal, "AssumedRoleId").text = "SYNTHETIC:" + RUN
        SubElement(principal, "Arn").text = returned_arn
        credential = SubElement(result_node, "Credentials")
        SubElement(credential, "AccessKeyId").text = "SYNTHETIC-NOT-AN-AWS-KEY"
        SubElement(credential, "SecretAccessKey").text = "LOOPBACK-FIXTURE"
        SubElement(credential, "SessionToken").text = "LOOPBACK-FIXTURE"
        SubElement(credential, "Expiration").text = (
            datetime.now(timezone.utc) + timedelta(seconds=lease)
        ).isoformat(timespec="seconds")
        SubElement(SubElement(root, "ResponseMetadata"), "RequestId").text = "sdlc0080-" + RUN
        self.reply(200, tostring(root), "text/xml")


if __name__ == "__main__":
    POLICY = target_policy()
    with HTTPServer(("127.0.0.1", 0), STS) as server:
        (ROOT / "broker.port").write_text(str(server.server_port))
        server.serve_forever()
