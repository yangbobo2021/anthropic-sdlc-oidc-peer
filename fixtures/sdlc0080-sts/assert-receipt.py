"""Check the unchanged delivery step against the loopback server receipt."""
import json
import os
from pathlib import Path

root = Path(os.environ["RUNNER_TEMP"]) / "sdlc0080"
receipt = json.loads((root / "receipt.json").read_text())
case = os.environ["TEST_CASE"]
assert receipt["case"] == case
assert receipt["request_signed"] is False and receipt["issuer_control_http"] == 200
assert receipt["claims"]["job_workflow_sha"] == os.environ["GITHUB_WORKFLOW_SHA"]
assert receipt["claims"]["ref_protected"] == "true"
if case == "allow":
    assert os.environ["STEP_OUTCOME"] == "success"
    assert receipt["target_login_http"] == 200 and receipt["sts_http"] == 200
    assert receipt["mismatched_target_fields"] == []
    assert receipt["returned_arn"] == "arn:aws:sts::000000000000:assumed-role/sdlc0080-deploy/sdlc-" + os.environ["GITHUB_RUN_ID"]
    assert receipt["target_write_http"] == receipt["target_read_http"] == 200
    assert set(receipt["forbidden"].values()) == {403}
    assert receipt["target_receipt"] == {
        "run": os.environ["GITHUB_RUN_ID"], "commit": os.environ["GITHUB_WORKFLOW_SHA"], "service": "synthetic-service",
    }
else:
    assert os.environ["STEP_OUTCOME"] == "failure"
    assert receipt["target_login_http"] == 400 and receipt["sts_http"] == 403
    assert receipt["returned_arn"] is None and "target_write_http" not in receipt
    assert receipt["mismatched_target_fields"] == (["aud"] if case == "reject-audience" else ["sub"])
assert bool(receipt.get("lease_seconds")) == (case == "allow")
print("SDLC0080_CHAIN=" + json.dumps(receipt, sort_keys=True), flush=True)
