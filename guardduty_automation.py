#!/usr/bin/env python3
"""AWS GuardDuty automation demo — enable, inspect, and auto-remediate findings.

Covers the full loop from the README:
  1. Enable GuardDuty + all protection plans (one call, 30-day free trial).
  2. List high-severity findings (>= 7.0) in a readable table.
  3. Auto-remediate a crypto-mining finding: quarantine the EC2 instance
     (isolating security group + EBS snapshot for forensics + tag).
  4. Revoke a compromised IAM access key.
  5. Wire findings to Lambda + SNS via an EventBridge rule.

Usage:
    pip install boto3
    python guardduty_automation.py --demo        # dry-run walkthrough (no changes)
    python guardduty_automation.py --enable      # actually enable GuardDuty
    python guardduty_automation.py --findings    # list high-severity findings

Everything that mutates AWS state is behind an explicit flag. The --demo
mode only prints what *would* happen, so it is safe to run anywhere.
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

gd = boto3.client("guardduty")
ec2 = boto3.client("ec2")
iam = boto3.client("iam")
events = boto3.client("events")


# ---------------------------------------------------------------------------
# 1. Enable GuardDuty + protection plans
# ---------------------------------------------------------------------------

def enable_guardduty(dry_run: bool = True) -> str | None:
    """Create a detector with every protection plan turned on.

    Returns the detector ID. GuardDuty's first 30 days are free, so this is
    the cheapest way to measure real cost before rolling out account-wide.
    """
    if dry_run:
        print("[dry-run] Would create detector with:")
        print("          S3 Protection, EKS Protection, Lambda Protection,")
        print("          RDS Protection, Malware Protection (EC2 + S3), EKS Audit Logs")
        return "dry-run-detector-id"

    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    gd.update_detector(
        DetectorId=detector_id,
        Enable=True,
        DataSources={
            "S3Logs": {"Enable": True},
            "Kubernetes": {"AuditLogs": True},
            "FlowLogs": {"Enable": True},
            "DNSLogs": {"Enable": True},
            "CloudTrail": {"Enable": True},
        },
    )
    print(f"GuardDuty enabled — detector {detector_id}")
    return detector_id


# ---------------------------------------------------------------------------
# 2. List high-severity findings
# ---------------------------------------------------------------------------

SEVERITY_LABELS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (1.0, "LOW"))


def severity_label(score: float) -> str:
    for threshold, label in SEVERITY_LABELS:
        if score >= threshold:
            return label
    return "INFO"


def list_high_findings(detector_id: str, min_severity: float = 7.0) -> list[dict]:
    """Return findings with severity >= min_severity, newest first."""
    finding_ids = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            "Criterion": {"severity": {"Gte": min_severity}},
        },
        SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
        MaxResults=25,
    )["FindingIds"]

    if not finding_ids:
        print(f"No findings with severity >= {min_severity}. Quiet is good.")
        return []

    findings = gd.get_findings(
        DetectorId=detector_id, FindingIds=finding_ids
    )["Findings"]

    print(f"{'SEVERITY':<10} {'TYPE':<58} {'RESOURCE'}")
    print("-" * 110)
    for f in findings:
        resource = (
            f["Resource"].get("InstanceDetails", {}).get("InstanceId")
            or f["Resource"].get("AccessKeyDetails", {}).get("UserName")
            or f["Resource"].get("S3BucketDetails", [{}])[0].get("Name")
            or "—"
        )
        print(f"{severity_label(f['Severity']):<10} {f['Type']:<58} {resource}")
    return findings


# ---------------------------------------------------------------------------
# 3. Remediate a crypto-mining EC2 finding
# ---------------------------------------------------------------------------

def remediate_crypto_mining(instance_id: str, dry_run: bool = True) -> None:
    """Quarantine a compromised instance, preserving evidence first.

    Order matters: snapshot the volumes BEFORE isolating, so forensics keeps
    the disk state; then replace the security groups with an isolating one
    (no ingress, no egress); then tag it so nobody "fixes" it back.
    """
    if dry_run:
        print(f"[dry-run] Would snapshot volumes of {instance_id},")
        print("          attach isolating security group (no ingress/egress),")
        print("          and tag it quarantined=true + finding=crypto-mining.")
        return

    # 1. Snapshot every attached volume (evidence, before anything changes).
    volumes = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]["BlockDeviceMappings"]
    for v in volumes:
        snap = ec2.create_snapshot(
            VolumeId=v["Ebs"]["VolumeId"],
            Description=f"Forensics snapshot — GuardDuty crypto-mining finding on {instance_id}",
        )
        print(f"Snapshot created: {snap['SnapshotId']} (from {v['Ebs']['VolumeId']})")

    # 2. Isolate: swap all security groups for the quarantine group.
    quarantine_sg = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["quarantine-no-traffic"]}]
    )["SecurityGroups"][0]["GroupId"]
    ec2.modify_instance_attribute(
        InstanceId=instance_id, Groups=[quarantine_sg]
    )
    print(f"{instance_id} isolated behind {quarantine_sg} (no ingress, no egress)")

    # 3. Tag so the instance is never silently returned to service.
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "quarantined", "Value": "true"},
            {"Key": "finding", "Value": "crypto-mining"},
        ],
    )
    print(f"{instance_id} tagged quarantined=true")


# ---------------------------------------------------------------------------
# 4. Revoke a compromised IAM access key
# ---------------------------------------------------------------------------

def disable_compromised_key(user_name: str, access_key_id: str, dry_run: bool = True) -> None:
    """Disable (not delete) a leaked key — disabling is instant and reversible.

    Deleting a key you are unsure about can break a legitimate workload;
    disabling stops the attacker immediately and lets you verify first.
    """
    if dry_run:
        print(f"[dry-run] Would disable access key {access_key_id} for {user_name}.")
        return
    iam.update_access_key(
        UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
    )
    print(f"Access key {access_key_id} for {user_name} is now Inactive")


# ---------------------------------------------------------------------------
# 5. Wire findings to Lambda + SNS via EventBridge
# ---------------------------------------------------------------------------

def create_eventbridge_rule(rule_name: str, lambda_arn: str, sns_topic_arn: str,
                           min_severity: float = 7.0, dry_run: bool = True) -> None:
    """Route GuardDuty findings (severity >= min) to Lambda and SNS.

    Event pattern matches GuardDuty findings at or above the threshold;
    Lambda auto-remediates, SNS alerts the security team in parallel.
    """
    pattern = {
        "source": ["aws.guardduty"],
        "detail-type": ["GuardDuty Finding"],
        "detail": {"severity": [{"numeric": [">=", min_severity]}]},
    }
    if dry_run:
        print(f"[dry-run] Would create EventBridge rule '{rule_name}' with pattern:")
        print(json.dumps(pattern, indent=2))
        print(f"          Targets: Lambda {lambda_arn} + SNS {sns_topic_arn}")
        return

    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Description="Route high-severity GuardDuty findings to auto-remediation",
    )
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "remediation-lambda", "Arn": lambda_arn},
            {"Id": "security-sns", "Arn": sns_topic_arn},
        ],
    )
    print(f"EventBridge rule '{rule_name}' created (severity >= {min_severity})")


# ---------------------------------------------------------------------------
# Demo walkthrough
# ---------------------------------------------------------------------------

def demo() -> None:
    """Walk the whole loop in dry-run mode — nothing is changed in AWS."""
    print("== GuardDuty automation demo (dry-run, nothing changes) ==\n")

    print("1. Enable GuardDuty")
    detector_id = enable_guardduty(dry_run=True)

    print("\n2. List high-severity findings")
    example_findings = [
        {"Severity": 8.0, "Type": "CryptoCurrency:EC2/BitcoinTool.B",
         "Resource": {"InstanceDetails": {"InstanceId": "i-0123456789abcdef0"}}},
        {"Severity": 9.5, "Type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
         "Resource": {"AccessKeyDetails": {"UserName": "deploy-bot"}}},
    ]
    print(f"{'SEVERITY':<10} {'TYPE':<58} {'RESOURCE'}")
    print("-" * 110)
    for f in example_findings:
        resource = (
            f["Resource"].get("InstanceDetails", {}).get("InstanceId")
            or f["Resource"].get("AccessKeyDetails", {}).get("UserName")
        )
        print(f"{severity_label(f['Severity']):<10} {f['Type']:<58} {resource}")

    print("\n3. Remediate the crypto-mining instance")
    remediate_crypto_mining("i-0123456789abcdef0", dry_run=True)

    print("\n4. Revoke the leaked IAM key")
    disable_compromised_key("deploy-bot", "AKIAIOSFODNN7EXAMPLE", dry_run=True)

    print("\n5. Wire findings to Lambda + SNS")
    create_eventbridge_rule(
        rule_name="guardduty-high-severity",
        lambda_arn="arn:aws:lambda:us-east-1:123456789012:function:guardduty-remediate",
        sns_topic_arn="arn:aws:sns:us-east-1:123456789012:security-alerts",
        dry_run=True,
    )
    print("\nDemo complete. Re-run with --enable / --findings for live calls.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GuardDuty automation demo")
    parser.add_argument("--demo", action="store_true", help="dry-run walkthrough")
    parser.add_argument("--enable", action="store_true", help="actually enable GuardDuty")
    parser.add_argument("--findings", action="store_true", help="list high-severity findings")
    parser.add_argument("--detector-id", default=None, help="GuardDuty detector ID")
    args = parser.parse_args(argv)

    try:
        if args.demo or (not args.enable and not args.findings):
            demo()
        if args.enable:
            enable_guardduty(dry_run=False)
        if args.findings:
            detector_id = args.detector_id or gd.list_detectors()["DetectorIds"][0]
            list_high_findings(detector_id)
    except ClientError as exc:
        print(f"AWS error: {exc.response['Error']['Message']}", file=sys.stderr)
        return 1
    except IndexError:
        print("No GuardDuty detector found — run with --enable first.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
