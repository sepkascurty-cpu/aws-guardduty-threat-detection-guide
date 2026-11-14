# Quiz: AWS GuardDuty Threat Detection 🛡️

Test what you learned from the [README](README.md). Answers are hidden — click to reveal.

---

## 1. What does GuardDuty analyse to find threats?

A. The full contents (payloads) of your network traffic, via agents you install on every EC2 instance
B. AWS-native log metadata — VPC Flow Logs, CloudTrail, DNS logs, S3 and EKS logs — with no agents to install
C. Only CloudTrail events, once a day, in a batch report
D. Your application logs, which you must stream to GuardDuty yourself

<details>
<summary>Answer</summary>

**B.** GuardDuty reads **metadata** from AWS-native logs (who talked to whom, when, how much) — never traffic payloads — and needs no agents, sensors or log forwarding from you. Enable it and it starts analysing within minutes.

</details>

---

## 2. You see the finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` with severity 9.5. What happened?

A. Someone ran a port scan against your EC2 instance
B. EC2 role credentials were used from an IP address outside AWS — the keys were likely stolen
C. An S3 bucket was made public by mistake
D. A Lambda function timed out and retried too many times

<details>
<summary>Answer</summary>

**B.** This finding means credentials issued to an EC2 instance (its IAM role) were used from an **external IP**. That is the classic signature of stolen instance credentials. Severity 9.5 is Critical — disable the key and isolate the instance immediately.

</details>

---

## 3. A GuardDuty finding has severity 8.2. Which band is it in, and what should you do?

A. Low — review it in the weekly cleanup
B. Medium — triage it sometime today
C. High — investigate within the hour, and auto-remediate if the pattern is known
D. Critical — page the on-call and shut down the whole VPC

<details>
<summary>Answer</summary>

**C.** 8.2 is **High** (7.0–8.9). High findings deserve investigation within the hour; if the pattern is a known one (e.g. crypto-mining), auto-remediation is appropriate. Critical starts at 9.0 — that is the page-the-on-call level.

</details>

---

## 4. What is the difference between GuardDuty and Security Hub?

A. There is none — they are two names for the same service
B. GuardDuty detects threats in progress; Security Hub centralises findings from GuardDuty, Inspector, Config and Macie into one dashboard
C. GuardDuty scans for vulnerabilities; Security Hub detects threats
D. Security Hub is the free version of GuardDuty

<details>
<summary>Answer</summary>

**B.** **GuardDuty** is the detector — it catches bad things happening right now. **Security Hub** is the alarm panel — it aggregates findings from GuardDuty and other services so the security team has one place to look. (Inspector is the one that scans for vulnerabilities before they are exploited.)

</details>

---

## 5. Your auto-remediation Lambda quarantines an EC2 instance flagged for crypto-mining. What is the FIRST step it should take, and why?

A. Attach the isolating security group first — stop the mining immediately, evidence doesn't matter
B. Snapshot the EBS volumes first, so forensics keeps the disk state before anything changes
C. Terminate the instance immediately — a compromised host can't be trusted
D. Reboot the instance — the miner is probably just a runaway process

<details>
<summary>Answer</summary>

**B.** **Snapshot first, isolate second.** If you isolate or terminate first, you may lose the disk state you need to understand how the attacker got in. Snapshot the volumes, then attach the quarantine security group (no ingress, no egress), then tag the instance so nobody returns it to service by accident.

</details>

---

**Score yourself:** 5/5 — you're ready to run GuardDuty in production. 3–4 — re-read the severity bands and the finding-types table. 0–2 — start again at the top of the README, it's worth it. 🛡️
