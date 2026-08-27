# AWS Detection Lab

I built a cloud detection pipeline in AWS with Terraform, then attacked it with a
script and watched the detections fire. This repo has the infrastructure code,
the attack simulation, the raw evidence from a real run, and my triage notes.

**Full analyst write-up: [FINDINGS.md](FINDINGS.md)**

---

## What this demonstrates

- Writing detections as code: 6 CloudWatch metric-filter rules on CloudTrail, each mapped to a MITRE ATT&CK technique
- Building the supporting pipeline: multi-region CloudTrail, log delivery, SNS alerting, GuardDuty, Athena for threat hunting, all in Terraform
- Adversary emulation: a script that runs credential creation, privilege escalation, defense evasion, and attempted data exposure
- SOC triage: reading the raw CloudTrail events, deciding severity, and writing up next steps
- Detection tuning: finding a false positive, tracing its root cause, and rewriting the rule

---

## Architecture

```
   AWS API activity ──> CloudTrail (multi-region) ──┬──> S3 (log archive, locked down)
                                                    │        └──> Athena + Glue (threat hunting)
                                                    └──> CloudWatch Logs
                                                             └──> 6 metric filters ──> alarms ──> SNS ──> email

   GuardDuty (managed detection) ─────────────────────────────────────────────────────> SNS

   detlab-attacker  (IAM user, no console, scoped perms)  ──used by──>  attack-simulation/
```

---

## The detections

| # | Detection | MITRE ATT&CK | Fires on |
|---|---|---|---|
| 1 | Root account used | T1078.004 | Any API call by the root principal |
| 2 | Console login without MFA | T1078.004 | `ConsoleLogin` with `MFAUsed = No` |
| 3 | CloudTrail disabled or altered | T1562.008 | `StopLogging`, `DeleteTrail`, `UpdateTrail` |
| 4 | IAM policy change | T1098 | `PutUserPolicy`, `AttachUserPolicy`, `CreatePolicyVersion`, `PutRolePolicy` |
| 5 | Access key created | T1098.001 | `CreateAccessKey` |
| 6 | S3 bucket made public | T1530 / T1567.002 | `PutBucketPolicy`, `PutBucketAcl`, `PutBucketPublicAccessBlock` |

Rule definitions as deployed: [`evidence/03-metric-filters.json`](evidence/03-metric-filters.json)

---

## The run — 2026-08-27

### 1. Infrastructure built

Terraform planned 24 resources:

![Terraform plan](<evidence/Screen Shot 2026-08-26 at 10.53.00 PM.png>)

...and applied them:

![Terraform apply complete](<evidence/Screen Shot 2026-08-26 at 11.04.13 PM.png>)

### 2. Attack simulation

Setup: mint an access key for the `detlab-attacker` IAM user (this call alone
fires detection 5):

![Attacker setup](<evidence/Screen Shot 2026-08-26 at 11.06.08 PM.png>)

Then one script executing five techniques in sequence:

![Attack simulation output](<evidence/Screen Shot 2026-08-26 at 11.08.45 PM.png>)

| Scenario | Technique | Result |
|---|---|---|
| 1 | Account enumeration (`ListUsers`, `ListRoles`, `GetAccountAuthorizationDetails`) | Ran; picked up by GuardDuty recon |
| 2 | Persistence — attacker mints a second access key for itself | **Detected** (rule 5) |
| 3 | Privilege escalation — inline `Action:*` policy attached to self | **Detected** (rule 4) |
| 4 | Data exposure — create bucket, make it public | **Detected on attempt** (rule 6); attack **blocked** by account S3 Block Public Access |
| 5 | Defense evasion — `StopLogging` on the trail | **Detected** (rule 3) |

### 3. Detections fired

From the alarm state-change history ([`evidence/01-alarm-history.json`](evidence/01-alarm-history.json)):

| Detection | Fired at (UTC) | Caught |
|---|---|---|
| `access_key_created` | 04:05:16, 04:08:05 | setup key + persistence key |
| `s3_public_access` | 04:08:18 | the `PutBucketPolicy` attempt (logged even though denied) |
| `iam_policy_change` | 04:08:10 | the `Action:*` inline policy |
| `cloudtrail_tampering` | 04:08:27 | `StopLogging` |

The whole attack chain — key, escalate, disable logging — happened in **22
seconds**. Raw events: [`evidence/05-attack-events.json`](evidence/05-attack-events.json)

---

## Three things I took away

1. **Defense in depth beat a permissive IAM policy.** The S3 exposure attack
   failed even though the attacker could call `PutBucketPolicy`, because
   account-level Block Public Access was on. Argument for keeping that guardrail
   everywhere.

2. **A detection can be accurate and still be noise.** The root-usage rule fired
   every few minutes. I traced it to my own console session's background polling
   of `notifications.amazonaws.com`, not an attack. Rewrote the rule to alert
   only on root console logins and mutating actions. Before/after in FINDINGS.md.

3. **GuardDuty caught something I wasn't testing.** A severity 8.0
   `InstanceCredentialExfiltration` finding — EC2 instance-role credentials used
   from another AWS account. Triaged it: instance-profile creds are supposed to
   stay on the instance, so this reads as theft. Full triage in FINDINGS.md.
   Evidence: [`evidence/04-guardduty-findings.json`](evidence/04-guardduty-findings.json)

---

## Reproduce it

Prereqs: an AWS account, AWS CLI configured, Terraform >= 1.5.

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # set alert email + region
terraform init
terraform apply                                 # ~2 min, 24 resources

cd ../attack-simulation
./00-setup-attacker-creds.sh
./simulate.sh                                    # press Enter between scenarios
```

Detections land in CloudWatch Alarms within 1 to 5 minutes (CloudTrail delivery
latency). GuardDuty findings take 15 minutes to a few hours.

### Teardown

```bash
cd terraform
terraform destroy
```

Stays within the AWS Free Tier plus the GuardDuty trial. Under $2 if destroyed
within a few days.

---

## Honesty note

This is a lab I built and ran, not production experience. What it shows is that I
can write detections as code, emulate an adversary against them, and do the
triage. The analysis in FINDINGS.md is real, from the run above.
