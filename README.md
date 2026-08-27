# AWS Detection Lab

A reproducible AWS security monitoring lab built with Terraform. It stands up
logging and detection controls, then provides attack-simulation scripts that
trigger the detections so you can see them fire end to end.

Built to run inside the AWS Free Tier plus the GuardDuty 30-day trial. Expected
cost if torn down within a few days: under $2.

## What it builds

| Component | Purpose |
|---|---|
| CloudTrail (multi-region) | Records all management-plane API activity |
| S3 bucket + policy | Stores CloudTrail logs, blocks public access, enforces TLS |
| CloudWatch Log Group | CloudTrail events for real-time metric filters |
| 6 metric filters + alarms | Detections (see table below) |
| SNS topic + email subscription | Alert delivery |
| GuardDuty detector | Managed threat detection |
| Athena + Glue table | Threat-hunting queries over CloudTrail history |
| `attacker` IAM user (low-priv, no console) | Safe principal for attack simulation |

## Detections

Each maps to MITRE ATT&CK. All are CloudWatch metric filters on the CloudTrail
log group unless noted.

| # | Detection | ATT&CK | What triggers it |
|---|---|---|---|
| 1 | Root account used | T1078.004 Valid Accounts: Cloud | Any API call by the root principal |
| 2 | Console login without MFA | T1078.004 | `ConsoleLogin` where `additionalEventData.MFAUsed = No` |
| 3 | CloudTrail disabled or altered | T1562.008 Impair Defenses: Disable Cloud Logs | `StopLogging`, `DeleteTrail`, `UpdateTrail` |
| 4 | IAM policy change | T1098 Account Manipulation | `PutUserPolicy`, `AttachUserPolicy`, `CreatePolicyVersion`, `PutRolePolicy` |
| 5 | Access key created | T1098.001 Additional Cloud Credentials | `CreateAccessKey` |
| 6 | S3 bucket made public | T1567.002 Exfil to Cloud Storage / T1530 Data from Cloud Storage | `PutBucketPolicy`, `PutBucketAcl`, `PutBucketPublicAccessBlock` loosening access |

Athena hunting queries in [`detections/athena-hunts.sql`](detections/athena-hunts.sql)
cover credential enumeration, unusual regions, and failed-then-success auth
patterns that are better suited to retro hunting than real-time alerts.

## Setup

Prereqs: an AWS account you control, AWS CLI configured with admin creds for
setup, Terraform >= 1.5.

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # set your alert email + region
terraform init
terraform apply
```

Confirm the SNS subscription email that arrives. GuardDuty findings and metric
alarms will now route to that address.

## Run the attack simulation

```bash
cd attack-simulation
./00-setup-attacker-creds.sh     # creates an access key for the attacker user
./simulate.sh                    # runs the scenarios below, pausing between each
```

Scenarios in `simulate.sh`:
1. Enumerate the account (`iam list-users`, `list-roles`, `get-account-authorization-details`)
2. Create a second access key for persistence
3. Attach an inline admin policy to the attacker user (privilege escalation)
4. Create a public-read S3 bucket policy
5. Attempt to stop CloudTrail logging

Alarms 3, 4, 5, and 6 should fire within 1 to 5 minutes. GuardDuty findings
(`Recon:IAMUser/*`, `PrivilegeEscalation:IAMUser/*`) appear within 15 minutes to
a few hours depending on the finding type.

## Record what you saw

Fill in [`FINDINGS.md`](FINDINGS.md) as alarms and findings land: timestamp, what
fired, the raw event, how you would triage it in a SOC. That file is the
interview artifact.

## Teardown

```bash
cd terraform
terraform destroy
```

Also disable GuardDuty in the console if you enabled the trial manually.

## Notes on honesty

This repo is a lab you run, not a claim of production experience. The value is in
`FINDINGS.md`: your own triage notes on detections you built and then set off on
purpose. Keep it accurate.
