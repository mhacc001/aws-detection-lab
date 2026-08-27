# Findings Log

Lab run: 2026-08-27, ~04:05 to 04:09 UTC. AWS account 085568227004, region
us-east-1. Attacker principal: IAM user `detlab-attacker`. Analyst credentials:
IAM user `marie-cli`.

All five simulated techniques were run. Four produced detections. One was blocked
by an account guardrail before it could succeed, which is itself a finding. One
detection produced a repeating false positive that I traced and would tune.

---

## Summary table

| # | Detection | Fired | ATT&CK | Outcome |
|---|---|---|---|---|
| 5 | Access key created | Yes, x2 | T1098.001 | True positive |
| 4 | IAM policy change | Yes | T1098 | True positive |
| 3 | CloudTrail tampering | Yes | T1562.008 | True positive |
| 6 | S3 public access | Yes | T1530 / T1567.002 | True positive on the attempt; attack itself blocked by S3 Block Public Access |
| 1 | Root account used | Yes, repeating | T1078.004 | False positive: console background polling |
| 2 | Console login no MFA | No | T1078.004 | Not exercised (no console login in the sim) |

---

## Detection 5 — Access key created (x2)

**Alarm:** `detlab-access_key_created`, ALARM at 04:05:16 and 04:08:05 UTC.

**Events:**

1. `CreateAccessKey` by `arn:aws:iam::085568227004:user/marie-cli` at 04:05:16,
   target user `detlab-attacker`, new key `AKIARH3CDQ26KBS7WMMG`, from
   99.88.49.167, `aws-cli/1.46.0`. This is the lab setup step.
2. `CreateAccessKey` by `arn:aws:iam::085568227004:user/detlab-attacker` at
   04:08:05, target user `detlab-attacker` (itself), from 99.88.49.167. This is
   the persistence step: the attacker minting a second key for itself.

**Triage:**
- Event 2 is the interesting one. A principal creating an additional access key
  for itself is a classic persistence move (T1098.001). One user with two active
  keys should be rare in a real environment.
- What I would check next: `aws iam list-access-keys --user-name detlab-attacker`
  for total active keys, and `GetAccessKeyLastUsed` on each. Then pivot on the
  new key ID in CloudTrail to see everything it did after creation.
- Severity call: high if the principal is not a service/CI account. This is how
  an attacker keeps access after the original credential is rotated.

**Verdict:** true positive, would escalate.

---

## Detection 4 — IAM policy change

**Alarm:** `detlab-iam_policy_change`, ALARM at 04:08:10 UTC.

**Event:** `PutUserPolicy` by `user/detlab-attacker` on itself, policy name
`escalate`, policy document:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
```

**Triage:**
- A principal attaching an inline `Action:*, Resource:*` policy to itself is
  privilege escalation, full stop. There is no benign reason for a user to grant
  itself admin inline.
- The fact that it is an *inline* policy (not a managed policy attach) is worth
  noting, inline policies are easier to miss in an access review because they do
  not show up in the managed-policy list.
- Next steps: immediately detach the policy, disable the user's access keys,
  pull the full CloudTrail history for this principal to scope what it touched
  while it had admin.

**Verdict:** true positive, contain now.

---

## Detection 3 — CloudTrail tampering

**Alarm:** `detlab-cloudtrail_tampering`, ALARM at 04:08:27 UTC.

**Event:** `StopLogging` by `user/detlab-attacker` on trail `detlab-trail`.

**Triage:**
- Disabling logging is a defense-evasion move (T1562.008). It usually comes
  right before something the attacker does not want recorded.
- Timing here is the story: the attacker created a key (04:08:05), escalated
  (04:08:10), then killed logging (04:08:27). Under 30 seconds. That sequence is
  the incident.
- This detection has a weakness: if the attacker had also deleted the CloudWatch
  Logs delivery or the metric filter, the alert might not have made it out. Real
  defense would put a copy of CloudTrail in a separate logging account the
  workload principals cannot touch.
- Next steps: re-enable logging (done in the lab), confirm no gap in the S3 log
  archive, treat everything after 04:08 as low-confidence until the archive is
  verified.

**Verdict:** true positive, high priority.

---

## Detection 6 — S3 public access (attempt detected, attack blocked)

**Alarm:** `detlab-s3_public_access`, ALARM at 04:08:18 UTC.

**Events:**
- `CreateBucket` `detlab-exfil-1401910064` by `user/detlab-attacker` at 04:08:16, succeeded.
- `PutBucketPublicAccessBlock` at 04:08:17, **AccessDenied**.
- `PutBucketPolicy` with `Principal:*` at 04:08:18, **AccessDenied** — "public
  policies are prevented by the BlockPublicPolicy setting in S3 Block Public
  Access."

**Triage:**
- The detection fired on the *attempt*, which is correct. Metric filters match on
  `eventName` regardless of the result, so a denied action still alerts. That is
  the behavior you want here — a failed attempt to expose a bucket is still worth
  a look.
- The attack failed for two independent reasons (defense in depth):
  1. Account-level **S3 Block Public Access** is enabled, so even a permissive
     bucket policy would be ignored.
  2. The attacker's IAM policy did not include `s3:PutBucketPublicAccessBlock`,
     so it could not turn the guardrail off first.
- Takeaway: permissive IAM alone did not lead to data exposure because the
  account guardrail held. This is the argument for keeping account-level BPA on
  everywhere, permanently.
- Next steps: check whether the attacker put any objects in the bucket before
  trying to open it, and delete the bucket.

**Verdict:** true positive on the attempt, no exposure occurred.

---

## Detection 1 — Root account used (FALSE POSITIVE, traced)

**Alarm:** `detlab-root_account_used`, repeated ALARM roughly every 5 minutes
starting 04:04 UTC, which we never triggered on purpose.

**Investigation:** filtered the log group for `userIdentity.type = "Root"`. Every
hit was:

```
ListManagedNotificationEvents | notifications.amazonaws.com | invokedBy: none | sourceIP: 99.88.49.167
```

**Root cause:** an AWS Console session signed in as the **root user** (my own
browser, doing IAM and billing setup). The console polls the notifications
service every few minutes and those calls are attributed to Root. GuardDuty
independently flagged the same thing: `Policy:IAMUser/RootCredentialUsage`, count
3613 since 2026-08-15.

**Two findings:**
1. **Detection needs tuning.** As written, the rule alerts on any root API call,
   including read-only console background noise. Better rule: alert on root
   `ConsoleLogin` events and root mutating actions, and exclude read-only calls
   to `notifications.amazonaws.com` and `health.amazonaws.com`. Draft:
   ```
   { $.userIdentity.type = "Root"
     && $.eventType != "AwsServiceEvent"
     && $.eventSource != "notifications.amazonaws.com"
     && $.eventSource != "health.amazonaws.com"
     && ($.eventName = "ConsoleLogin" || $.readOnly IS FALSE) }
   ```
2. **Operational fix.** Root is being used for routine console work. It should
   not be. Set up an IAM admin user (or Identity Center), enable MFA on root,
   lock root away for break-glass only.

**Verdict:** false positive as configured, but it points at a real hygiene
problem. Good example of a detection that is technically accurate and still
needs work before it belongs in a queue.

---

## GuardDuty findings

The detector is shared with earlier work in this account (the NextWork GuardDuty
project, resources prefixed `nextwork-` / `NextWork-`, first seen 2026-08-15).

| Type | Severity | Title | Notes |
|---|---|---|---|
| `Policy:IAMUser/RootCredentialUsage` | 2.0 low | Root used for ListManagedNotificationEvents | Same root-console issue as Detection 1. Count 3613. |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | 2.0 low | Trail `management-events` disabled 2026-08-16 | From the earlier project. Tonight's `StopLogging` on `detlab-trail` should generate a fresh one of these. |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` | 8.0 high | EC2 role `NextWork-GuardDuty-project-...-TheRole` credentials used from a remote AWS account | From the NextWork project where instance-role creds were deliberately exfiltrated. GuardDuty correctly rates this high: instance-role credentials being used outside the instance is a strong compromise signal. |

**Triage note on the high-severity one:** in a real environment this is a
drop-everything finding. Instance-profile credentials are supposed to stay on the
instance. Used from another account means they were stolen (SSRF, metadata
service, exposed in code). Response: revoke the role's active sessions
(`aws iam ...` put a deny-all boundary or rotate), snapshot the instance for
forensics, hunt for what the stolen creds did in CloudTrail.

---

## What I would add next

- CloudTrail **data events** for S3 (object-level GetObject/PutObject) so
  exfiltration from a bucket is visible, not just policy changes.
- VPC Flow Logs and DNS logs for network-layer detection.
- Ship CloudTrail to a separate logging account so `StopLogging` cannot blind the
  whole pipeline.
- A detection for `CreateAccessKey` followed by use of that key within N minutes
  (the Athena query in `detections/athena-hunts.sql` #5 does this retroactively).
- Tune Detection 1 per the draft above and re-test.

## Cleanup done after this run

- [ ] `terraform destroy` on the lab
- [ ] deleted bucket `detlab-exfil-1401910064`
- [ ] rotated/deleted the `marie-cli` access key that was exposed
- [ ] reviewed and tore down the leftover NextWork project resources (EC2, role, CFN stack)
- [ ] logged out of root, created an IAM admin user, enabled MFA on root
