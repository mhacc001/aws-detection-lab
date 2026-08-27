# Findings Log

Fill this in as you run the simulation. This is the file interviewers care about.
For each detection: when it fired, the raw evidence, and how you would triage it
on a SOC shift.

---

## Detection 3 — CloudTrail tampering

- **Fired at:** <timestamp>
- **Alarm:** detlab-cloudtrail_tampering
- **Trigger event:** `StopLogging` on trail `detlab-trail`
- **Raw event (trimmed):**
  ```json
  <paste the CloudTrail record from CloudWatch Logs Insights>
  ```
- **Triage notes:**
  - Who: `<principal arn>` from `<source ip>`
  - Is this expected? (change ticket? known admin?)
  - Severity call and why:
  - Next step: <isolate key / contact owner / escalate to IR>

---

## Detection 4 — IAM policy change

- **Fired at:**
- **Trigger event:** `PutUserPolicy` attaching `"Action":"*"` to `detlab-attacker`
- **Raw event:**
- **Triage notes:** why an inline `*:*` policy on a user is a privilege-escalation red flag

---

## Detection 5 — Access key created

- **Fired at:**
- **Trigger event:** `CreateAccessKey`
- **Triage notes:** second active key on one user = common persistence technique. What would you check next? (key last-used, CloudTrail for that key)

---

## Detection 6 — S3 made public

- **Fired at:**
- **Trigger event:** `PutBucketPolicy` with `"Principal":"*"`
- **Triage notes:** data-exposure risk, how you would confirm whether objects are actually reachable

---

## GuardDuty findings observed

| Finding type | Severity | First seen | Notes |
|---|---|---|---|
| Recon:IAMUser/... | | | |
| PrivilegeEscalation:IAMUser/... | | | |

---

## What I would tune

- False positives I would expect in a real environment:
- Which of these belong as real-time alerts vs scheduled hunts:
- What I would add next (CloudTrail data events for S3, VPC flow logs, etc.):
