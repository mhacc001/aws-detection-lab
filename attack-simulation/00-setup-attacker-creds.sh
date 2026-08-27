#!/usr/bin/env bash
# Creates an access key for the lab attacker user and writes a named CLI profile.
# Run with your admin credentials active.
set -euo pipefail

ATTACKER_USER="${ATTACKER_USER:-detlab-attacker}"
PROFILE="${PROFILE:-detlab-attacker}"

echo "[*] Creating access key for $ATTACKER_USER ..."
CREDS=$(aws iam create-access-key --user-name "$ATTACKER_USER" --output json)

AK=$(echo "$CREDS" | python3 -c 'import sys,json;print(json.load(sys.stdin)["AccessKey"]["AccessKeyId"])')
SK=$(echo "$CREDS" | python3 -c 'import sys,json;print(json.load(sys.stdin)["AccessKey"]["SecretAccessKey"])')

aws configure set aws_access_key_id "$AK" --profile "$PROFILE"
aws configure set aws_secret_access_key "$SK" --profile "$PROFILE"
aws configure set region "${AWS_REGION:-us-east-1}" --profile "$PROFILE"

echo "[+] Profile '$PROFILE' ready. Note: this CreateAccessKey call itself fires detection #5."
echo "[+] Wait ~30s for IAM propagation before running simulate.sh"
