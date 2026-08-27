-- Threat-hunting queries over CloudTrail history.
-- Prereq: create an Athena table over your CloudTrail S3 path. Template:
--
-- CREATE EXTERNAL TABLE cloudtrail_logs (
--   eventVersion STRING, userIdentity STRUCT<type:STRING,principalId:STRING,arn:STRING,
--     accountId:STRING,userName:STRING,sessionContext:STRUCT<attributes:STRUCT<mfaAuthenticated:STRING,creationDate:STRING>>>,
--   eventTime STRING, eventSource STRING, eventName STRING, awsRegion STRING,
--   sourceIPAddress STRING, userAgent STRING, errorCode STRING, errorMessage STRING,
--   requestParameters STRING, responseElements STRING
-- )
-- ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
-- LOCATION 's3://detlab-cloudtrail-<ACCOUNT_ID>/AWSLogs/<ACCOUNT_ID>/CloudTrail/';

-- 1. Credential / permission enumeration bursts (T1087, T1069)
SELECT userIdentity.arn, sourceIPAddress, COUNT(*) AS calls,
       array_agg(DISTINCT eventName) AS actions
FROM cloudtrail_logs
WHERE eventName IN ('ListUsers','ListRoles','ListPolicies','GetAccountAuthorizationDetails',
                    'ListAccessKeys','ListAttachedUserPolicies','GetPolicyVersion','ListGroupsForUser')
  AND from_iso8601_timestamp(eventTime) > current_timestamp - interval '1' day
GROUP BY userIdentity.arn, sourceIPAddress
HAVING COUNT(*) >= 5
ORDER BY calls DESC;

-- 2. Access denied storms - probing for what a principal can do (T1078)
SELECT userIdentity.arn, sourceIPAddress, COUNT(*) AS denied
FROM cloudtrail_logs
WHERE errorCode IN ('AccessDenied','UnauthorizedOperation','Client.UnauthorizedOperation')
  AND from_iso8601_timestamp(eventTime) > current_timestamp - interval '1' day
GROUP BY userIdentity.arn, sourceIPAddress
HAVING COUNT(*) >= 10
ORDER BY denied DESC;

-- 3. Activity in regions you do not normally use (T1535)
SELECT awsRegion, eventSource, eventName, userIdentity.arn, COUNT(*) AS n
FROM cloudtrail_logs
WHERE awsRegion NOT IN ('us-east-1')          -- set to your normal regions
  AND eventSource != 'health.amazonaws.com'
  AND from_iso8601_timestamp(eventTime) > current_timestamp - interval '2' day
GROUP BY awsRegion, eventSource, eventName, userIdentity.arn
ORDER BY n DESC;

-- 4. Console logins without MFA (T1078.004)
SELECT eventTime, userIdentity.arn, sourceIPAddress,
       json_extract_scalar(responseElements, '$.ConsoleLogin') AS result
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND json_extract_scalar(requestParameters, '$') IS NULL
  AND userIdentity.sessionContext.attributes.mfaAuthenticated = 'false'
ORDER BY eventTime DESC;

-- 5. New principals or keys created, then used within the hour (T1098)
WITH created AS (
  SELECT eventTime, json_extract_scalar(responseElements,'$.accessKey.accessKeyId') AS new_key
  FROM cloudtrail_logs WHERE eventName = 'CreateAccessKey'
)
SELECT c.eventTime AS key_created, c.new_key, MIN(l.eventTime) AS first_used
FROM created c
JOIN cloudtrail_logs l
  ON l.userIdentity.accessKeyId = c.new_key
 AND from_iso8601_timestamp(l.eventTime) BETWEEN from_iso8601_timestamp(c.eventTime)
     AND from_iso8601_timestamp(c.eventTime) + interval '1' hour
GROUP BY c.eventTime, c.new_key;
