# Architecture

```
                        ┌─────────────────────────────┐
   AWS API activity ───>│  CloudTrail (multi-region)   │
                        └──────────────┬──────────────┘
                                       │ delivers to
                        ┌──────────────▼──────────────┐   ┌────────────────────┐
                        │  S3 bucket (log archive)    │   │  CloudWatch Logs   │
                        │  - public access blocked    │   │  /aws/cloudtrail/  │
                        │  - TLS enforced             │   │  detlab            │
                        │  - log file validation on   │   └─────────┬──────────┘
                        └──────────────┬──────────────┘             │
                                       │ queried by                 │ 6 metric filters
                        ┌──────────────▼──────────────┐   ┌─────────▼──────────┐
                        │  Athena + Glue (hunting)    │   │  CloudWatch Alarms │
                        └─────────────────────────────┘   └─────────┬──────────┘
                                                                    │ on breach
   ┌──────────────────┐   findings                        ┌─────────▼──────────┐
   │    GuardDuty     │──────────────────────────────────>│   SNS topic        │
   │  (managed detn)  │                                   │   -> email alert   │
   └──────────────────┘                                   └────────────────────┘

   ┌──────────────────────────────┐
   │  detlab-attacker IAM user    │  used by attack-simulation/ to exercise
   │  (no console, scoped perms)  │  every detection above
   └──────────────────────────────┘
```

Replace this with a real diagram (draw.io, Excalidraw) once the lab is running
and add a screenshot of a fired alarm.
