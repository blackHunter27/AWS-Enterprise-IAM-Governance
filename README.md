# AWS Enterprise IAM & Security Governance Framework

This repository documents the implementation and enforcement of an enterprise-grade Identity and Access Management (IAM) architecture in AWS. The project focuses on the Principle of Least Privilege, Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), global restriction guardrails, and automated compliance auditing using AWS Config and AWS Lambda.

---

## Architecture & Project Overview

The enterprise environment is structured around distinct operational roles (`analyst`, `developer`, `finance`) governed by granular policies, regional boundaries, and continuous automated monitoring.

### Key Components:
1. **Least-Privilege Policies:** Tailored JSON identity-based policies aligned with an enterprise Access Control Matrix.
2. **Global Restrictions:** Boundary policies denying unauthorized cross-region actions outside designated operational areas (`us-east-1`, `us-east-2`, `us-west-1`, `us-west-2`).
3. **ABAC & Tag-Based Controls:** Utilizing condition keys (`s3:ExistingObjectTag/Role`, `s3:RequestObjectTag/Role`, `s3:ExistingObjectTag/Stage`) for precise object-level access boundaries.
4. **Automated Compliance:** Custom Python Lambda functions integrated with AWS Config to continuously evaluate IAM policies for prohibited resources.

---

## Section 1: Permissions and Policies

The IAM policies were audited and updated to remove invalid or overly permissive statements, ensuring strict alignment with the Least Privilege Access Control Matrix.

* **`enterprise-analyst-policy`:** Grants precise S3 read/write permissions scoped via object tags (`Role=analyst`) and access to reporting buckets.
* **`enterprise-developer-policy`:** Combines least-privilege S3 object access with monitoring permissions for EC2 and CloudWatch (`ec2:Describe*`, `cloudwatch:*`, `sns:*`).
* **`enterprise-finance-policy`:** Scoped explicitly to billing, cost management, and pricing descriptors (`ce:*`, `invoicing:*`, `cur:*`).
* **`enterprise-restrictions-policy`:** Implements global guardrails denying actions outside authorized regions using `aws:RequestedRegion` condition keys.

---

## Section 2: IAM Role Configuration & Testing

Each enterprise role has its respective business policy attached alongside the global restriction policy:

* **`enterprise-analyst-role`:** Attached `enterprise-analyst-policy` + `enterprise-restrictions-policy`. Tested via role assumption to verify successful download of obfuscated S3 reports and explicit access denials on non-obfuscated objects.
* **`enterprise-developer-role`:** Attached `enterprise-developer-policy` + `enterprise-restrictions-policy`. Verified access to EC2 security groups, CloudWatch metrics, and developer bucket uploads/downloads.
* **`enterprise-finance-role`:** Attached `enterprise-finance-policy` + `enterprise-restrictions-policy`. Verified access to the Cost Explorer console and billing usage data.

> **Technical Insight (ABAC Limitations on Uploads):** 
> During implementation, evaluating `ExistingObjectTag` vs `RequestObjectTag` highlighted that on `PutObject` operations, S3 only evaluates tags in the request. Existing object tags are not checked for writes. Consequently, an analyst uploading a file that overwrites a developer file can re-tag it. In production environments, this is mitigated using S3 Versioning, Object Lock, or dedicated role prefixes rather than relying solely on tag conditions.

---

## Section 3: AWS Config & Automated Governance

* **Lambda Automation:** Updated Python Lambda code (`config_rule_policy_enforcement.py`) to include restricted resources (`arn:aws:s3:::super-secret-bucket`) in the monitoring scope.
* **Compliance Enforcement:** Manually remediated and evaluated the `ConfigRulePolicyEnforcement` rule in AWS Config to flag non-compliant policies violating enterprise security restrictions.

---

## Section 4: Organizational Role & Policy Visualization

The architecture mapping and permission structures have been fully diagrammed, depicting the relationship between organizational roles, restriction guardrails, resource policies, and underlying AWS services (S3, CloudWatch, EC2).
