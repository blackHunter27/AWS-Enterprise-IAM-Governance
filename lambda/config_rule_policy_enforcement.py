import os
import json
import boto3
import datetime
from urllib.parse import unquote

RESTRICTED_RESOURCES = []
ALERTING_ENABLED = False

def handler(event, context):
    print(event)
    invoking_event = json.loads(event["invokingEvent"])
    resource_type = invoking_event["configurationItem"]["resourceType"]
    resource_id = invoking_event["configurationItem"]["resourceId"]
    resource_arn = invoking_event["configurationItem"]["ARN"]
    result_token = event["resultToken"]
    
    compliance_type = 'COMPLIANT'
    annotation = 'The policy has no restricted resources listed.'
    restricted_resources_enabled = []

    if resource_type == "AWS::IAM::Policy":
        configuration = invoking_event.get("configurationItem", {}).get("configuration")
        if configuration:
            policy_version_list = configuration.get("policyVersionList", [])
            default_version = next((v for v in policy_version_list if v.get("isDefaultVersion", False)), None)
            if default_version:
                policy = json.loads(unquote(default_version["document"]))
                statements = policy.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for statement in statements:
                    if any(resource in RESTRICTED_RESOURCES for resource in statement.get("Resource", [])):
                        compliance_type = 'NON_COMPLIANT'
                        annotation = 'The policy has a restricted resource listed.'
                        restricted_resources_enabled.append(resource_arn)
                        break

    client = boto3.client("config")
    client.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': resource_type,
                'ComplianceResourceId': resource_id,
                'ComplianceType': compliance_type,
                'Annotation': annotation,
                'OrderingTimestamp': datetime.datetime.now()
            },
        ],
        ResultToken=result_token
    )

    if ALERTING_ENABLED and restricted_resources_enabled:
        print("ALERTING SNS")
        sns_client = boto3.client("sns")
        sns_client.publish(
            TopicArn=os.environ["SNS_TOPIC"],
            Message=f'The following policies have restricted resources enabled {restricted_resources_enabled}'
        )
    
    return {"status": "Successfully evaluated"}