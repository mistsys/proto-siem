import logging
import boto3
import json
import botocore
import jmespath

DOREMEDY = False
#Debug Control, set to True for logs to be oserved in CloudWatch
debug_enabled = False


POLICY_EVENTS_TO_CHECK = ["CreatePolicy"]

def evaluatePolicy(event, eventName):
    if eventName in POLICY_EVENTS_TO_CHECK:
        
        client = boto3.client('iam')
        policy_arn = event['detail']['responseElements']['policy']['arn']
        
        try:
            # Get the policy details.
            policy = client.get_policy(PolicyArn = policy_arn)['Policy']
            # Get the latest policy version.
            policy_version = client.get_policy_version(
                PolicyArn = policy['Arn'],
                VersionId = policy['DefaultVersionId']
            )
        except:
            return False
        
        if jmespath.search('PolicyVersion.Document.Statement[?Effect == \'Allow\' && contains(Resource, \'*\') && contains (Action, \'*\')]', policy_version):
            return True
        
    return False

def lambda_handler(event, context):
    """Summary
    Args:
        event (TYPE): Description
        context (TYPE): Description
    Returns:
        TYPE: Description
    """
    # print("CloudTrail Event",json.dumps(event))
    
    #Begin evaluating event
    eventName = event['detail']['eventName']
    
    #priority to check notification type and remediate
    classification = "IAM_EVENT"
    policyAlert = evaluatePolicy(event, eventName)

    
    #Extract user info from the event
    try:
        userName = event['detail']['userIdentity']['userName']
    except KeyError:
        # User is federated/assumeRole
        userName = event['detail']['userIdentity']['sessionContext']['sessionIssuer']['userName']
    
    userArn = event['detail']['userIdentity']['arn']
    accessKeyId = event['detail']['userIdentity']['accessKeyId']
    region = event['region']
    account = event['account']
    eventTime = event['detail']['eventTime']
    userAgent = event['detail']['userAgent']
    sourceIP = event['detail']['sourceIPAddress']
    eventSource = event['detail']['eventSource']
    
    logData = {'userName': userName, 'userArn': userArn, 'accessKeyId': accessKeyId, 
               'region': region, 'account': account, 'eventTime': eventTime, 
               'userAgent': userAgent, 'sourceIP': sourceIP, "eventSource":eventSource,
              'notification':classification, 'policyAlert':policyAlert,
              'eventName':eventName}

    #TODO:Temporary to send to ElasticSearch, Required Minimal Calls.
    print(json.dumps(logData))
    
    return True
