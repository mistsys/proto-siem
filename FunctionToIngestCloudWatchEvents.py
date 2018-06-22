'''
FunctionToIngestCloudWatchEvent

Lambda Function that gets triggered on the event of a rule configured
in CloudWatch being invoked.

Citations:
[1]:https://github.com/awslabs/aws-security-automation
[2]:
[3]:
[4]:
'''
import logging
import boto3
import json
import botocore

DOREMEDY = True
#Debug Control, set to True for logs to be oserved in CloudWatch
debug_enabled = False


#Remedy Status Constants, Fail when Remedy Function fails, Error when encounter an error
SUCCESS="Success"
FAIL="Fail"
ERROR="Error"

# Security Group API Calls to Log
SECURITY_GROUP_CHANGE_APIS = ["AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress",
"RevokeSecurityGroupIngress","RevokeSecurityGroupEgress","CreateSecurityGroup","DeleteSecurityGroup"]
SECURITY_GROUP_REMEDIATE_APIS = ["AuthorizeSecurityGroupIngress","DeleteSecurityGroup"]

# NACL Change API Calls to Log
NACL_CHANGE_APIS = ["CreateNetworkAcl","CreateNetworkAclEntry","DeleteNetworkAcl","DeleteNetworkAclEntry",
"ReplaceNetworkAclEntry","ReplaceNetworkAclAssociation"]

# Network Change API Calls to Log
NETWORK_CHANGE_APIS = ["AttachInternetGateway","AssociateRouteTable","CreateCustomerGateway",
"CreateInternetGateway","CreateRoute","CreateRouteTable","DeleteCustomerGateway","DeleteInternetGateway",
"DeleteRoute","DeleteRouteTable","DeleteDhcpOptions","DetachInternetGateway","DisassociateRouteTable",
"ReplaceRoute","ReplaceRouteTableAssociation"]

# Cloudtrail Change API Calls to Log
CLOUDTRAIL_CHANGE_APIS = ["StopLogging","DeleteTrail","UpdateTrail"]
CLOUDTRAIL_REMEDIATE_APIS = ["StopLogging","DeleteTrail"]

# Config Change API Calls to Log
AWS_CONFIG_CHANGE_APIS = ["PutConfigurationRecorder","StopConfigurationRecorder","StopConfigurationRecorder",
                      "PutDeliveryChannel"]

# S3 Bucket Policy Change API Calls to Log
S3BUCKET_POLICY_CHANGE_APIS = ["PutBucketAcl","PutBucketPolicy","PutBucketCors",
                      "PutBucketLifecycle","PutBucketReplication","DeleteBucketPolicy",
                              "DeleteBucketCors","DeleteBucketLifecycle","DeleteBucketReplication"]
# Sample Required Permissions
# TODO: Ingest Permisssions from a template
REQUIRED_PERMISSIONS = [
{
    "IpProtocol" : "tcp",
    "FromPort" : 80,
    "ToPort" : 80,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "73.92.124.103/32"}],
    "PrefixListIds" : [],
    "Ipv6Ranges": []
},
{
    "IpProtocol" : "tcp",
    "FromPort" : 443,
    "ToPort" : 443,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "73.92.124.103/32"}],
    "PrefixListIds" : [],
    "Ipv6Ranges": []
},
{
    "IpProtocol" : "tcp",
    "FromPort" : 22,
    "ToPort" : 22,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "73.92.124.103/32"}],
    "PrefixListIds" : [],
    "Ipv6Ranges": []
}]

def eventClassification(event,eventName):
    """Classifies Event into defined API's and
    calls remediate functions before returning.
    Args:
        event, eventName 
    Returns:
        classification, remedyStatus
    """
    remedyStatus = FAIL
    if eventName in SECURITY_GROUP_CHANGE_APIS:
        if eventName in SECURITY_GROUP_REMEDIATE_APIS and DOREMEDY:
            remedyStatus=remediateSecurityGroupChange(event)
        classification="SECURITY_GROUP_CHANGE"
    elif eventName in NACL_CHANGE_APIS:
        classification="NACL_CHANGE"
    elif eventName in NETWORK_CHANGE_APIS:
        classification="NETWORK_CHANGE"
    elif eventName in CLOUDTRAIL_CHANGE_APIS:
        if eventName in CLOUDTRAIL_REMEDIATE_APIS and DOREMEDY:
            remedyStatus=remediateCloudtrailChange(event)
        classification="CLOUDTRAIL_CHANGE"
    elif eventName in AWS_CONFIG_CHANGE_APIS:
        classification="AWS_CONFIG_CHANGE"
    elif eventName in S3BUCKET_POLICY_CHANGE_APIS:
        classification="S3BUCKET_POLICY_CHANGE_CHANGE"
    else:
        classification="DEFAULT"
    return(classification, remedyStatus)


def remediateSecurityGroupChange(event):
    """Remediates Security Group Change and return remedyStatus
    Args:
        event (TYPE): Event from lambda_handler
    Returns:
        remedyStatus
        TYPE: String
    """
    group_id = event["detail"]["requestParameters"]["groupId"]
    client = boto3.client("ec2");
    
    try:
        response = client.describe_security_groups(GroupIds=[group_id])
    except botocore.exceptions.ClientError as e:
        print("Error",e)
        return ERROR

    ip_permissions = response["SecurityGroups"][0]["IpPermissions"]
    authorize_permissions = [item for item in REQUIRED_PERMISSIONS if item not in ip_permissions]
    revoke_permissions = [item for item in ip_permissions if item not in REQUIRED_PERMISSIONS]

    if authorize_permissions:
        try:
            responseAuthorize = client.authorize_security_group_ingress(GroupId=group_id, IpPermissions=authorize_permissions)
           
        except botocore.exceptions.ClientError as e:
            print("Error",e)
            return ERROR
        
    if revoke_permissions:
        try:
            responseRevoke = client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke_permissions)
        except botocore.exceptions.ClientError as e:
            print("Error",e)
            return ERROR
        
    if (responseAuthorize['ResponseMetadata']['HTTPStatusCode']!=200 or responseRevoke['ResponseMetadata']['HTTPStatusCode']!=200):
                return FAIL
        
    return SUCCESS
    
    
def remediateCloudtrailChange(event):
    """Remediates Cloudtrail Change and return remedyStatus
    Args:
        event (TYPE): Event from lambda_handler
    Returns:
        remedyStatus
        TYPE: String
    """
    trailArn = event['detail']['requestParameters']['name']
    client=boto3.client('cloudtrail')
    response=client.get_trail_status(Name=trailArn)
    #Check if trail was started after delete
    if response['IsLogging']:
        return SUCCESS 
    else:
        try:
            response = client.start_logging(Name=trailArn)
            if (response['ResponseMetadata']['HTTPStatusCode']!=200):
                return FAIL
        except:
            return ERROR
    return SUCCESS



def lambda_handler(event, context):
    """Summary
    Args:
        event (TYPE): Description
        context (TYPE): Description
    Returns:
        TYPE: Description
    """
    #Begin evaluating event
    eventName = event['detail']['eventName']
    
    #priority to check notification type and remediate
    classification, remedyStatus = eventClassification(event,eventName)
    
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
              'notification':classification, 'remedyStatus':remedyStatus,
              'eventName':eventName}

    #TODO:Temporary to send to ElasticSearch, Required Minimal Calls.
    print(json.dumps(logData))
    
    return True
