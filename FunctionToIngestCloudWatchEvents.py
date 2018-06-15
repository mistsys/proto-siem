import logging
import boto3
import json
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DOREMEDY = True
debug_enabled = True

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

# Specify the required ingress permissions using the same key layout as that provided in the
# describe_security_group API response and authorize_security_group_ingress/egress API calls.

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

def priority_notification(event, eventName):
    remedyDone = False
    if eventName in SECURITY_GROUP_CHANGE_APIS:
        if eventName in SECURITY_GROUP_REMEDIATE_APIS:
            remedyDone=remediate_security_group_change(event)
        notification="SECURITY_GROUP_CHANGE"
    elif eventName in NACL_CHANGE_APIS:
        notification="NACL_CHANGE"
    elif eventName in NETWORK_CHANGE_APIS:
        notification="NETWORK_CHANGE"
    elif eventName in CLOUDTRAIL_CHANGE_APIS:
        if eventName in CLOUDTRAIL_REMEDIATE_APIS:
            remedyDone=remediate_cloudtrail_change(event)
        notification="CLOUDTRAIL_CHANGE"
    else:
        notification="DEFAULT"
    return(notification, remedyDone)


def remediate_security_group_change(event):
    group_id = event["detail"]["requestParameters"]["groupId"]
    client = boto3.client("ec2");
    
    try:
        response = client.describe_security_groups(GroupIds=[group_id])
    except botocore.exceptions.ClientError as e:
        logger.error(e)

    ip_permissions = response["SecurityGroups"][0]["IpPermissions"]
    authorize_permissions = [item for item in REQUIRED_PERMISSIONS if item not in ip_permissions]
    revoke_permissions = [item for item in ip_permissions if item not in REQUIRED_PERMISSIONS]

    if authorize_permissions:
        try:
            client.authorize_security_group_ingress(GroupId=group_id, IpPermissions=authorize_permissions)
        except botocore.exceptions.ClientError as e:
            return False
        
    if revoke_permissions:
        try:
            client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke_permissions)
        except botocore.exceptions.ClientError as e:
            return False
    return True
    
    
def remediate_cloudtrail_change(event):
    trailArn = event['detail']['requestParameters']['name']
    client=boto3.client('cloudtrail')
    response=client.get_trail_status(Name=trailArn)
    if response['IsLogging']:
        return False
    else:
        response = client.start_logging(Name=trailArn)
        return True


def lambda_handler(event, context):
    """Summary
    Args:
        event (TYPE): Description
        context (TYPE): Description
    Returns:
        TYPE: Description
    """
    #Debug Control, set to True for logs to be oserved in CloudWatch
    
    #Begin evaluating event
    eventName = event['detail']['eventName']
    
    # test:
    print("test")
    print(event['detail']['requestParameters'])
    
    #priority to check notification type and remediate
    notification_type, remedyDone = priority_notification(event,eventName)
    
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
              'notification':notification_type, 'remedyDone':remedyDone}
    
    #log to cloudwatch
    print(json.dumps(logData))
