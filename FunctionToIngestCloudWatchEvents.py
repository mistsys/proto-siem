import logging
import boto3
import json
import botocore

DOREMEDY = True
#Debug Control, set to True for logs to be oserved in CloudWatch
debug_enabled = False
LOGTABLE = "CloudTrailLogEventData"
# Boolean for Test
TEST = True

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
        print("Error",e)
        return False

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

def verifyLogTable():
    """Verifies if the table name provided is deployed using CloudFormation
       template and thereby have a prefix and suffix in the name.
    Returns:
        The real table name
        TYPE: String
    """
    client = boto3.client('dynamodb')
    resource = boto3.resource('dynamodb')
    table = LOGTABLE

    response = client.list_tables()
    tableFound = False
    for n, _ in enumerate(response['TableNames']):
        if table in response['TableNames'][n]:
            table = response['TableNames'][n]
            tableFound = True

    if not tableFound:
        # Table not created in CFn, let's check exact name or create it
        try:
            result = client.describe_table(TableName=table)
        except:
            # Table does not exist, create it
            newtable = resource.create_table(
                TableName=table,
                KeySchema=[
                    {'AttributeName': 'userName', 'KeyType': 'HASH'},
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'userName', 'AttributeType': 'S'},
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            # Wait for table creation
            newtable.meta.client.get_waiter('table_exists').wait(TableName=table)
    return table

def sendAlert(data):
    """Placeholder for alert functionality.
       This could be Amazon SNS, SMS, Email or adding to a ticket tracking
       system like Jira or Remedy.
    Args:
        data (dict): All extracted event info.
    Returns:
        TYPE: String
    """
    return 0

def logEvent(logData, table):
    """Log all information to the provided DynamoDB table.
    Args:
        logData (dict): All extracted information
        table (string): Table name for event history.
    Returns:
        TYPE: Success
    """
    client = boto3.client('dynamodb')

    #Store data
    response = client.put_item(
        TableName=table,
        Item={
            'userName': {'S': logData['userName']},
            'eventTime': {'S': logData['eventTime']},
            'userArn': {'S': logData['userArn']},
            'region': {'S': logData['region']},
            'account': {'S': logData['account']},
            'userAgent': {'S': logData['userAgent']},
            'sourceIP': {'S': logData['sourceIP']}
        }
    )
    return 0

def forensic(data, table):
    """Perform forensic on the resources and details in the event information.
       Example: Look for MFA, previous violations, corporate CIDR blocks etc.
    Args:
        data (dict): All extracted event info.
        table (string): Table name for event history.
    Returns:
        TYPE: String
    """
    # Set remediationStatus to True to trigger remediation function.
    remediationStatus = False

    if remediationStatus:
        # See if user have tried this before.
        client = boto3.client('dynamodb')
        response = client.get_item(
            TableName=table,
            Key={
                'userName': {'S': data['userName']}
            }
        )
        try:
            if response['Item']:
                # If not first time, trigger countermeasures.
                result = disableAccount(data['userName'])
                return result
        except:
            # First time incident, let it pass.
            return "NoRemediationNeeded"


def disableAccount(userName):
    """Countermeasure function that disables the user by applying an
       inline IAM deny policy on the user.
       policy.
    Args:
        userName (string): Username that caused event.
    Returns:
        TYPE: Success
    """
    client = boto3.client('iam')
    response = client.put_user_policy(
        UserName=userName,
        PolicyName='BlockPolicy',
        PolicyDocument='{"Version":"2012-10-17", "Statement":{"Effect":"Deny", "Action":"*", "Resource":"*"}}'
    )
    return 0

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
    
    #Test:
    
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
    
    #Alerting
    # result = sendAlert(logData)

    #TODO:Temporary to send to ElasticSearch, Required Minimal Calls.
    print(json.dumps(logData))
    
    # Forensics
    realTable = verifyLogTable()
    # result = forensic(logData, realTable)

    # Logging
    result = logEvent(logData, realTable)
    return result
