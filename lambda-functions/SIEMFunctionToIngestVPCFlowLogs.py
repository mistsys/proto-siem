from __future__ import print_function
import boto3
import logging
import json
import gzip
from StringIO import StringIO
from botocore.vendored import requests
import datetime
import re
import os
from boto3 import client as boto3_client

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)

protocoltable = {256: 'MAX', 0: 'HOPOPTS', 2: 'IGMP', 3: 'GGP', 4: 'IPV4', 6: 'TCP', 1: 'ICMP', 8: 'EGP', 12: 'PUP', 17: 'UDP', 22: 'IDP', 29: 'TP', 36: 'XTP', 
         41: 'IPV6', 43: 'ROUTING', 44: 'FRAGMENT', 46: 'RSVP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPV6', 59: 'NONE', 60: 'DSTOPTS', 63: 'HELLO', 
         77: 'ND', 80: 'EON', 103: 'PIM', 108: 'IPCOMP', 255: 'RAW'}
rfc1918 = re.compile('^(10(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172\.(1[6-9]|2[0-9]|3[01]))|192\.168)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})$')

time_fmt = '%Y-%m-%d %H:%M:%S'

client = boto3.client('ec2')

#Remedy Flag
DOREMEDY=False

#Remedy Status Constants, Fail when Remedy Function fails, Error when encounter an error
SUCCESS="Success"
FAIL="Fail"
ERROR="Error"

#Functionality for THREAT_FEED
THREAT_FEED=[]

def fetchProtocolService(protocol_name, port_no):
    '''
    Function to fetch service name from protocol and port combination
    Args:
        protocol_name(string): protocol 
        port_no(string): port 
    Returns:
        service name if relevant else None
    '''
    try:
        service = socket.getservbyport(int(port_no), protocol_name)
    except:
        try:
            service = socket.getservbyport(int(port_no))
        except:
            service = None
    return(service)


def fetchGeoIPData(address):
    '''
    Function to Fetch GeoIP data for an IP address
    Args:
        address(string): IP address to be looked up in the database 
    Returns:
        geoip response from Lambda Function
    '''
    lambda_client = boto3_client('lambda')
    response = lambda_client.invoke(
            FunctionName="CentralizedLogging_FunctionToFetchGeoIPData",
            InvocationType='RequestResponse',
            Payload=json.dumps(address)
        )
    
    string_response = response["Payload"].read().decode('utf-8')
    
    parsed_response = json.loads(string_response)
    
    try:
        if (parsed_response['statusCode']==200):
            geoipresponse = {}
            geoipresponse = json.loads(parsed_response["body"])
            return geoipresponse
    except:
        pass
    
    return None

def isPrivate(ipAddress):
    '''
    Function to Check if ipAddress is private or public
    '''
    if rfc1918.match(ipAddress):
        return True
    return False


MAX_RULE = 100 #Default Rule, Add Deny Rules with RuleNumber less than this

def addToNACL(address, vpcId):
    '''
    Function to add Deny Rule to Network ACL
    Args:
        address(string): IP address to be looked up in the database 
        vpcId(string): vpcId as identifier
    Returns:
        status(string): SUCCESS, FAIL or ERROR
    '''
    next_rule=100
    ec2 = boto3.resource('ec2')
    vpc = ec2.Vpc(vpcId)
    network_acl_iterator = vpc.network_acls.all()
    for acl in network_acl_iterator:
        nacls = client.describe_network_acls(NetworkAclIds=[acl.id])
        if len(nacls['NetworkAcls']) == 0:
            raise Exception("No NACLs found!")
        # find next available rule number
        addressCidr=address + "/32"
        cidrBlockPresent=False
    
        for entry in nacls['NetworkAcls'][0]['Entries']:
            if entry['Egress'] == False and entry['RuleAction'] == 'deny':
                if entry['RuleNumber'] >= MAX_RULE:
                    continue
                if entry['CidrBlock']==addressCidr:
                    cidrBlockPresent=True
                    break
                if entry['RuleNumber'] < MAX_RULE:
                    next_rule = min(next_rule, entry['RuleNumber'])

        next_rule -= 1
        if not cidrBlockPresent:
            try:
                addDenyEntryResponse = client.create_network_acl_entry(
                    NetworkAclId=acl.id,
                    RuleNumber=next_rule,
                    Protocol="-1",
                    RuleAction="deny",
                    Egress=False,
                    CidrBlock=addressCidr
                )
            except:
                print("Caught Error while adding NACL")
                return ERROR
        # Check Response
            
            if (addDenyEntryResponse['ResponseMetadata']['HTTPStatusCode']!=200):
                return FAIL
    return SUCCESS

def lambda_handler(event, context):
    #CloudWatch log data
    outEvent = str(event['awslogs']['data'])
    
    #decode,unzip
    outEvent = gzip.GzipFile(fileobj=StringIO(outEvent.decode('base64','strict'))).read()

    #JSON to dictionary log_data
    cleanEvent = json.loads(outEvent)
    
    for logEvent in cleanEvent['logEvents']:
        logData={}
        logData=logEvent['extractedFields']
        client_network_interfaces = client.describe_network_interfaces(NetworkInterfaceIds=[logEvent['extractedFields']["interface_id"]])
        
        try:
            logData['SGID']=client_network_interfaces['NetworkInterfaces'][0]['Groups'][0]['GroupId']
        except:
            logData['SGID']='N/A'
            
        try:
            logData['VPC']=client_network_interfaces['NetworkInterfaces'][0]['VpcId']
        except:
            logData['VPC']='N/A'
        
        srcaddr=logData['srcaddr']
        dstaddr=logData['dstaddr']
        
        logData['notification']="vpcflowlog-"
        logData['protocol']=protocoltable[int(logData['protocol'])]
        
        if isPrivate(srcaddr) and isPrivate(dstaddr):
            logData['direction']="private-internal"
        else:
            
            if isPrivate(srcaddr):
                ipAddressToScan=dstaddr
                logData['direction']="public-outbound"
            else:
                ipAddressToScan=srcaddr
                logData['direction']="public-inbound"
            
            
            logData['geoip']=fetchGeoIPData(ipAddressToScan)    
            logData['remedyStatus']=None
            if logData['action']=="ACCEPT":
                logData['srcportinfo']=fetchProtocolService(logData['protocol'], logData['srcport'])
                logData['dstportinfo']=fetchProtocolService(logData['protocol'], logData['dstport'])
                
                try:
                    logData['inThreatFeed']=logData['geoip']['inThreatFeed']
                except:
                    logData['inThreatFeed']=False
                    
            	if DOREMEDY and logData['inThreatFeed']:
                    logData['remedyStatus']=addToNACL(ipAddressToScan)
            
        
        print(json.dumps(logData))
