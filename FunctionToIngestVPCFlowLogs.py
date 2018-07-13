'''
FunctionToIngestVPCFlowLogs

Lambda Function that gets triggered on the event of a VPC Flow Log receieved
by CloudWatch. The function adds various fields to Flow Log.

Citations:
[1]:https://aws.amazon.com/blogs/security/how-to-optimize-and-visualize-your-security-groups/
[2]:https://mysteriouscode.io/blog/intrusion-detection-and-prevention-with-aws-lambda-and-dynamodb-streams/
[3]:https://aws.amazon.com/blogs/security/how-to-facilitate-data-analysis-and-fulfill-security-requirements-by-using-centralized-flow-log-data/
[4]:https://aws.amazon.com/blogs/security/how-to-visualize-and-refine-your-networks-security-by-adding-security-group-ids-to-your-vpc-flow-logs/

'''
from __future__ import print_function
import boto3
import logging
import json
import gzip
from StringIO import StringIO
from botocore.vendored import requests
import datetime
import socket
import re
import os

table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
rfc1918 = re.compile('^(10(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172\.(1[6-9]|2[0-9]|3[01]))|192\.168)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})$')
IP_Cache = {}

# Logging, Tweaks required
logger = logging.getLogger()
if logger.handlers:
    for handler in logger.handlers:
        logger.removeHandler(handler)
logging.basicConfig(level=logging.INFO)
time_fmt = '%Y-%m-%d %H:%M:%S'


client = boto3.client('ec2')

#Remedy Flag
DOREMEDY=False

#Remedy Status Constants, Fail when Remedy Function fails, Error when encounter an error
SUCCESS="Success"
FAIL="Fail"
ERROR="Error"

# TODO: Get from API Call POC
THREAT_FEED=["173.255.238.173","186.67.91.98","79.34.201.74","104.200.20.129",
"180.183.142.77","154.70.135.195","190.214.219.247","152.240.102.192","179.101.41.234",
"186.101.211.202","156.197.80.109","181.199.16.111","145.131.154.236","185.200.250.155",
"109.226.213.241","51.254.188.36","41.46.168.26","197.51.198.220","179.90.186.142",
"52.53.210.208","171.242.126.133","188.118.181.192","190.214.220.167","211.151.26.4",
"222.240.241.29","186.101.187.162","202.131.228.123","191.14.185.50","159.192.232.11",
"181.198.230.215","1.54.47.244","179.119.172.239","181.198.254.246","14.161.163.119",
"178.47.183.230","212.237.45.26","186.3.228.113","41.42.184.167","123.27.22.100",
"5.62.41.26","145.239.197.98","66.85.152.32","181.112.110.29","123.59.45.153",
"136.144.129.3","217.23.2.182","189.172.15.196","181.199.110.67","14.162.245.251",
"54.38.184.9","186.4.244.47","41.252.228.21","118.71.122.64","171.241.199.36",
"208.117.45.190","158.177.139.228","193.70.49.198","107.170.226.214","58.152.87.91",
"50.116.27.38","159.89.165.109","61.182.27.121","185.220.101.8","186.101.246.194",
"186.4.146.73","37.26.136.249","217.23.2.183","41.238.98.44","123.21.203.247",
"113.170.122.19","89.184.77.171","172.104.246.157","18.218.252.138","113.172.114.38",
"63.140.28.206","95.108.0.171","186.4.146.60","85.250.57.222","186.4.154.224",
"186.47.170.138","139.162.254.21","181.198.203.113","177.184.93.241","188.166.1.95",
"186.47.170.129","181.199.90.143","139.162.147.159","186.3.186.134","109.74.206.244",
"171.242.222.164","186.33.143.237","171.7.171.64","119.29.54.203","118.68.61.64",
"159.89.54.241","69.164.204.42","217.23.9.106","177.163.222.177","186.3.158.252","186.101.139.20"]


# TODO: Handle API Calls and Build Cached Solution For Queries

def getIPInfo(address, access_key):
    geoip  = {"city_name":None,"region_name":None,"location": None,
          "country_name":None,"latitude":None,"longitude":None}
          
    api = "http://api.ipstack.com/"
    request_string=api+address+"?access_key="+access_key
    
    
    try:
        cached_geoip = IP_Cache[address]
        return  cached_geoip
    except:
        pass
        
    try:
        response = requests.get(request_string)
    except:
        return geoip
    
    json_response = json.loads(response.text)
    geoip ["city_name"]=str(json_response["city"])
    geoip ["region_name"]=str(json_response["region_name"])
    geoip ["location"]=[json_response["longitude"],json_response["latitude"]]
    geoip ["latitude"]=json_response["latitude"]
    geoip ["longitude"]=json_response["longitude"]
    geoip ["country_name"]=str(json_response["country_name"])
    IP_Cache[address]=geoip
    
    return geoip

def isPrivate(ipAddress):
    if rfc1918.match(ipAddress):
        return True
    return False
    
NACL_ID = ''
MAX_RULE = 100 #Default Rule, Add Deny Rules with RuleNumber less than this

def addToNACL(address):
    next_rule=100
    nacls = client.describe_network_acls(NetworkAclIds=[NACL_ID])
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
                NetworkAclId=NACL_ID,
                RuleNumber=next_rule,
                Protocol="-1",
                RuleAction="deny",
                Egress=False,
                CidrBlock=addressCidr
            )
        except:
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
        
        try:
            client_network_interfaces = client.describe_network_interfaces(NetworkInterfaceIds=[logEvent['extractedFields']["interface_id"]])
            logData['SGID']=client_network_interfaces['NetworkInterfaces'][0]['Groups'][0]['GroupId']
            logData['VPC']=client_network_interfaces['NetworkInterfaces'][0]['VpcId']
        except:
            logData['SGID']=''
            logData['VPC']=''
        
        srcaddr=logData['srcaddr']
        dstaddr=logData['dstaddr']
        
        
        
        if isPrivate(srcaddr) and isPrivate(dstaddr):
            logData['direction']="private-internal"
        else:
            if isPrivate(srcaddr):
                ipAddressToScan=dstaddr
                logData['direction']="public-outbound"
            else:
                ipAddressToScan=srcaddr
                logData['direction']="public-inbound"
                
            logData['remedyStatus']=None
            # TODO:Placeholder for security object
            if logData['action']=="ACCEPT":
                logData['geoip']=getIPInfo(ipAddressToScan,os.environ['GEOIP_KEY'])
                if ipAddressToScan in THREAT_FEED:
                    logData["inThreatFeed"]=True
                    if DOREMEDY:
                        logData['remedyStatus']=addToNACL(ipAddressToScan)
                else:
                    logData["inThreatFeed"]=False
    
        logData['notification']="VPC_FLOW_LOG"
        logData['protocol']=table[int(logData['protocol'])]
        print(json.dumps(logData))
        return True 
