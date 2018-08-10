from __future__ import print_function
import logging
import json
import boto3
import logging
import json
import gzip
from botocore.vendored import requests
import datetime
import os
from boto3 import client as boto3_client

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)

LOGTABLE = "centralized-logging-table"

# Logic for AWS IP Check
# Code to Check for IP on AWS Feed
ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']

prefixinfo={}
toupdateprefixeinfo={}

for item in ip_ranges:
    prefixinfo[item['ip_prefix']]={'region':item['region'],'service':item['service']}
    
netlist = [item['ip_prefix'] for item in ip_ranges]

# geoip placeholder

geoip  = {"city_name":None,"region_name":None,"location": None, "country_name":None,"latitude":None,"longitude":None}

def getIPInfo(address, access_key):
    '''To fetch IP Info from API, provide GEOIP Key in Environment Variables'''
    api = "http://api.ipstack.com/"
    request_string=api+address+"?access_key="+access_key
    
    cachedgeoIP = getgeoIPData(address, LOGTABLE)
    
    if cachedgeoIP is not None:
        return cachedgeoIP
        
    try:
        api_response = requests.get(request_string)
    except:
        return None
    
    json_response = json.loads(api_response.text)
    
    #Check for API response
    try:    
        if not json_response(["success"]):
            return None
    except:
        pass
    
    geoip ["city_name"]=str(json_response["city"])
    geoip ["region_name"]=str(json_response["region_name"])
    geoip ["location"]=[json_response["longitude"],json_response["latitude"]]
    geoip ["latitude"]=json_response["latitude"]
    geoip ["longitude"]=json_response["longitude"]
    geoip ["country_name"]=str(json_response["country_name"])
    putgeoIPData(address, geoip, LOGTABLE)
    
    return geoip

def putgeoIPData(address, geoIPData, table):
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
            'IPaddress': {'S': address},
            'city_name': {'S': geoIPData['city_name']},
            'region_name': {'S': geoIPData['region_name']},
            'latitude': {'S': str(geoIPData['latitude'])},
            'longitude': {'S': str(geoIPData['longitude'])},
            'country_name': {'S': geoIPData['country_name']},
            'isOnAWS': {'BOOL': addressInAWSNetwork(address, netlist)},
            'service': {'S': str(toupdateprefixeinfo[address]['service'])},
            'awsregion': {'S': str(toupdateprefixeinfo[address]['region'])}
        }
    )
    return 0
    
def getgeoIPData(address, table):
    """Log all information to the provided DynamoDB table.
    Args:
        logData (dict): All extracted information
        table (string): Table name for event history.
    Returns:
        TYPE: Success
    """
    client = boto3.client('dynamodb')

    try:
        response = client.get_item(
            TableName=table,
            Key={
                'IPaddress': {'S': address}
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        try:
            item = response['Item']
        except:
            item = None
    
    geoip = {}
    
    if item is not None:
        #print("Item",item)
        geoip ["city_name"]=str(item["city_name"]['S'])
        geoip ["region_name"]=str(item["region_name"]['S'])
        geoip ["location"]=[float(item["longitude"]['S']),float(item["latitude"]['S'])]
        geoip ["latitude"]=float(item["latitude"]['S'])
        geoip ["longitude"]=float(item["longitude"]['S'])
        geoip ["country_name"]=str(item["country_name"]['S'])
        try:
            geoip ["isOnAWS"]=item["isOnAWS"]
            geoip ["service"]=str(item["service"]['S'])
            geoip ["awsregion"]=str(item["awsregion"]['S'])
        except:
            pass
    else:
        geoip = None
    
    return geoip



#https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python-2-x
def addressInAWSNetwork(ip, netlist):
    ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
    isOnAWS=False
    for net in netlist: 
        netstr, bits = net.split('/')
        netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        if (ipaddr & mask) == (netaddr & mask):
            isOnAWS=True
            #print("IP on AWS Network",ip)
            toupdateprefixeinfo[ip] = prefixinfo[net]
            #print("toupdateprefixeinfo",toupdateprefixeinfo)
            break
        else:
            toupdateprefixeinfo[ip] = {'service':"N/A",'region':"N/A"}
    return isOnAWS

def lambda_handler(event, context):
    #print("Event",json.dumps(event))
    geoip = getIPInfo(event, os.environ['GEOIP_KEY'])
    
    response_failure = {
        "statusCode": 404,
        "body": None
    }
    
    
    response_sucess = {
        "statusCode": 200,
        "body": json.dumps(geoip)
    }
    
    if geoip is None:
        return response_failure

    return response_sucess




