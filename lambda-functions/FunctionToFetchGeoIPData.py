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

LOGTABLE = "GeoIPData"

geoip  = {"city_name":None,"region_name":None,"location": None, "country_name":None,"latitude":None,"longitude":None}

def getIPInfo(address, access_key):
    
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
            'country_name': {'S': geoIPData['country_name']}
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
        geoip ["city_name"]=str(item["city_name"]['S'])
        geoip ["region_name"]=str(item["region_name"]['S'])
        geoip ["location"]=[float(item["longitude"]['S']),float(item["latitude"]['S'])]
        geoip ["latitude"]=float(item["latitude"]['S'])
        geoip ["longitude"]=float(item["longitude"]['S'])
        geoip ["country_name"]=str(item["country_name"]['S'])
    else:
        geoip = None
    
    return geoip


def lambda_handler(event, context):
    
    
    
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

