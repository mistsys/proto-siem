from __future__ import print_function
import logging
import json
import boto3
from botocore.vendored import requests
import datetime
import os
from datetime import timedelta
import time
import socket,struct
import sys
from boto3 import client as boto3_client

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Best Practice to pass LOGTABLE name as environment variable
# and use LOGTABLE=os.environ['LOGTABLE']
LOGTABLE = "centralized-logging-geoip"

# To build Threat Feed from this data import IP's as a list

IPThreatFeedList = []

ThreatFeedLinks = ["https://www.talosintelligence.com/documents/ip-blacklist"]
for link in ThreatFeedLinks:
    res = requests.get(link)
    IPThreatFeedList = res.text.split('\n')

client = boto3.client('dynamodb')
dynamodb = boto3.resource('dynamodb')
tabledb = dynamodb.Table(LOGTABLE)

def updateIPThreatFeed(address, status, table=LOGTABLE):
    '''
    Args:
        address(string):IP address to be updated on the DynamoDB table
        status(bool): status to be set, True if in ThreatFeed, False if not
        table(string):name of LOGTABLE
    Returns:
        0 or succesful return
    Raises:
        Exception is adding to Table failed
    '''
    try:
        response = tabledb.update_item(
            TableName=table,
            Key={
                'IPaddress': address
            },
            UpdateExpression="SET inThreatFeed=:p",
            ExpressionAttributeValues={
                ':p': status
            },
            ReturnValues="UPDATED_NEW"
        )
    except:
        print ("Caught exception!")
        print ("Unexpected error:", sys.exc_info()[0])
        raise
    return 0
    
def scanTable():
    '''
    Function to Scan a DynamoDB table for all items to build
    keys with threatFeedTrue and threatFeedFalse
    
    Returns:
        threatFeedTrue, threatFeedFalse
    '''
    tableIPKeysThreatFeedTrue=[]
    alldata = []
    response = tabledb.scan()
    
    alldata.extend(response['Items'])
    
    while 'LastEvaluatedKey' in response:
        response = tabledb.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        alldata.extend(response['Items'])
        
    print("Total Data to Evaluate",len(alldata))
    tableIPKeys = [item['IPaddress'] for item in alldata]
    
    for item in alldata:
        try:
            if item['inThreatFeed']:
                tableIPKeysThreatFeedTrue.append(item['IPaddress'])
        except:
            continue
        
    threatFeedTrue = [ip for ip in tableIPKeys if ip in IPThreatFeedList and ip not in tableIPKeysThreatFeedTrue]
    print("IP list to update to threatFeedTrue",threatFeedTrue)
    threatFeedFalse = [ip for ip in tableIPKeysThreatFeedTrue if ip not in IPThreatFeedList]
    print("IP list to update to threatFeedFalse",threatFeedFalse)
    return threatFeedTrue,threatFeedFalse

def lambda_handler(event, context):

    threatFeedTrue,threatFeedFalse = scanTable()
    if threatFeedTrue:
        for ip in threatFeedTrue:
            updateIPThreatFeed(ip, True, table=LOGTABLE)
    if threatFeedFalse:
        for ip in threatFeedFalse:
            updateIPThreatFeed(ip, False, table=LOGTABLE)

    return 0
    
