# Function Requires AWS Lambda to Have access to  ES
# Configure a scheduled CloudWatch rule for this function to be triggered

from __future__ import print_function
import logging
import json
import boto3
from botocore.vendored import requests
import datetime
import os
from datetime import timedelta
import time

# Dictionary of logType:ExpiryDays as per log retention Policy
indexexpirydict = {"cloudtrail":14,"vpcflowlog":90,"authlog":180}
# Input ES domain Name here
eshost = ""

now = time.time() + time.altzone

def fetchIndex(uri):
    res = requests.get(eshost+"/_aliases")
    json_response = json.loads(res.text)
    return json_response.keys()

def dropIndex(uri, idxName):
    res = requests.request('delete',eshost+"/"+idxName)
    json_response = json.loads(res.text)
    try:
        if (json_response['acknowledged']):
            print("Index {0} Deleted".format(idx))
            return True
    except:
        print("Caught Exception",sys.exc_info()[0])
    print("Index {0} Could Not be Deleted".format(idx))
    return False
    
def lambda_handler(event, context):
    
    indexes = fetchIndex(eshost)
    for idx in indexes:
        idxsplit = idx.split('-')
        group = idxsplit[0]
        if (group=="cwl" and idxsplit[1] in indexexpirydict.keys()):
            subgroup = idxsplit[1]
            dayCutoff = now - (indexexpirydict[subgroup] * 24 * 60 * 60)
            ymd = idxsplit[2].split('.')
            idxTimeToCompare = time.mktime((int(ymd[0]), int(ymd[1]), int(ymd[2]),0,0,0,0,0,0))
            if (idxTimeToCompare < dayCutoff):
                print("Deleting Index for type:",subgroup," | With Identifier:",idx)
                dropIndex(uri, idxName)
    
