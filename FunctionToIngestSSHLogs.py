from __future__ import print_function
import logging
import json
import boto3
import logging
import json
import gzip
from StringIO import StringIO
from botocore.vendored import requests
import datetime

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)

import re
time_fmt = '%Y-%m-%d %H:%M:%S'

#TODO: Handle API Calls and Build Cached Solution For Queries
geoip  = {"city_name":None,"region_name":None,"location": None,
          "country_name":None,"latitude":None,"longitude":None}

def getIPInfo(address):
    """Returns a geoip type object that countains city_name, region_name,
    location, latutute, longitude, and country_name for a given IP address
    looked up over 
    Args:
        address:IP address
        TYPE:String
    Returns:
        geoip dictionary
        TYPE: Dictionary
    """
    api = "http://api.ipstack.com/"
    access_key="?access_key=__IPSTACK_KEY__&output=json"
    try:
        request_string=api+address+access_key
        response = requests.get(api+address+access_key)
    except:
        return geoip 

    if (response.status_code==200):
        json_response = json.loads(response.text)
        geoip ["city_name"]=str(json_response["city"])
        geoip ["region_name"]=str(json_response["region_name"])
        geoip ["location"]=[json_response["longitude"],json_response["latitude"]]
        geoip ["latitude"]=json_response["latitude"]
        geoip ["longitude"]=json_response["longitude"]
        geoip ["country_name"]=str(json_response["country_name"])
    return geoip 
    
def lambda_handler(event, context):
    """Summary
    Processes events subscribed from /var/secure logs from EC2 Instances
    Args:
        event (TYPE): Description
        context (TYPE): Description
    """
    #CloudWatch log data
    outEvent = str(event['awslogs']['data'])
    
    #decode,unzip
    outEvent = gzip.GzipFile(fileobj=StringIO(outEvent.decode('base64','strict'))).read()
    
    #JSON to dictionary log_data
    cleanEvent = json.loads(outEvent)
    
    logData = {"notification":"EC2_AUTH_LOGS","source":None, "isSSHLog":False,"logType":None}
    
    for logEvent in cleanEvent['logEvents']:
        logData['source']=logEvent['extractedFields']['source']
        message=logEvent['extractedFields']['message']
        logData['eventTimestamp']=logEvent['timestamp']
        utility=logEvent['extractedFields']['utility']
        if "sshd" in utility:
            logData['isSSHLog']=True
            if "session opened" in message:
                logData['logType']="SuccessfulLogin"
                logData['user']=re.findall(r"user(.*?)by",message)[0].strip()
            elif "Accepted publickey" in message:
                logData['logType']="AcceptedPublickey"
                logData['IP']=re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",message)[0]
            elif "Received disconnect" in message:
                logData['logType']="PortScanning"
                logData['IP']=re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",message)[0]
            elif "Invalid user" in message:
                logData['logType']="FailedLogin"
                logData['user']=re.findall(r"user(.*?)from",message)[0].strip()
                logData['IP']=re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",message)[0]
                logData['geoip']=getIPInfo(logData['IP'])  
            elif "maximum authentication attempts" in message:
                logData['logType']="MaxAuthTries"
                logData['user']=re.findall(r"user(.*?)from",message)[0]
                logData['IP']=re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",message)[0]
                logData['geoip']=getIPInfo(logData['IP'])            
            else:
                continue
        elif "sudo" in utility:
            logData['isSSHLog']=False
            logData['SudoInfo']=message
            logData['logType']="sudo"
        elif "runuser" in utility:
            logData['isSSHLog']=False
            logData['RunUserInfo']=message
            logData['logType']="runuser"
        else:
            logData['isSSHLog']=False
            logData['DefaultInfo']=message
        #print logData to be consumed by ElasticSearch
        print(json.dumps(logData))
        
