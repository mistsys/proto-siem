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

# TODO: Handle API Calls and Build Cached Solution For Queries
ip_lookup = {"city":None,"region":None,"location": None,"country":None,"geoname":None}

def get_ip_info(address):
    api = "http://api.ipstack.com/"
    access_key="?access_key=__IPSTACK_KEY__&output=json"
    try:
        request_string=api+address+access_key
        response = requests.get(api+address+access_key)
    except:
        return ip_lookup

    if (response.status_code==200):
        json_response = json.loads(response.text)
        ip_lookup["city"]=str(json_response["city"])
        ip_lookup["region"]=str(json_response["region_name"])
        ip_lookup["location"]={"lat": json_response["latitude"],"lon": json_response["longitude"]}
        ip_lookup["country"]=str(json_response["country_name"])
        ip_lookup["geoname"]=str(json_response["location"]["geoname_id"])
    return ip_lookup
    
def lambda_handler(event, context):
    #CloudWatch log data
    outEvent = str(event['awslogs']['data'])
    
    #decode,unzip
    outEvent = gzip.GzipFile(fileobj=StringIO(outEvent.decode('base64','strict'))).read()
    
    #JSON to dictionary log_data
    cleanEvent = json.loads(outEvent)
    
    logData = {"notification":"EC2_AUTH_LOGS","source":None, "isSSHLog":False,"logType":None}
    
    for logEvent in cleanEvent['logEvents']:
        # print("Event:",json.dumps(logEvent))
        source=logEvent['extractedFields']['process']
        logData['source']=source
        message=logEvent['extractedFields']['eventdata']
        logData['eventTimestamp']=logEvent['timestamp']
        # print("Message:",logEvent['message'])
        if "sshd" in source:
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
                logData['FailedLoginInfo']=get_ip_info(logData['IP'])  
            elif "maximum authentication attempts" in message:
                logData['logType']="MaxAuthTries"
                logData['user']=re.findall(r"user(.*?)from",message)[0]
                logData['IP']=re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",message)[0]
                logData['DisconnectedInfo']=get_ip_info(logData['IP'])            
            else:
                continue
        elif "sudo" in source:
            logData['isSSHLog']=False
            logData['SudoInfo']=message
        elif "runuser" in source:
            logData['isSSHLog']=False
            logData['RunUserInfo']=message
        else:
            logData['isSSHLog']=False
            logData['DefaultInfo']=message
        print(json.dumps(logData))
        
