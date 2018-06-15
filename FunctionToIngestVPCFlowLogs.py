from __future__ import print_function
import boto3
import logging
import json
import gzip
from StringIO import StringIO
from botocore.vendored import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_info(address):
    api = "http://api.ipstack.com/"
    access_key="?access_key=__IPSTACK_KEY__"
    try:
        request_string=api+address+access_key
        response = requests.get(api+address+access_key)
        json_response = json.loads(response.text)
        processed_response = {"city":str(json_response["city"]),
                    "region_name":str(json_response["region_name"]),
                    "location": {"lat": json_response["latitude"],"lon": json_response["longitude"]},
                    "country_name":str(json_response["country_name"]),
                    "geoname":json_response["location"]["geoname_id"]
        }
        return processed_response
    except:
        return None

def lambda_handler(event, context):
    #capture the CloudWatch log data
    outEvent = str(event['awslogs']['data'])
    
    #decode and unzip the log data
    outEvent = gzip.GzipFile(fileobj=StringIO(outEvent.decode('base64','strict'))).read()
    
    #convert the log data from JSON into a dictionary
    cleanEvent = json.loads(outEvent)
    for logEvent in cleanEvent['logEvents']:
        srcaddr = str(logEvent['extractedFields']['srcaddr'])
        processed_response=get_info(srcaddr)
        action = str(logEvent['extractedFields']['action'])
        if "10." not in srcaddr:
            log={"NOTIFICATION":"VPC_FLOW_LOG",
                "dstaddr":str(logEvent['extractedFields']['dstaddr']),
                "srcaddr":srcaddr,
                "srcport":str(logEvent['extractedFields']['srcport']),
                "dstport":str(logEvent['extractedFields']['dstport']),
                "action":action,
                "info":processed_response
            }
            print(json.dumps(log))
