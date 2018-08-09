# Centralized Security Logging SIEM

A comprehensive log management and analysis solution that can be used to analyze events
that could affect the security of the infrastructure and take actions. With multiple account and services provisioned, the amount and variety of logs can include service-specific metrics and log files, additional data, such as API calls, configuration changes etc.. Log files from web servers, applications, and operating systems also provide valuable data, though in different formats, and in a random and distributed fashion. The aim is to effectively consolidate, manage, and analyze these different logs 

## Getting Started

Requirement for getting started with deploying the solution.

## Prerequisites

Required Resources

## Installing


### Configuring Data Sources

The solution requires logs from all sources to be published to CloudWatch log groups and further these groups subscribe to Lambda Functions for specific logs. Following are the steps to enable Authentication Logs, CloudTrail Logging and VPC Flow Logs:

1. If authentication logs from EC2 Instances are to be captured, install cloudwatch logs agent and capture files from     source /var/log/auth.log and destination as a cloudwatch logs group. This log group can contain log streams from all machines on your account. For steps to install please check [Install and Configure the CloudWatch Logs Agent on a Running EC2 Linux Instance](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/QuickStartEC2Instance.html) and associate EC2 Instance with necessary permission to send logs to cloudwatch.

2. For CloudTrail log analysis ensure that CloudTrail logging is enabled across regions on your account. You can use a custom log group of your choice or default. The logs from CloudWatch log group can be shipped to an elastic search domain directly without any processing. For more information on how to enable logging check [Logging AWS Organizations API Calls with AWS CloudTrail](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_monitoring.html)

3. Ensure that VPC Flow Logs are published to a CloudWatch Logs group, this will be the source for another ingestor function that consumes VPC Flow Logs and augments more data to be later sent to Elastic Search. For this step visit [Publishing Flow Logs to CloudWatch Logs](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs-cwl.html?shortFooter=true)

### Configuring DynamoDB table for GeoIP and Threat Feed data

Create a DynamoDB table by following steps from by following steps from (https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/SampleData.CreateTables.html) and name the table "centralized-logging". The schema requires "IPaddress" as the primary key.

### Configuring Lambda Functions

1. Ingestor functions [FunctionToIngestSSHLogs.py](https://github.com/mistsys/mist-centralized-logging/blob/master/FunctionToIngestSSHLogs.py), [FunctionToIngestVPCFlowLogs.py](https://github.com/mistsys/mist-centralized-logging/blob/master/FunctionToIngestVPCFlowLogs.py) are source specific lambda functions that consume logs from CloudWatch Log Groups and augment information further. This is similar to normalization of logs and modification of logs further to be sent to ELK stack.

2. [FunctionToFetchGeoIPData.py](https://github.com/mistsys/mist-centralized-logging/blob/master/FunctionToFetchGeoIPData.py) is the IP lookup function that is called with an IP address as an argument from the above two lambda functions. This function also maintains the DynamoDB database that lists GeoIP information, ThreatFeed information for each IP as well as information if IP belongs to AWS.

3. [FunctionToUpdateThreatFeed.py](https://github.com/mistsys/mist-centralized-logging/blob/master/FunctionToUpdateThreatFeed.py) maintains Threat Feed data on the DynamoDB table and can be configured to run after evaluation. This can be a scheduled update that scans through all the IPs on the table and updates IP's on active threat feed.

4. [FunctionForESDataRetention.py](https://github.com/mistsys/mist-centralized-logging/blob/master/FunctionForESDataRetention.py) Although there have been many approaches that are suggested for LogData retention, this solution explicitly makes use of a scheduled lambda function that looks for indexes on the ELK stack older than a predefined policy and deletes them. A better approach would be to ship old logs to an S3 bucket or AWS glacier.

5. Since we are working with three variety of log types, the design requires different Elastic Search indexes to be maintained for these types. Having different indexes helps with searching, query and maintaining logs as required by custom policies. The function autocreated when shipping logs to ElasticSearch requires an update to process logs and is provided.

| Function Name | Source/Trigger | timeout | memory-size |
| ------ | ------ | ------ | ------ |
| FunctionToIngestVPCFlowLogs.py | CloudWatch Log Group - VPC Flow Logs  | 1 min | 128 MB |
| FunctionToIngestSSHLogs.py | CloudWatch Log Group - Authentication Logs | 10 sec | 128 MB |
| FunctionToFetchGeoIPData.py | None, Function called by other Lambda | 10 sec | 128 MB |
| FunctionToUpdateThreatFeed.py | Scheduled CloudWatch Rule Trigger | 10 sec | 128 MB |
| FunctionForESDataRetention.py | Scheduled CloudWatch Rule Trigger | 10 sec | 128 MB |
| Google Analytics | [plugins/googleanalytics/README.md][PlGa] |

### Setting Up Kibana

Steps for deploying Kibana Template

  To install the Kibana Index Mapping:
    
    1. Use the Development Console in AWS ElasticSearch Kibana Console to access templates
    
    2. Run Command GET /_template to retrieve all available templates
    
    3. If reindexing is required use the command curl -XDELETE 'http://YOUR_ES_DOMAIN_ENDPOINT/cwl*/' to delete any previous
       indexes
    
    4. Finally, Use PUT _template/template_1 and append the template data from KibanaTemplateVPCFlowLogs.json file and PUT _template/template_2 and append the template data from KibanaTemplateAuthLog.json file
   
   Note: This template is required for changing type of certain fields to the desired value which is not captured by
   ES by default (location type as geo_point and packets type as long)
   
After this step enable respective subsciptions, search through ES management console and create index for "authlog-","vpcflowlog-","cloudtrail-". Import the dashboard templates provided and visualize data. 

## Additional Deployment Notes

The above steps must be followed in a specific order for the Elastic Search to identify mapping associations correctly. The Threat Feed subscription can be customized further. GeoIP data requires subscription and this solution makes use of [IPStack](https://ipstack.com/documentation), for evaluation you can work with the free API Access Key that grants upto 10000 requests per month or a paid subscription can offer better options about IP reputation and be integrated into Threat Feed analysis.

## Contributors

Sumit Bajaj

## Acknowledgements
