# Centralized Security Logging SIEM

A comprehensive log management and event analysis SIEM solution that provides an insight into your AWS infrastructure using the ELK stack. With multiple account and services provisioned, the amount and variety of logs can include service-specific metrics and log files, additional data, such as API calls, configuration changes etc.. Log files from web servers, applications, and operating systems also provide valuable data, though in different formats, and in a random and distributed fashion. The aim is to effectively consolidate, manage, and analyze critical logs. 

## Getting Started

The solution requires an AWS account with Admin User access.

## Prerequisites

Knowledge about deploying the Lambda Functions and configuring AWS managed ElasticSearch.

## Installing


### Configuring Data Sources

The solution requires logs from all sources to be published to CloudWatch log groups and further these groups subscribe to Lambda Functions for specific logs. Following are the steps to enable Authentication Logs, CloudTrail Logging and VPC Flow Logs:

1. If authentication logs from EC2 Instances are to be captured, install cloudwatch logs agent and capture files from     source /var/log/auth.log and destination as a cloudwatch logs group. This log group can contain log streams from all machines on your account. For steps to install please check [Install and Configure the CloudWatch Logs Agent on a Running EC2 Linux Instance](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/QuickStartEC2Instance.html) and associate EC2 Instance with necessary permission to send logs to cloudwatch.

2. For CloudTrail log analysis ensure that CloudTrail logging is enabled across regions on your account. You can use a custom log group of your choice or default. The logs from CloudWatch log group can be shipped to an elastic search domain directly without any processing. For more information on how to enable logging check [Logging AWS Organizations API Calls with AWS CloudTrail](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_monitoring.html)

3. Ensure that VPC Flow Logs are published to a CloudWatch Logs group, this will be the source for another ingestor function that consumes VPC Flow Logs and augments more data to be later sent to Elastic Search. For this step visit [Publishing Flow Logs to CloudWatch Logs](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs-cwl.html?shortFooter=true)

### Configuring DynamoDB table for GeoIP and Threat Feed data

[Create a DynamoDB table](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/SampleData.CreateTables.html)  and name the table "centralized-logging-table". The schema required is "IPaddress", type String as the primary key.

### Configuring ElastiSearch Domain

Create an ElasticSearch domain with Instance type and Instance number of your choice. It is best to have 3 instances or type m4.large.elasticsearch.

### Configuring Lambda Functions

1. Ingestor functions [SIEMFunctionToIngestSSHLogs.py](https://github.com/mistsys/mist-centralized-logging/blob/master/lambda-functions/SIEMFunctionToIngestSSHLogs.py), [SIEMFunctionToIngestVPCFlowLogs.py](https://github.com/mistsys/mist-centralized-logging/blob/master/lambda-functions/SIEMFunctionToIngestVPCFlowLogs.py) are source specific lambda functions that consume logs from CloudWatch Log Groups and augment information further. This is similar to normalization of logs and modification of logs further to be sent to ELK stack.

2. [SIEMFunctionToFetchGeoIPData.py](https://github.com/mistsys/mist-centralized-logging/blob/master/lambda-functions/SIEMFunctionToFetchGeoIPData.py) is the IP lookup function that is called with an IP address as an argument from the above two lambda functions. This function also maintains the DynamoDB database that lists GeoIP information, ThreatFeed information for each IP as well as information if IP belongs to AWS.

3. [SIEMFunctionToUpdateThreatFeed.py](https://github.com/mistsys/mist-centralized-logging/blob/master/lambda-functions/SIEMFunctionToUpdateThreatFeed.py) maintains Threat Feed data on the DynamoDB table and can be configured to run after evaluation. This can be a scheduled update that scans through all the IPs on the table and updates IP's on active threat feed.

4. [SIEMFunctionForESDataRetention.py](https://github.com/mistsys/mist-centralized-logging/blob/master/lambda-functions/SIEMFunctionForESDataRetention.py) Although there have been many approaches that are suggested for LogData retention, this solution explicitly makes use of a scheduled lambda function that looks for indexes on the ELK stack older than a predefined policy and deletes them. A better approach would be to ship old logs to an S3 bucket or AWS glacier.

5. Since we are working with three variety of log types, the design requires different Elastic Search indexes to be maintained for these types. Having different indexes helps with searching, query and maintaining logs as required by custom policies. The function autocreated when shipping logs to ElasticSearch requires a minor update to process logs and is provided. This function looks for a "notification" keyword in the logs and modifies the index of the document that is send to ElasticSearch.

```

    function transform(payload) {
    if (payload.messageType === 'CONTROL_MESSAGE') {
        return null;
    }

    var bulkRequestBody = '';

    payload.logEvents.forEach(function(logEvent) {
        var timestamp = new Date(1 * logEvent.timestamp);
        

        // index name format: cwl-YYYY.MM.DD
        var indexName = [
            'cwl-'+fetchType(logEvent.message)+timestamp.getUTCFullYear(),              // year
            ('0' + (timestamp.getUTCMonth() + 1)).slice(-2),  // month
            ('0' + timestamp.getUTCDate()).slice(-2)          // day
        ].join('.');

        var source = buildSource(logEvent.message, logEvent.extractedFields);
        source['@id'] = logEvent.id;
        source['@timestamp'] = new Date(1 * logEvent.timestamp).toISOString();
        source['@message'] = logEvent.message;
        source['@owner'] = payload.owner;
        source['@log_group'] = payload.logGroup;
        source['@log_stream'] = payload.logStream;

        
        var action = { "index": {} };
        action.index._index = indexName;
        action.index._type = payload.logGroup;
        action.index._id = logEvent.id;
        
        bulkRequestBody += [ 
            JSON.stringify(action), 
            JSON.stringify(source),
        ].join('\n') + '\n';
    });
    return bulkRequestBody;
    }

    function fetchType(message) {
    var log_type;
    var jsonSubString;
    var JSONMessage;
    jsonSubString = extractJson(message);
    if (jsonSubString !== null) { 
        JSONMessage=JSON.parse(jsonSubString);
        try {
            log_type = JSONMessage['notification'];
        } catch(err) {
            log_type = "undefined-"
        } 
        
        if (log_type==undefined) {
            log_type = "cloudtrail-"
        }
        
    }
    console.log("Type:"+log_type);
    return log_type;
    }
```

| Function Name | Source/Trigger | timeout | memory-size |
| ------ | ------ | ------ | ------ |
| FunctionToIngestVPCFlowLogs.py | CloudWatch Log Group - VPC Flow Logs  | 1 min | 128 MB |
| FunctionToIngestSSHLogs.py | CloudWatch Log Group - Authentication Logs | 10 sec | 128 MB |
| FunctionToFetchGeoIPData.py | None, Function called by other Lambda | 10 sec | 128 MB |
| FunctionToUpdateThreatFeed.py | Scheduled CloudWatch Rule Trigger | 10 sec | 128 MB |
| FunctionForESDataRetention.py | Scheduled CloudWatch Rule Trigger | 10 sec | 128 MB |

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

## Lambda Subscriptions

1. CloudTrail logs log-group on CloudWatch ships logs directly to the function that can be autocreated with the edit above, Use option "Subscribe to AWS Lambda" and choose filter pattern as CloudTrail Logs
2. After configuring a CloudWatch log group to receive authentication logs, choose "Stream To AWS Lambda" option and select FunctionToIngestSSHLogs as the target. This function publishes logs to another log group on CloudWatch with the function name /aws/lambda/FunctionToIngestSSHLogs, Stream this to the Lambda function that ships logs to elastic search. Configure the filter as "notification"
3. After configuring a CloudWatch log group to receive VPC Flow Logs, choose "Stream To AWS Lambda" option and select FunctionToIngestVPCFlowLogs as the target. This function publishes logs to another log group on CloudWatch with the function name /aws/lambda/FunctionToIngestVPCFlowLogs, Stream this to the Lambda function that ships logs to elastic search. Configure the filter as "notification"
4. The Lambda functions SIEMFunctionToUpdateThreatFeed.py and SIEMFunctionToFetchGeoIPData.py require CloudWatch rules to be enabled that can trigger these functions on a scheduled basis.
5. SIEMFunctionForESDataRetention.py requires additional policies that grant the lambda function access to make changes to the ES domain.
6. If you choose to use the functionality provided by SIEMFunctionToIngestCloudWatchEvents.py, configure rules which listen for specific calls as listed in the function and this requires an IAM role to make changes to security group or the ACL.

## Additional Deployment Notes

The above steps must be followed in a specific order for the Elastic Search to identify mapping associations correctly. The Threat Feed subscription can be customized further. GeoIP data requires subscription and this solution makes use of [IPStack](https://ipstack.com/documentation), for evaluation you can work with the free API Access Key that grants upto 10000 requests per month or a paid subscription can offer better options about IP reputation and be integrated into Threat Feed analysis. It is required for the templates to be set up on Kibana before shipping logs to ES.

## Contributors

Sumit Bajaj

## Resources

1. [how-to-optimize-and-visualize-your-security-groups](https://aws.amazon.com/blogs/security/how-to-optimize-and-visualize-your-security-groups/)
2. [intrusion-detection-and-prevention-with-aws-lambda-and-dynamodb-streams](https://mysteriouscode.io/blog/intrusion-detection-and-prevention-with-aws-lambda-and-dynamodb-streams/)
3. [how-to-facilitate-data-analysis-and-fulfill-security-requirements-by-using-centralized-flow-log-data](https://aws.amazon.com/blogs/security/how-to-facilitate-data-analysis-and-fulfill-security-requirements-by-using-centralized-flow-log-data/)
4. [how-to-visualize-and-refine-your-networks-security-by-adding-security-group-ids-to-your-vpc-flow-logs](https://aws.amazon.com/blogs/security/how-to-visualize-and-refine-your-networks-security-by-adding-security-group-ids-to-your-vpc-flow-logs/)
5. [classifying-api-calls[(https://github.com/monkeysecurity/aws_api_classifier)

