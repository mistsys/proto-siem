# Centralized Security Logging SIEM

A comprehensive log management and analysis solution that can be used to analyze events
that could affect the security of the infrastructure and take actions. With multiple account and services provisioned, the amount and variety of logs can include service-specific metrics and log files, additional data, such as API calls, configuration changes etc.. Log files from web servers, applications, and operating systems also provide valuable data, though in different formats, and in a random and distributed fashion. The aim is to effectively consolidate, manage, and analyze these different logs 

## Getting Started

Requirement for getting started with deploying the solution.

## Prerequisites

Required Resources

## Installing

Steps for deploying Kibana Template

  To install the Kibana Index Mapping:
    
    1. Use the Development Console in AWS ElasticSearch Kibana Console to access templates
    
    2. Run Command GET /_template to retrieve all available templates
    
    3. If reindexing is required use the command curl -XDELETE 'http://YOUR_ES_DOMAIN_ENDPOINT/cwl*/' to delete any previous
       indexes
    
    4. Finally, Use PUT _template/template_1 and append the template data from KibanaTemplate.json file
   
   Note: This template is required for changing type of certain fields to the desired value which is not captured by
   ES by default (location type as geo_point and packets type as long)

## Running Tests

## Additional Deployment Notes

## Contributors

## Acknowledgements
