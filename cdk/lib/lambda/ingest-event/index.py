## Soaring - Ingest Event

import boto3
from botocore.retries import bucket

def lambda_handler(event, _context):

    ## Analyse S3 tags for canary bucket (or not) 
    ## if canary bucket : event.eventType = CANARY
    ## if not canary    : event.eventType = PII
    ingested_event  = event
    bucket_name     = ingested_event['detail']['requestParameters']['bucketName']
    event_type      = "PII"

    
    ## connect to S3 and get tags for the affected bucket 
    s3 = boto3.resource('s3')
    bucket_tagging = s3.BucketTagging(bucket_name)
    tag_set = bucket_tagging.tag_set()
  
    for tag_list in tag_set:
        for tag in tag_list:
            if (tag['key'] == "DataSecurityClassification" and tag['value'] == "CanaryBucket"):
                event_type = "CANARY"


    ## return modified event containing event type
    ingested_event["eventType"] = event_type

    return ingested_event