## Soaring - Ingest Event

import boto3
from botocore.retries import bucket

def lambda_handler(event, _context):

    ## Analyse S3 tags for canary bucket (or not) 
    ## event.soaringEventType   = CANARY, PII, OTHER
    ##      if CANARY:  skip Macie job
    ##      if PII:     run Macie job
    ##      if OTHER:   exit at EventTypeChoice

    ## event.soaringBucketType  = CANARY, PII, OTHER
    ## determines severity classifications
    ##      if CANARY:  -> match pattern  'is_canary_bucket'    with > 1
    ##                  -> would alert on baseline
    ##                  -> increased by cofactor (user_not_in_zone)
    ##      if PII:     -> match pattern  'is_pii_bucket'       with < 1
    ##                  -> would NOT alert on baseline
    ##                  -> unless increased by cofactors (user_not_in_zone or is_public_bucket)
    ##      if OTHER:   -> match pattern  'is_non_pii_bucket'   with > 1
    ##                  -> would alert on baseline, increased by cofactors (user_not_in_zone or is_public_bucket)
    
    ingested_event          = event
    event_name              = ingested_event['detail']['eventName']
    bucket_name             = ingested_event['detail']['requestParameters']['bucketName']
    soaring_event_type      = "PII"
    soaring_bucket_type     = "OTHER"

    
    ## connect to S3 and get tags for the affected bucket
    s3 = boto3.resource('s3')
    bucket_tagging = s3.BucketTagging(bucket_name)
    tag_set = bucket_tagging.tag_set
  
    for tag in tag_set:
        if (tag['Key'] == "DataSecurityClassification" and tag['Value'] == "CanaryBucket"):
            soaring_event_type = "CANARY"
            soaring_bucket_type = "CANARY"
        elif (tag['Key'] == "SensitiveDataClassification" and tag['Value'] == "PII"):
            soaring_bucket_type = "PII"
    
    if (soaring_bucket_type != "CANARY" and event_name == "ListObjects"):
        soaring_event_type = "OTHER"

    ## return modified event containing event type
    ingested_event['soaringEventType']      = soaring_event_type
    ingested_event['soaringBucketType']     = soaring_bucket_type
    ingested_event['detail']['bucketTags']  = tag_set

    return ingested_event