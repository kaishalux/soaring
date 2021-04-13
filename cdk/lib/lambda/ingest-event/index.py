## Soaring - Ingest Event

import boto3

def lambda_handler(event, _context):

    ingested_event = event

    ## TODO: add logic to analyse S3 tags for canary bucket (or not) 
    ## if canary bucket : event.macieJobs.macieStatus = NOT_REQUIRED
    ## if not canary    : event.macieJobs.macieStatus = REQUIRED
    
    scan_bucket_name    = event['detail']['requestParameters']['bucketName']
    
    macie_job = {
        "bucketName":   scan_bucket_name,
        "jobStatus":    "REQUIRED"
    }

    return ingested_event