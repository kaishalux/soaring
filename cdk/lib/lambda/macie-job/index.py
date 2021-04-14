## Soaring Macie Findings Integration
## ingest macie findings and route to context adder

import boto3
import datetime
# import json


def lambda_handler(event, _context):
    
    # make a connection to Amazon Macie
    macie_client = boto3.client('macie2')

    print(event)

    date_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%Z")

    acct_id             = event['account']
    scan_bucket_name    = event['detail']['requestParameters']['bucketName']
    
    try:
        response = macie_client.create_classification_job(
            description = 'Scan affected buckets for PII',
            initialRun = True,
            jobType = 'ONE_TIME',
            name = f'Soaring-S3Scan-{scan_bucket_name}-{date_time}',
            s3JobDefinition = {
                'bucketDefinitions': [{
                    'accountId': acct_id, 
                    'buckets': [scan_bucket_name]
                }]
            }
        )
    except Exception as e:
        print(f'Could not scan bucket {scan_bucket_name}')
        raise e
    

    macie_job = {
        "bucketName":   scan_bucket_name,
        "macieJobArn":  response['jobArn'],
        "macieJobId":   response['jobId'],
        "jobStatus":    "INCOMPLETE"
    }
    
    
    event['macieJobs'] = macie_job

    return event