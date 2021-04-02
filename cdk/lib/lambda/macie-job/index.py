## Soaring Macie Findings Integration
## ingest macie findings and route to context adder

import boto3
import datetime
# import json


def lambda_handler(event, _context):
    
    # make a connection to Amazon Macie
    macie_client = boto3.client('macie2')

    date_time = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S%Z")

    event_id            = event['id']
    acct_id             = event['account']
    scan_bucket_name    = event['detail']['requestParameters']['bucketName']
    
    try:
        response = macie_client.create_classification_job(
            description = 'Scan affected buckets for PII',
            initialRun = True,
            jobType = 'ONE_TIME',
            name = f'Soaring-S3Scan-{date_time}',
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
    
    
    event['macieJobs'] = [macie_job]

    return event



## IMPORTANT - comment out this section when deploying to Lambda
# filename = "message.txt"
# with open(filename, "r") as f:
#     cloud_event = json.load(f)

# lambda_context = {
#     "function_name": "lambda_macie"
# }

# lambda_result = lambda_handler(cloud_event, lambda_context)
# print( json.dumps(lambda_result, sort_keys=False, indent=4) )