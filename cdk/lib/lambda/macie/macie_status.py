## Checks if macie job is complete 

# import sys
import boto3
import json
from botocore.exceptions import ClientError

macie_client = boto3.client('macie2')

def lambda_handler(event, _context):

    job_id = event['macieJobs']['macieJobId']
    try:
        response = macie_client.describe_classification_job(jobId = job_id)
    except Exception as e:
        print(f'Job not completed {job_id}')
        print(e)
        return

    event['macieJobs']['jobStatus'] = response['jobStatus']
    return event