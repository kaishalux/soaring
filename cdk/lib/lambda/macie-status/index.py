## Checks if macie job is complete 

# import sys
import boto3
from botocore.exceptions import ClientError

macie_client = boto3.client('macie2')

def lambda_handler(event, _context):

    job_id = event['macieJobs']['macieJobId']
    try:
        response = macie_client.describe_classification_job(jobId = job_id)
        event['macieJobs']['jobStatus'] = response['jobStatus']

    except Exception as e:
        print(e)
        return
    
    return event