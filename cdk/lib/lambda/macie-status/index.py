## Checks if macie job is complete 

# import sys
import boto3
from botocore.exceptions import ClientError

macie_client = boto3.client('macie2')

def lambda_handler(event, _context):

    job_id = event['Payload']['macieJobs'][-1]['macieJobId']
    try:
        response = macie_client.describe_classification_job(jobId = job_id)

        status = response['jobStatus']
        if (status == "COMPLETE"):
            print(f'Job {job_id} is complete!')
        else:
            print(f'Job {job_id} is not complete: Status is {status}')

    except Exception as e:
        print(e)
        return
    
    for job in event['Payload']['macieJobs']:
        if (job['macieJobId'] == job_id):
            job['jobStatus'] = response['jobStatus']
    
    return event