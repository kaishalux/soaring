## Soaring Macie Findings Integration
<<<<<<< HEAD
## ingest macie findings and route to context adder

import boto3
import os
import datetime
import json


def lambda_handler(event):
    
    # create an STS client object that represents a live connection to the 
    # STS service
    sts_client = boto3.client('sts')

    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object=sts_client.assume_role(
        RoleArn="arn:aws:iam::659855141795:role/soaring-lambda-dev",
        RoleSessionName="MacieFindingsTest"
    )

    # From the response that contains the assumed role, get the temporary 
    # credentials that can be used to make subsequent API calls
    credentials=assumed_role_object['Credentials']

    # Use the temporary credentials that AssumeRole returns to make a 
    # connection to Amazon Macie
    macie_client = boto3.client(
        'macie2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    date_time = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S%Z")

    event_id           = event['id']
    acct_id             = event['account']
    scan_bucket_name   = event['detail']['requestParameters']['bucketName']
    
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
                }],
                'scoping': {
                    'includes': {
                        'and': [{
                            'tagScopeTerm': {
                                'comparator': 'EQ',
                                'key': 'TAG',
                                'tagValues': [{
                                        'key': 'WorkflowId',
                                        'value': event_id 
                                }],
                                'target': 'S3_OBJECT'
                            }
                        }]
                    }
                }
            }
        )
    except Exception as e:
        print(f'Could not scan bucket {scan_bucket_name}')
        print(e)
        return


    macie_job = {
        "bucketName": scan_bucket_name,
        "macieJobArn": response['jobArn'],
        "macieJobId": response['jobId'],
        "jobStatus": "INCOMPLETE"
    }
    
    event['macieJobs'].append(macie_job)

    return event


## IMPORTANT - comment out this section when deploying to Lambda
filename = "message.txt"
with open(filename, "r") as f:
    cloud_event = json.load(f)

print(json.dumps(lambda_handler(cloud_event), sort_keys=False, indent=4))
=======
## ingest macie findings and route to context adder 

>>>>>>> c9a117806eaaf5c13f5b93384da991cfbc5ac42e
