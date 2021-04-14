import boto3
from datetime import datetime

def lambda_handler(event, _context):
    """
    Handles input/output for Lambda - do all logic in separate functions
    """
    ### Soaring Contextual Engine
    ### Geo IP Lookup

    ## Open CloudTrail event in JSON format
    cloud_event = event
    job_id = cloud_event['macieJobs']['macieJobId']
    
    # print("Looking for Macie job " + job_id)

    ## MAKE CONNECTION WITH MACIE
    macie_client = boto3.client('macie2')
    

    ## QUERY MACIE FOR FINDING IDS 
    paginator = macie_client.get_paginator('list_findings')    
    page_iterator = paginator.paginate(
        findingCriteria = {
            'criterion': {
                'classificationDetails.jobId': {
                    'eq': [job_id]
                }
            }
        }
    )
    
    ## GET FINDING FROM MACIE
    for page in page_iterator:
        findings_list = page['findingIds']
        findings = macie_client.get_findings(findingIds=findings_list)
    
    macie_finding = findings['findings'][0]
    # print(macie_finding)
    

    ## GENERATE NEW EVENT FROM COMBINED EVENTS 
    new_finding = macie_finding
    new_finding['createdAt'] = new_finding['createdAt'].isoformat() + "Z"
    new_finding['resourcesAffected']['s3Bucket']['createdAt'] = new_finding['resourcesAffected']['s3Bucket']['createdAt'].isoformat() + "Z"
    new_finding['resourcesAffected']['s3Object']['lastModified'] = new_finding['resourcesAffected']['s3Object']['lastModified'].isoformat() + "Z"
    new_finding['updatedAt'] = new_finding['updatedAt'].isoformat() + "Z"
    
    if ('macieJobs' in cloud_event):
        del(cloud_event['macieJobs'])

    new_finding['originalEvent'] = cloud_event

    return new_finding