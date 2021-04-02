import boto3
import json
from datetime import datetime

def get_static_map_url(ip_lat, ip_long):

    with open("api_access.json", "r") as f:
        api_access = json.load(f)
    
    url_prefix      = "https://maps.googleapis.com/maps/api/staticmap?"
    map_center      = str(ip_lat) + "," + str(ip_long)
    map_zoom        = 9
    map_width       = 600
    map_height      = 400
    map_scale       = 1
    key             = api_access['gcp-static-maps']['key']
    
    map_url         = url_prefix + "center=" + map_center + "&zoom=" + str(map_zoom) \
                        + "&size=" + str(map_width) + "x" + str(map_height) \
                        + "&scale=" + str(map_scale) \
                        + "&markers=" + map_center \
                        + "&key=" + key

    return map_url


def lambda_handler(event, _context):
    """
    Handles input/output for Lambda - do all logic in separate functions
    """
    ### Soaring Contextual Engine
    ### Geo IP Lookup

    ## Open CloudTrail event in JSON format
    cloud_event = event
    job_id = cloud_event['macieJobs'][-1]['macieJobId']
    
    print("Looking for Macie finding " + job_id)

    # make connection with macie 
    macie_client = boto3.client('macie2')
    macie_finding = macie_client.get_findings(
    findingIds = [
        job_id
    ])

    # get account information from macie finding
    account_id = macie_finding['accountId']
    account_region = macie_finding['region']
    title = macie_finding['title']
    macie_type = macie_finding['type']

    classification_details = macie_finding['classificationDetails']
    job_arn = classification_details['jobArn']
    job_id = classification_details['jobId']

    ## Get Basic Event Attributes    - double check that this is in message.txt
    account_source  = cloud_event['source']
    detail          = cloud_event['detail'] 
    event_id        = detail['eventID']
    action_type     = detail['eventType']
    user_identity   = detail['userIdentity']
    user_type       = user_identity['type']
    user_name       = user_identity['sessionContext']['sessionIssuer']['userName']
    
    # initialise lists
    detections_list = [] 
    cells_list      = []

    # get sensitive data from macie finding
    
    sensitive_data = macie_finding['classificationDetails']['result']['sensitiveData']
    sensitive_data_list = []

    # for obj in sensitive_data: 
    #     object_category = obj['category']
    #     object_detections = obj['detections']
    #     sensitive_data = {
    #         "category": object_category,
    #         "detections": object_detections
    #     }

        
    #     for detections in object_detections: 
    #         count = detections['count']
    #         occurrences = detections['occurrences']

    #         for cells in occurrences: 
    #             cell_reference = occurrences['cellReference']
    #             column = occurrences['column']
    #             column_name = occurrences['columnName']
    #             row = occurrences['row']
    #             cells = { 
    #                 "cellReference": cell_reference, 
    #                 "column": column, 
    #                 "columnName": column_name, 
    #                 "row": row
    #             }
    #             cells_list.append(cells)
            
    #         detection_type = detections['type']

    #         detections = { 
    #             "count" : count, 
    #             "occurrences" : occurrences_list, 
    #             "type" : detection_type
    #         }

    #         detections_list.append(detections)

    #     sensitive_data_list.append(sensitive_data)
    
    # size = macie_finding['sizeClassified']
    
    
    # ## Get Affected Resources Metadata
    data_classification = macie_finding['classificationDetails']['result']

    bucket_info = macie_finding['resourcesAffected']['s3Bucket']
    bucket_name = bucket_info['name']
    bucket_owner = bucket_info['owner']['displayName']
    bucket_arn = bucket_info['arn']
    
    bucket_object = macie_finding['resourcesAffected']['s3Object']
    object_etag = bucket_object['eTag']
    object_key = bucket_object['key']

    s3Object = { 
        "bucketArn" : bucket_arn,
        "eTag" : object_etag, 
        "key" : object_key
    }
    
    
    resource_list = [] 
    resource_list_sensitive = [] 
    resource_list_canary = [] 
    

    for obj_key, obj_value in macie_finding['resourcesAffected']: 
        
        tags = obj_value['tags']

        # PUBLIC or NOT_PUBLIC
        if (obj_key == "S3Bucket"): 
            bucket_permission = obj_value['publicAccess']['effectivePermission']
            rname = obj_value['name']
        
        if (obj_key == "S3Object"):
            rname = obj_value['key']
        
        if (len(tags) > 0):
            for tag in tags:
                # key = t['key']
                # value = t['value']
                
                # tag = { 
                #     "key": key, 
                #     "value": value
                # }

                if (tag['key'] == "SensitiveDataClassification" and tag['value'] == "PII"):
                    resource_list_sensitive.append(obj_key)
                if (tag['key'] == "DataSecurityClassification" and tag['value'] == "CanaryBucket"):
                    resource_list_canary.append(obj_key)
            
        resource_list.append(obj_key)

    
    # macie severity score 
    severity_desc = macie_finding['severity']['description']
    severity_score = macie_finding['severity']['score']
    
    ## Generate event descriptions based on event type and contexts
    # include info about resources + PII data
    
    ## first see if there is an AWS::S3::Bucket and check its tags
    ## if the tags contain either of event_types, set the finding_type and event_desc accordingly
    # event_types   = ["SensitiveData-PII", "CanaryBucket"]
    # finding_types = ["TTPs/Initial Access", "Sensitive Data Identifications/PII"]

    n_resources     = len(resource_list)
    descriptions    = []
    finding_types   = []

    #description from macie finding 
    event_description = macie_finding['description']
    descriptions.append(event_description)

    event_description_type    = "There was an attempted " + action_type + " on your secure S3 resources. " \
        + str(n_resources) + " resources are affected."
    descriptions.append(event_description_type)

    if (len(resource_list_sensitive) > 0):
        event_desc_sensitive = "Sensitive data containing PII, stored in the resources [" \
            + ", ".join(resource_list_sensitive) + "] may have been compromised."
        descriptions.append(event_desc_sensitive)
        finding_types.append("Sensitive Data Identifications/PII")

    if (len(resource_list_canary) > 0):
        event_desc_canary    = "One or more canaries [" + ", ".join(resource_list_canary) + "] may have been compromised."
        descriptions.append(event_desc_canary)
        finding_types.append("TTPs/Initial Access")
    
    description = " ".join(descriptions)

    job_arn = macie_finding['classificationDetails']['jobArn']

    ## Add Additional SecurityHub Finding Metadata
    product_arn         = "arn:aws:securityhub:" + account_region + ":" + account_id + ":" + "product/soaring/v2"
    finding_id          = "/".join([account_region, account_id, event_id])          # Id
    sources             = account_source.split(".")
    generator_id        = "-".join([sources[0], sources[1], cloud_event['id']])     # GeneratorId
    
    ## Get event timestamp
    ## the three timestamps may be different in the Macie findings
    first_observed_at   = detail['eventTime']                                     # when the event was first observed (event created at)
    updated_at          = macie_finding['updatedAt']                                # when the event was updated
    created_at          = datetime.utcnow().isoformat() + "Z"                       # when THIS finding was created (time now)

    # IP address details
    # ip_details  = detail['policyDetails']['actor']['ipAddressDetails']
    ip_details  = {
        "ipAddressV4": "13.210.232.8",
        "ipOwner": {
            "asn": "AS16509",
            "asnOrg": "Amazon.com, Inc.",
            "isp": "Amazon Technologies Inc.",
            "org": "AWS EC2 (ap-southeast-2)"
        },
        "ipCountry": {
            "code": "AU",
            "name": "Australia"
        },
        "ipCity": {
            "name": "Sydney"
        },
        "ipGeoLocation": {
            "lat": -33.8591,
            "lon": 151.2002
        }
    }

    ip_address  = ip_details['ipAddressV4']
    ip_country  = ip_details['ipCountry']['name']
    ip_city     = ip_details['ipCity']['name']
    ip_lat      = ip_details['ipGeoLocation']['lat']
    ip_long     = ip_details['ipGeoLocation']['lon']
    
    ## get Google Static Map url
    map_url     = get_static_map_url(ip_lat, ip_long)
    
    
    
    ## TODO: move this part into a separate lambda (at the end of the SFN)
    
    ## output as json in AWS Security Findings Format
    ## Accountid, timestamp (CreatedAt and FirstObservedAt), description, resources (resourceID, resourceType), severity, title and types
    finding = {
        "AwsAccountId"      : account_id,
        "CreatedAt"         : created_at,
        "Description"       : description,
        "GeneratorId"       : generator_id,
        "Id"                : finding_id, 
        "ProductArn"        : product_arn,  
        "SchemaVersion"     : "2018-10-08",
        "Resources" : [
            { 
                "Type" : "AwsS3Bucket",
                "Id"   : bucket_arn, 
                "Partition" : "aws", 
                "Region"  : account_region,
                "DataClassification" : data_classification
            }
        ],
        "Severity"  : {
            "Label"         : severity_desc, 
            "Original"      : severity_score
        }, 
        "Title"             : title, 
        "Types"             : finding_types,
        "UpdatedAt"         : updated_at,
        "FirstObservedAt"   : first_observed_at,
        "ProductFields": {
            "UserIdentity" : {
                "userName"      : user_name,
                "userType"      : user_type,
                "userIP"        : ip_address,
                "userCity"      : ip_city,
                "userCountry"   : ip_country,
                "userCoords"    : str(ip_lat + ip_long),
                "userMap"       : map_url
            }, 
           "bucketInfo" : { 
            "bucketName"        : bucket_name,
            "bucketOwner"       : bucket_owner,
            "s3object"          : s3Object,
            "bucketPermission"  : bucket_permission
           }
        }
    }
    return finding


# ## IMPORTANT - comment out this section when deploying to Lambda
# filename = "message-soaring-after-job"
# with open(filename, "r") as f:
#     cloud_event = json.load(f)

# lambda_context = {
#     "function_name": "lambda_macie"
# }

# lambda_result = lambda_handler(cloud_event, lambda_context)
# print( json.dumps(lambda_result, sort_keys=False, indent=4) )
