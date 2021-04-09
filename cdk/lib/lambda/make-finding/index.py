import json
from datetime import datetime

def get_static_map_url(ip_lat, ip_long):

    # with open("api_access.json", "r") as f:
    #     api_access = json.load(f)
    
    url_prefix      = "https://maps.googleapis.com/maps/api/staticmap?"
    map_center      = str(ip_lat) + "," + str(ip_long)
    map_zoom        = 9
    map_width       = 600
    map_height      = 400
    map_scale       = 1
    key             = "AIzaSyA6mPDpj5h6x4MWi842vsLdEWqIYKHKE8A"
    
    map_url         = url_prefix + "center=" + map_center + "&zoom=" + str(map_zoom) \
                        + "&size=" + str(map_width) + "x" + str(map_height) \
                        + "&scale=" + str(map_scale) \
                        + "&markers=" + map_center \
                        + "&key=" + key

    return map_url

def lambda_handler (event, __context):

    ## Get refs to macie finding and original cloud event
    macie_finding = event
    
    cloud_event = macie_finding['originalEvent']


    # get account information from macie finding
    account_id = macie_finding['accountId']
    account_region = macie_finding['region']
    title = macie_finding['title']
    macie_type = macie_finding['type']

    classification_details = macie_finding['classificationDetails']
    job_arn = classification_details['jobArn']
    job_id = classification_details['jobId']


    ## Get Basic Event Attributes
    account_source  = cloud_event['source']
    detail          = cloud_event['detail'] 
    event_id        = detail['eventID']
    action_type     = detail['eventType']
    user_identity   = detail['userIdentity']
    user_type       = user_identity['type']
    user_name       = user_identity['sessionContext']['sessionIssuer']['userName']
    # user_groups     = detail['userGroups']
    
    
    ## Get Affected Resources Metadata
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
    
    
    ## CATEGORISE AFFECTED RESOURCES BASED ON TAGS
    resource_list = [] 
    resource_list_sensitive = [] 
    resource_list_canary = [] 

    for resource_key in macie_finding['resourcesAffected']: 
        
        resource_details = macie_finding['resourcesAffected'][resource_key]
        
        tags = resource_details['tags']
        
        # PUBLIC or NOT_PUBLIC
        if (resource_key == "s3Bucket"): 
            bucket_permission = resource_details['publicAccess']['effectivePermission']
            rname = resource_details['name']
        
        if (resource_key == "s3Object"):
            rname = resource_details['key']
        
        if (len(tags) > 0):
            for tag in tags:
                # key = t['key']
                # value = t['value']
                
                # tag = { 
                #     "key": key, 
                #     "value": value
                # }
                if (tag['key'] == "SensitiveDataClassification" and tag['value'] == "PII"):
                    resource_list_sensitive.append(rname)
                if (tag['key'] == "DataSecurityClassification" and tag['value'] == "CanaryBucket"):
                    resource_list_canary.append(rname)
            
        resource_list.append(rname)

    
    
    
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
    # descriptions.append(event_description)

    event_description_type    = f"There was an attempted {action_type} on your secure S3 resources ({str(n_resources)} resources are affected)."
    descriptions.append(event_description_type)

    if (len(resource_list_sensitive) > 0):
        sensitive_list_str      = ", ".join(resource_list_sensitive)
        event_desc_sensitive    = f"Sensitive PII data stored in the S3 bucket [{sensitive_list_str}] may have been compromised."
        descriptions.append(event_desc_sensitive)
        finding_types.append("Sensitive Data Identifications/PII")

    if (len(resource_list_canary) > 0):
        canary_list_str     = ", ".join(resource_list_canary)
        event_desc_canary   = f"One or more canaries [{canary_list_str}] may have been compromised."
        descriptions.append(event_desc_canary)
        finding_types.append("TTPs/Initial Access")
    
    long_description = " ".join(descriptions)

    job_arn = macie_finding['classificationDetails']['jobArn']


    # macie severity score 
    severity_desc = macie_finding['severity']['description']
    severity_score = macie_finding['severity']['score']



    ## Add Additional SecurityHub Finding Metadata
    product_arn         = "arn:aws:securityhub:" + account_region + ":" + account_id + ":" + "product/soaring/v2"
    finding_id          = "/".join([account_region, account_id, event_id])          # Id
    sources             = account_source.split(".")
    generator_id        = "-".join([sources[0], sources[1], cloud_event['id']])     # GeneratorId
    
    ## Get event timestamp
    ## the three timestamps may be different in the Macie findings
    first_observed_at   = detail['eventTime']                                     # when the event was first observed (event created at)
    updated_at          = macie_finding['updatedAt']                              # when the event was updated
    created_at          = datetime.utcnow().isoformat() + "Z"                     # when THIS finding was created (time now)


    # TODO: Add IP address details from Gordon's geolocation lambda
    
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
    
    
    
    ## output as json in AWS Security Findings Format
    ## Accountid, timestamp (CreatedAt and FirstObservedAt), description, resources (resourceID, resourceType), severity, title and types
    finding = {
        "AwsAccountId"      : account_id,
        "CreatedAt"         : created_at,
        "Description"       : event_description,
        "GeneratorId"       : generator_id,
        "Id"                : finding_id, 
        "ProductArn"        : product_arn,  
        "SchemaVersion"     : "2018-10-08",
        "Resources" : [
            { 
                "Type" : "AwsS3Bucket",
                "Id"   : bucket_arn, 
                "Partition" : "aws", 
                "Region"  : account_region
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
            "DataClassification" : data_classification,
            "UserIdentity"      : {
                "userName"          : user_name,
                "userType"          : user_type,
                "userIP"            : ip_address,
                "userCity"          : ip_city,
                "userCountry"       : ip_country,
                "userCoords"        : str(ip_lat + ip_long),
                "userMap"           : map_url
            },
            # "UserGroups"        : user_groups,
            "BucketInfo"        : { 
                "bucketName"        : bucket_name,
                "bucketOwner"       : bucket_owner,
                "s3object"          : s3Object,
                "bucketPermission"  : bucket_permission
            },
            "LongDescription"   : long_description
        }
    }

    return finding