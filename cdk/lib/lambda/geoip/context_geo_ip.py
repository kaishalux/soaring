import json
from datetime import datetime

def lambda_handler(event):
    """
    Handles input/output for Lambda - do all logic in separate functions
    """
    ### Soaring Contextual Engine
    ### Geo IP Lookup


    ## Open CloudTrail event in JSON format
    cloud_event = event
    
    ## Basic Attributes:
    ## get event type
    
    account_source  = cloud_event['source']
    account_id      = cloud_event['account']
    account_region  = cloud_event['region']
    
    detail          = cloud_event['detail'] 
    event_id        = detail['eventID']

    # policy_actions  = detail['policyDetails']['action']
    action_type     = detail['eventType']
    # api_type        = policy_actions['apiCallDetails']['api']
    user_identity   = detail['userIdentity']
    user_type       = user_identity['type']
    user_name       = user_identity['sessionContext']['sessionIssuer']['userName']
    
    finding_id      = "/".join([account_region, account_id, event_id])          # Id
    sources         = account_source.split(".")
    generator_id    = "-".join([sources[0], sources[1], cloud_event['id']])  # GeneratorId
    
    resources       = detail['resources']
    resource_list   = []
    resource_list_sensitive = []
    resource_list_canary = []
    # resource_list_names = resources.keys()

    for object in resources:
        
        object_type = object['type']
        object_tags = object['tags']

        if (object_type == "AWS::S3::Object"):
            resource_type = "S3 Object"
            resource_arn = object['ARNPrefix']

        if (object_type == "AWS::S3::Bucket"):
            resource_type = "S3 Bucket"
            resource_arn = object['ARN']
        
        resource_name = resource_arn.split(":")[-1]
        rname = " ".join([resource_type, resource_name])

        resource = {
            "Type": resource_type,
            "Id": resource_arn,
            "Name": resource_name
        }
        
        for tag in object_tags:
            if (tag['key'] == "SensitiveDataClassification" and tag['value'] == "PII"):
                resource_list_sensitive.append(rname)
            if (tag['key'] == "DataSecurityClassification" and tag['value'] == "CanaryBucket"):
                resource_list_canary.append(rname)
        
        resource_list.append(resource)

    n_resources     = len(resource_list)
    ## generate description based on event type and contexts
    # include info about resources + PII data
    
    ## first see if there is an AWS::S3::Bucket
    ## check its tags
    ## if the tags contain either of [event_types] then set the finding_type accordingly
    # event_types   = ["SensitiveData-PII", "CanaryBucket"]
    # finding_types = ["TTPs/Initial Access", "Sensitive Data Identifications/PII"]
    
    descriptions = []
    finding_types = []

    event_description    = "There was an attempted " + action_type + " on your S3 resources. " + str(n_resources) + " resources are affected."
    event_desc_sensitive = "Sensitive data containing PII, stored in the resources ['" + "', '".join(resource_list_sensitive) + "'] may have been compromised."
    event_desc_canary    = "One or more canary buckets ['" + "', '".join(resource_list_canary) + "'] may have been compromised."

    descriptions.append(event_description)

    if (len(resource_list_sensitive) > 0):
        descriptions.append(event_desc_sensitive)
        finding_types.append("Sensitive Data Identifications/PII")

    if (len(resource_list_canary) > 0):
        descriptions.append(event_desc_canary)
        finding_types.append("TTPs/Initial Access")
    
    description = " ".join(descriptions)

    # arn                 = detail['resourcesAffected']['s3Bucket']['arn']
    # bucket_name         = detail['resourcesAffected']['s3Bucket']['name']
    title_encryption    = "Attempted AWS API Call on S3 resources"
    product_arn         = "arn:aws:securityhub:" + account_region + ":" + account_id + ":" + "product/soaring/v1"
    
    ## !TODO ADD SEVERITY SCORE
    # severity_score      = detail['severity']['score']
    # severity_desc       = detail['severity']['description']
    severity = {
            "score": 6,
            "description": "Medium"
    }
    severity_score      = severity['score']
    severity_desc       = severity['description']
    
    ## get date and time from event
    # event_time  = cloud_event['time']               # FirstObservedAt
    first_observed_at   = detail['eventTime']       # when the event was first observed (event created at)
    updated_at          = detail['eventTime']       # when the event was updated
    created_at          = datetime.utcnow().isoformat() + "Z"   # when THIS finding was created (time now)
    
    # IP address details 
    # ip_details  = detail['policyDetails']['actor']['ipAddressDetails']
    ip_details  = {
                    "ipAddressV4": "192.0.2.0",
                    "ipOwner": {
                        "asn": "-1",
                        "asnOrg": "ExampleFindingASNOrg",
                        "isp": "ExampleFindingISP",
                        "org": "ExampleFindingORG"
                    },
                    "ipCountry": {
                        "code": "US",
                        "name": "United States"
                    },
                    "ipCity": {
                        "name": "Ashburn"
                    },
                    "ipGeoLocation": {
                        "lat": 39.0481,
                        "lon": -77.4728
                    }
                }
    ip_address  = ip_details['ipAddressV4']
    ip_country  = ip_details['ipCountry']['name']
    ip_city     = ip_details['ipCity']['name']
    ip_lat      = ip_details['ipGeoLocation']['lat']
    ip_long     = ip_details['ipGeoLocation']['lon']
    
    ## get Google Static Map url
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
    
        
    ## message output in console
    ## comment out when deploying to Lambda
    # print("=== Soaring Alert ===")
    # print("=====================\n")
    
    # print("Finding ID: " + finding_id)
    # print("Account ID: " + account_id + "\n")
    
    # print("There was an attempted " + action_type) 
    # print("at " + event_time + "\n")
    
    # print(str(n_resources) + " resources in your account are affected:")
    # # print(json.dumps(resource_details, indent=4), "\n")
    
    # print("CRITICAL: " + event_desc_sensitive)
    # print(event_desc_encrypted + "\n")
    
    # print("Actor Information:")
    # print("User/role ID:  " + user_identity['assumedRole']['arn'])
    # print("Source IP:     " + ip_address)
    # print("Location:      " + ip_city + ", " + ip_country \
    #     + " (" + str(ip_lat) + "," + str(ip_long) + ")")
    # print("Map URL:       " + map_url)
    # # print("Actors:\n")
    
    
    ## output as json in AWS Security Findings Format
    ## Accountid, timestamp (CreatedAt and FirstObservedAt), description, resources (resourceID, resourceType), severity, title and types
    finding = {
        "CreatedAt"         : created_at,
        "Description"       : description,
        "GeneratorId"       : generator_id,
        "Id"                : finding_id, 
        "ProductArn"        : product_arn,  
        "SchemaVersion"     : "2018-10-08", 
        "AwsAccountId"      : account_id,
        "Region"            : account_region,
        "Resources"         : resource_list,
        "Severity"  : {
            "Label"         : severity_desc, 
            "Original"      : severity_score
        }, 
        "Title"             : title_encryption, 
        "UpdatedAt"         : updated_at,
        "FirstObservedAt"   : first_observed_at,
        "Types"             : finding_types,
        "Note": {
            "UserIdentity" : {
                "userName"      : user_name,
                "userType"      : user_type,
                "userIP"        : ip_address,
                "userCity"      : ip_city,
                "userCountry"   : ip_country,
                "userMap"       : map_url
            }
        }
    }

    # !TODO add the following:
    # - types
    # - user identity info (user ID, IP address, map url)
    # - macie logic
    
    return finding

## IMPORTANT - comment out this section when deploying to Lambda
filename = "eventbridge-s3.txt"
with open(filename, "r") as f:
    cloud_event = json.load(f)

print(json.dumps(lambda_handler(cloud_event), sort_keys=False, indent=4))w