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
    

    ## Get Basic Event Attributes    
    account_source  = cloud_event['source']
    account_id      = cloud_event['account']
    account_region  = cloud_event['region']

    detail          = cloud_event['detail'] 
    event_id        = detail['eventID']
    action_type     = detail['eventType']
    # policy_actions  = detail['policyDetails']['action']
    # api_type        = policy_actions['apiCallDetails']['api']
    user_identity   = detail['userIdentity']
    user_type       = user_identity['type']
    user_name       = user_identity['sessionContext']['sessionIssuer']['userName']
    
    

    ## Get Affected Resources Metadata
    resources               = detail['resources']
    resource_list           = []
    resource_list_sensitive = []
    resource_list_canary    = []

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
        rname = resource_type + " '" + resource_name + "'"

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

    
    

    ## Generate event descriptions based on event type and contexts
    # include info about resources + PII data
    
    ## first see if there is an AWS::S3::Bucket and check its tags
    ## if the tags contain either of event_types, set the finding_type and event_desc accordingly
    ## event_types   = ["SensitiveData-PII", "CanaryBucket"]
    ## finding_types = ["TTPs/Initial Access", "Sensitive Data Identifications/PII"]
    
    n_resources     = len(resource_list)
    descriptions    = []
    finding_types   = []

    event_description    = "There was an attempted " + action_type + " on your secure S3 resources. " \
        + str(n_resources) + " resources are affected."
    event_desc_sensitive = "Sensitive data containing PII, stored in the resources [" \
        + ", ".join(resource_list_sensitive) + "] may have been compromised."
    event_desc_canary    = "One or more canaries [" + ", ".join(resource_list_canary) + "] may have been compromised."

    descriptions.append(event_description)

    if (len(resource_list_sensitive) > 0):
        descriptions.append(event_desc_sensitive)
        finding_types.append("Sensitive Data Identifications/PII")

    if (len(resource_list_canary) > 0):
        descriptions.append(event_desc_canary)
        finding_types.append("TTPs/Initial Access")
    
    description = " ".join(descriptions)



    ## Add Additional SecurityHub Finding Metadata
    # arn                 = detail['resourcesAffected']['s3Bucket']['arn']
    # bucket_name         = detail['resourcesAffected']['s3Bucket']['name']
    title               = "Attempted AWS API Call on S3 resources"
    product_arn         = "arn:aws:securityhub:" + account_region + ":" + account_id + ":" + "product/soaring/v1"
    finding_id          = "/".join([account_region, account_id, event_id])          # Id
    sources             = account_source.split(".")
    generator_id        = "-".join([sources[0], sources[1], cloud_event['id']])  # GeneratorId
    
    

    ## Calculate advanced severity score (TODO)
    # severity_score      = detail['severity']['score']
    # severity_desc       = detail['severity']['description']
    severity = {
            "score": 6,
            "description": "Medium"
    }
    severity_score      = severity['score']
    severity_desc       = severity['description']
    


    ## Get event timestamp
    ## the three timestamps may be different in the Macie findings
    first_observed_at   = detail['eventTime']                                   # when the event was first observed (event created at)
    updated_at          = detail['eventTime']                                   # when the event was updated
    created_at          = datetime.utcnow().isoformat() + "Z"                   # when THIS finding was created (time now)
    


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
        "Title"             : title, 
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


    # TODO: add the following
    # - macie logic
    # - ip lookup
    # - advanced severity score

    # macie fields to add: 
    # severity - macie severity
    # financial information, personal information
    # resources affected --> Public access
    # tags --> SensitiveDataClassification
    
    # take the job id and go to macie and get the result 
    # get the macie client 
    # boto3.getfinding of job ... good luck talia
    
    return finding

filename = "message.txt"
with open(filename, "r") as f:
    cloud_event = json.load(f)

print(json.dumps(lambda_handler(cloud_event), sort_keys=False, indent=4))