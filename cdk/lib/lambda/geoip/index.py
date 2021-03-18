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
    event_id        = detail['id']

    policy_actions  = detail['policyDetails']['action']
    action_type     = policy_actions['actionType']
    api_type        = policy_actions['apiCallDetails']['api']
    user_identity   = detail['policyDetails']['actor']['userIdentity']
    
    finding_id      = "/".join([account_region, account_id, event_id])          # Id
    sources         = account_source.split(".")
    generator_id    = "-".join([sources[0], sources[1], cloud_event['id']])  # GeneratorId
    
    resources       = detail['resourcesAffected']
    resource_list   = []
    resource_list_names = resources.keys()

    for key in resources:
        
        value = resources[key]
        if (value is None): 
            resource_id = "unknown"
            resource_name = "unknown"
        else:
            resource_id = value['arn']
            resource_name = value['name']
        
        resource = {
            "Type": key,
            "Id": resource_id,
            "Name": resource_name
        }
        
        resource_list.append(resource)

    n_resources     = len(resource_list)

    arn                 = detail['resourcesAffected']['s3Bucket']['arn']
    bucket_name         = detail['resourcesAffected']['s3Bucket']['name']
    title_encryption    = detail['title']
    
    severity_score      = detail['severity']['score']
    severity_desc       = detail['severity']['description']
    
    ## get date and time from event
    event_time  = cloud_event['time']               # FirstObservedAt
    first_observed_at   = detail['createdAt']       # when the event was first observed (event created at)
    updated_at          = detail['updatedAt']       # when the event was updated
    created_at          = datetime.utcnow().isoformat() + "Z"   # when THIS finding was created (time now)
    
    # IP address details 
    ip_details  = detail['policyDetails']['actor']['ipAddressDetails']
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
    
    
    ## generate description based on event type and contexts
    # include info about resources + PII data
    event_description = "There was an attempted " + action_type + ". " + str(n_resources) + " resources are affected."
    event_desc_sensitive = "Sensitive data containing PII, stored in the resources ['" + "', '".join(resource_list_names) + "'] is at risk of compromise."
    event_desc_encrypted = detail['description']
    
    description = " ".join([event_description, event_desc_sensitive, event_desc_encrypted])
    
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
        "ProductArn"        : arn,
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
        "FirstObservedAt"   : first_observed_at
        #"Types"            : # no idea 
    }

    # !TODO add the following:
    # - types
    # - user identity info (user ID, IP address, map url)
    # - macie logic
    
    return finding