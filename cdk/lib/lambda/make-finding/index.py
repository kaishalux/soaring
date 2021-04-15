import json
import boto3
import base64
from botocore.exceptions import ClientError
from datetime import datetime


def get_secret():

    secret_name = "gcp-static-maps"
    region_name = "ap-southeast-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
            


def get_static_map_url(ip_lat, ip_long):
    
    url_prefix      = "https://maps.googleapis.com/maps/api/staticmap?"
    map_center      = str(ip_lat) + "," + str(ip_long)
    map_zoom        = 9
    map_width       = 600
    map_height      = 400
    map_scale       = 1
    key             = json.loads(get_secret())['gcp-static-maps']
    
    map_url         = url_prefix + "center=" + map_center + "&zoom=" + str(map_zoom) \
                        + "&size=" + str(map_width) + "x" + str(map_height) \
                        + "&scale=" + str(map_scale) \
                        + "&markers=" + map_center \
                        + "&key=" + key
    
    return map_url

def lambda_handler (event, __context):

    combined_event = event
    soaring_event_type  = combined_event['soaringEventType']


    # Get account information from Macie finding
    account_id      = combined_event['account']
    account_region  = combined_event['region']
    account_source  = combined_event['source']


    ## Get basic event attributes
    detail          = combined_event['detail']
    event_id        = detail['eventID']
    action_type     = detail['eventType']

    if (action_type == "AwsApiCall"): 
        action_type = "AWSAPICall"


    ## Get user identity attributes
    user_identity       = detail['userIdentity']
    user_groups_set     = detail['userGroups']
    user_policies_set   = detail['userPolicies']
    role_policies_set   = detail['rolePolicies']
    user_type           = user_identity['type']
    user_name           = user_identity['arn'].split(':')[-1]

    if (user_type == "AssumedRole"):  
        user_name = "/".join(user_name.split("/")[-2:])

    ## Find user groups, policies, role policies
    user_groups_list, user_group_policies_list, user_policies_list, role_policies_list = ([] for i in range(4))

    if (len(user_groups_set) > 0):
        for group in user_groups_set:
            
            user_groups_list.append(group['GroupName'])
            
            for policy in group['Policies']:
                user_group_policies_list.append(policy['PolicyName'])
    
    if (len(user_policies_set) > 0):
        for policy in user_policies_set:
            user_policies_list.append(policy['PolicyName'])

    if (len(role_policies_set) > 0):
        for policy in role_policies_set:
            role_policies_list.append(policy['PolicyName'])

    user_groups         = ", ".join(user_groups_list)
    user_group_policies = ", ".join(user_group_policies_list)
    user_policies       = ", ".join(user_policies_list)
    role_policies       = ", ".join(role_policies_list)
    

    # Get severity score 
    severity_desc   = combined_event['severity']['severity']['description']
    severity_score  = combined_event['severity']['severity']['score']
    should_alert    = combined_event['severity']['shouldAlert']
    matches         = combined_event['severity']['matches']
    severity_matches_list = []
    
    for match in matches:
        desc = match['description']
        
        for cofactor in match['cofactors']:
            desc = f"{desc} ({cofactor['description']})"
        
        severity_matches_list.append(desc)
    
    severity_matches = ", ".join(severity_matches_list)
    

    ## Add Additional SecurityHub Finding Metadata
    product_name        = "soaring"
    product_version     = "v1-0"
    product_arn         = f"arn:aws:securityhub:{account_region}:{account_id}:product/{account_id}/default"
    sh_finding_id       = "/".join([account_region, account_id, event_id])
    sources             = account_source.split(".")
    generator_id        = "-".join([sources[0], sources[1], combined_event['id']])
    

    ## Get event timestamps
    first_observed_at   = detail['eventTime']
    updated_at          = datetime.utcnow().isoformat() + "Z"
    created_at          = datetime.utcnow().isoformat() + "Z"


    ## Get affected resources metadata
    bucket_name             = detail['requestParameters']['bucketName']
    bucket_arn              = "arn:aws:s3:::" + bucket_name
    resource_list_sensitive = [] 
    resource_list_canary    = []

    if (soaring_event_type == "CANARY"):
        resource_list_canary.append(bucket_name)
    
    ## Get resource metadata from Macie Finding
    if (soaring_event_type == "PII"):

        macie_finding       = combined_event['macieFinding']
        macie_finding_id    = combined_event['macieJobs']['findingIds'][0]
        macie_finding_url   = f"https://{account_region}.console.aws.amazon.com/macie/home?region={account_region}#findings?itemId={macie_finding_id}"
        
        # PII specific metadata
        classification_details  = macie_finding['classificationDetails']
        data_classification     = classification_details['result']
        data_class_types        = len(data_classification['sensitiveData'])

        object_etag     = macie_finding['resourcesAffected']['s3Object']['eTag']
        object_key      = macie_finding['resourcesAffected']['s3Object']['key']
        macie_title     = macie_finding['title']

        ## Object metadata from Macie finding
        for resource_key in macie_finding['resourcesAffected']:

            resource_details = macie_finding['resourcesAffected'][resource_key]
        
            # If resource is an S3 bucket, check public/non public acccess
            if (resource_key == "s3Bucket"): 
                bucket_permission = resource_details['publicAccess']['effectivePermission']
                rname = resource_details['name']
            
            # If resource is an S3 object, get name
            if (resource_key == "s3Object"):
                rname = resource_details['key']
            
            resource_list_sensitive.append(rname)
        
    


    ## Generate event description based on event type and contexts
    ## include info about resources + PII data
    n_resources     = len(resource_list_sensitive + resource_list_canary)
    descriptions    = []
    finding_types   = []

    if (n_resources == 1):
        event_description_type    = f"There was an attempted {action_type} on your secure S3 resources ({str(n_resources)} resource is affected)."
    else:
        event_description_type    = f"There was an attempted {action_type} on your secure S3 resources ({str(n_resources)} resources are affected)."
    descriptions.append(event_description_type)

    ## Build title from 
    title = f"Attempted {action_type} on S3"

    if (soaring_event_type == "PII"):
        
        if (data_class_types > 1):
            title = title + " object, containing multiple types of sensitive information (PII Data)"
        else:
            title = title + " object, containing sensitive information (PII Data)"

        sensitive_list_str      = ", ".join(resource_list_sensitive)
        event_desc_sensitive    = f"Sensitive PII data stored in the S3 bucket [{sensitive_list_str}] may have been compromised."
        descriptions.append(event_desc_sensitive)
        finding_types.append("Sensitive Data Identifications/PII")

    elif (soaring_event_type == "CANARY"):

        canary_list_str     = ", ".join(resource_list_canary)
        event_desc_canary   = f"One or more canaries [{canary_list_str}] may have been compromised."
        descriptions.append(event_desc_canary)
        finding_types.append("TTPs/Initial Access")
        title = title + " bucket (Canary Bucket)"

    description = " ".join(descriptions)

    

    ## Get Geo IP details
    ip_details  = detail['ipDetails']

    ip_address  = ip_details['ip']
    ip_country  = ip_details['country_name']
    ip_city     = ip_details['city']
    ip_lat      = ip_details['latitude']
    ip_long     = ip_details['longitude']
    
    ## Get Google Static Map url
    map_url     = get_static_map_url(ip_lat, ip_long)
    
    
    
    ## Output as JSON in AWS Security Findings Format
    finding = {
        "AwsAccountId"      : account_id,
        "CreatedAt"         : created_at,
        "Description"       : description,
        "FirstObservedAt"   : first_observed_at,
        "GeneratorId"       : generator_id,
        "Id"                : sh_finding_id, 
        "ProductArn"        : product_arn,  
        "Resources" : [
            { 
                "Type"      : "AwsS3Bucket",
                "Id"        : bucket_arn, 
                "Partition" : "aws", 
                "Region"    : account_region
            }
        ],
        "SchemaVersion"     : "2018-10-08",
        "Severity"  : {
            "Label"         : severity_desc, 
            "Original"      : severity_score
        }, 
        "Title"             : title, 
        "Types"             : finding_types,
        "UpdatedAt"         : updated_at,
        "ProductFields": {
            "ProviderName"      : product_name,
            "ProviderVersion"   : product_version,
            "soaring/SeverityMatches"   : severity_matches,
            "soaring/ShouldAlert"       : should_alert,
            "soaring/UserName"          : user_name,
            "soaring/UserType"          : user_type,
            "soaring/UserIP"            : ip_address,
            "soaring/UserCity"          : ip_city,
            "soaring/UserCountry"       : ip_country,
            "soaring/UserCoords"        : str(ip_lat + ip_long),
            "soaring/UserMap"           : map_url,
            "soaring/UserGroups"        : user_groups,
            "soaring/UserGroupPolicies" : user_group_policies,
            "soaring/UserPolicies"      : user_policies,
            "soaring/UserRolePolicies"  : role_policies
        }
    }

    ## Add additional fields for PII use case
    if (soaring_event_type == "PII"):

        finding['ProductFields']['soaring/MacieFindingId']  = macie_finding_id
        finding['ProductFields']['soaring/MacieFindingUrl'] = macie_finding_url
        finding['ProductFields']['soaring/MacieTitle']      = macie_title
        finding['ProductFields']['soaring/S3Object']        = object_key
        finding['ProductFields']['soaring/S3ObjectEtag']    = object_etag
        finding['ProductFields']['soaring/S3BucketPermission'] = bucket_permission

    return finding