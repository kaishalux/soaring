import boto3
import json
import os
import datetime
import logging

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
ENCRYPTED_HOOK_URL = "hooks.slack.com/services/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" #os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = "9447 sec-alert" #os.environ['slackChannel']

""" Have to get KMS key permissions first
HOOK_URL = "https://" + boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')
"""
# for now store hook unencrypted
HOOK_URL = "https://" + ENCRYPTED_HOOK_URL
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sechub = boto3.client('securityhub')

def lambda_handler(event, context):
    finding = makeSecurityHubFinding(event.copy())
    response = sechub.batch_import_findings(Findings = [finding])
    finding['ProductFields'] = event['Note']
    sendSlack(finding)
    return 

def makeSecurityHubFinding(event):
    event['GeneratorId'] = "soaring"
    event['ProductArn'] = "arn:aws:securityhub:ap-southeast-2:659855141795:product/659855141795/default"
    event['Region'] = ""
    del event['Region']
    event['Severity']['Original'] = str(event['Severity']['Original']) 
    event['Severity']['Label'] = event['Severity']['Label'].upper()
    event['UpdatedAt'] = datetime.datetime.now().isoformat() + "Z"
    event['Id'] = event['Id'] + " " + event['UpdatedAt']
    i = 0
    while i < len(event['Resources']):
        #have this make and then delete a key to stop me from deleting a key that doesnt exist
        event['Resources'][i]['Name'] = ""
        del event['Resources'][i]['Name']
        i = i + 1
    event['ProductFields'] = { 
            "UserIdentity": json.dumps(event['Note']['UserIdentity']),
            "Username": = json.dumps(event['Note']['UserIdentity']['userName']),
            "ProviderName": "soaring", 
            "ProviderVersion": "0.1"
        }
    event['Note'] = ""
    del event['Note']
    return event
     
def sendSlack(event):
    user = event['ProductFields']['UserIdentity'].copy() 
    text = "%s \n\n*User:* %s \n*User Type:* %s \n*IP:* %s \n*Location:* <%s|%s, %s>" % (event['Description'], 
            user['userName'], user['userType'], user['userIP'], user['userMap'], user['userCity'], user['userCountry'])
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': text,
    	"blocks": [
    		{
    			"type": "header",
    			"text": {
    				"type": "plain_text",
    				"text": event['Title'] + " ["+event['Severity']['Label']+"]",
    			}
    		},
    		{
    			"type": "section",
    			"text": {
    				"type": "mrkdwn",
    				"text": text
    			}
    		},
    		{
    			"type": "image",
    			"title": {
    				"type": "plain_text",
    				"text": "%s, %s" % (user['userCity'], user['userCountry']),
    			},
    			"image_url": user['userMap'],
    			"alt_text": "IP location"
    		}
    	]
    }
    req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
    return