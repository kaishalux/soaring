import boto3
import json
import os
import datetime
import logging

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import urllib.parse


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
	#push finding to security hub
    finding = makeSecurityHubFinding(event.copy())
    response = sechub.batch_import_findings(Findings = [finding])
	#push finding to slack if secops should be alerted
	if (finding["soaring/ShouldAlert"]): sendSlack(finding)
    return response

def makeSecurityHubFinding(event):
	# set unique ID and update time 
    event['UpdatedAt'] = datetime.datetime.now().isoformat() + "Z"
    event['Id'] = event['Id'] + " " + event['UpdatedAt']
    return event
     
def sendSlack(finding):
	#get slack json and send message
	slack_message = formatSlackMessage(finding)
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

def formatSlackMessage(finding):
	description = finding['Description']

	severity = finding["Severity"]["Label"]

	title = finding['Title'] + " [" + severity + "]"

	#set url for finding in security hub (need to double parse ID for URL as Amazon does)
	sechubUrl = "https://ap-southeast-2.console.aws.amazon.com/securityhub/home?region=ap-southeast-2#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A"
	sechubUrl = sechubUrl + urllib.parse.quote(urllib.parse.quote(finding["Id"], safe=''))

	#resources
	resources = ""
	for res in finding["Resources"]:
		resources = f"{resources}{res["Type"]}:{res["Id"]} "

	#user
	user = finding["ProductFields"]["soaring/UserName"]

	#location
	location = f"{finding["ProductFields"]["soaring/UserCity"]}, {finding["ProductFields"]["soaring/UserCountry"]}"

    # text = "%s \n\n*Resources Affected:*\n S3 Bucket: <%s|%s>\n S3 Object: <%s|%s>\n\n*User:* %s \n*User Type:* %s \n*IP:* %s \n*Location:* <%s|%s, %s>" \
    #     % (description, bucket_url, bucket_name, object_url, object_key, user['userName'], user['userType'], user['userIP'], user['userMap'], user['userCity'], user['userCountry'])
    

	#set colour for message based on severity
	colour = "ff0000" #red
	if severity == "INFORMATIONAL": colour = "009dff" #blue
	if severity == "LOW": colour = "d834eb" #purple
	if severity == "MEDIUM": colour = "fff200" #yellow
	if severity == "HIGH": colour = "ed9600" #orange
	if severity == "CRITICAL": colour = "ff0000" #red
	
    slack = {
        "channel": SLACK_CHANNEL,
		"text": title, 	#set notification text of message
    	"blocks": [
    		{
    			"type": "header", 
    			"text": {
    				"type": "plain_text", 
    				"text": title 	#set heading
    			}
    		}
    	],
    	"attachments": [
    		{
    			"color": colour, # colour for message
    			"blocks": [
					{
						"type": "section",
						"text": {
							"type": "mrkdwn",
							"text": description 	#set description in message
						}
					},
    				{
    					"type": "section",
    					"fields": [
    						{
    							"type": "mrkdwn",
    							"text": "*Severity*"
    						},
    						{
    							"type": "mrkdwn",
    							"text": severity	#set severity
    						},
    						{
    							"type": "mrkdwn",
    							"text": "*Resources*"
    						},
    						{
    							"type": "mrkdwn",
    							"text": resources	#set resources
    						},
    						{
    							"type": "mrkdwn",
    							"text": "*User*"
    						},
    						{
    							"type": "mrkdwn",
    							"text": user 		#set user
    						},
    						{
    							"type": "mrkdwn",
    							"text": "*User Location*"
    						},
    						{
    							"type": "mrkdwn",
    							"text": location 	#set location
    						}
    					]
    				},
    				{
    					"type": "actions",
    					"elements": [
    						{
    							"type": "button",
    							"text": {
    								"type": "plain_text",
    								"text": "Security Hub Finding",
    							},
    							"url": sechubUrl 	#set url for button that leads to finding in sec hub console
    						},
    					]
    				},
    				{
    					"type": "actions",
    					"elements": [
    						{
    							"type": "static_select",
    							"placeholder": {
    								"type": "plain_text",
    								"text": "Change the severity",
    							},
    							"options": [
    								{
    									"text": {
    										"type": "plain_text",
    										"text": "INFORMATIONAL",
    									},
    									"value": "INFORMATIONAL"
    								},
    								{
    									"text": {
    										"type": "plain_text",
    										"text": "LOW",
    									},
    									"value": "LOW"
    								},
    								{
    									"text": {
    										"type": "plain_text",
    										"text": "MEDIUM",
    									},
    									"value": "MEDIUM"
    								},
									{
    									"text": {
    										"type": "plain_text",
    										"text": "HIGH",
    									},
    									"value": "HIGH"
    								},
    								{
    									"text": {
    										"type": "plain_text",
    										"text": "CRITICAL",
    									},
    									"value": "CRITICAL"
    								}

    							],
    							"action_id": "severity_select-action"
    						}
    					]
    				}
    			]
    		}
    	]
    }

		#add extra button link to macie finding if there is one   
	if "soaring/MacieFindingUrl" in finding["ProductFields"]:
		macieBtn = {
					"type": "button",
					"text": {
						"type": "plain_text",
						"text": "Macie Finding",
					},
					"url": finding["ProductFields"]["soaring/MacieFindingUrl"]
				}
		slack["attachments"][0]["blocks"][2]["elements"].append(macieBtn)
	return slack 
