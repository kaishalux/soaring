import boto3
import json
import os
import datetime
import logging
from botocore.exceptions import ClientError

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import urllib.parse


# # The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
# ENCRYPTED_HOOK_URL = "hooks.slack.com/services/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" #os.environ['kmsEncryptedHookUrl']
# # The Slack channel to send a message to stored in the slackChannel environment variable
# SLACK_CHANNEL = "9447 sec-alert" #os.environ['slackChannel']

# """ Have to get KMS key permissions first
# HOOK_URL = "https://" + boto3.client('kms').decrypt(
# 	CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL),
# 	EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
# )['Plaintext'].decode('utf-8')
# """

# for now store hook unencrypted
# HOOK_URL = "https://" + ENCRYPTED_HOOK_URL
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sechub = boto3.client('securityhub')

def lambda_handler(event, context):
	#push finding to security hub
	finding = makeSecurityHubFinding(event.copy())
	response = sechub.batch_import_findings(Findings = [finding])
	#push finding to slack if secops should be alerted
	if (finding["ProductFields"]["soaring/ShouldAlert"] == "true"): sendSlack(finding)
	return response

def makeSecurityHubFinding(event):
	# set unique ID and update time 
	event['UpdatedAt'] = datetime.datetime.now().isoformat() + "Z"
	event['Id'] = event['Id'] + " " + event['UpdatedAt']
	return event
	 
def sendSlack(finding):
	#get slack json and send message
	slack_message = formatSlackMessage(finding)
	hook_url = get_secret().decode('utf-8')
	req = Request(hook_url, json.dumps(slack_message).encode('utf-8'))
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

	#resources involved
	resources = ""
	for res in finding["Resources"]:
		resources = resources + res["Type"] + " : " + res["Id"] + " \n"

	#user
	user = finding["ProductFields"]["soaring/UserName"]

	#location
	location = finding["ProductFields"]["soaring/UserCity"] +", "+ finding["ProductFields"]["soaring/UserCountry"]

	#threat types
	threat = ""
	for thr in finding["Types"]:
		threat = thr + "\n"	

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
							},							{
								"type": "mrkdwn",
								"text": "*Threat Type*"
							},
							{
								"type": "mrkdwn",
								"text": threat		#set threat types
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

def get_secret():

    secret_name = "slack-hook-url"
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
