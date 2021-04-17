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
sechub = boto3.client('securityhub')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
	#if the user selected a severity
	payload = event["body"]
	temp = urllib.parse.unquote_plus(payload)
	temp = temp.split("=",1)[1]
	slackJson = json.loads(temp)
	# logger.info(slackJson["actions"])
	if slackJson["actions"][0]["type"] == "static_select":
		response = updateFinding(slackJson)
		# logger.info(response)
		response = {"statusCode" : response["ResponseMetadata"]["HTTPStatusCode"]}
	#if they clicked a button
	else:
		response = {"statusCode": 200}
	return response

def updateFinding(json):
	findingID = json["actions"][0]["action_id"].split("|",1)[1]
	severityLabel = json["actions"][0]["selected_option"]["value"]
	response = sechub.batch_update_findings(
		FindingIdentifiers=[
			{
				'Id': findingID,
				'ProductArn': 'arn:aws:securityhub:ap-southeast-2:659855141795:product/659855141795/default'
			},
		],
		Severity={
			'Label': severityLabel
		}
	)
	return response
	 
def sendReq(url, string):
	#get slack json and send message
	req = Request(url, json.dumps(string).encode('utf-8'))
	try:
		response = urlopen(req)
		response.read()
		logger.info("Message posted to %s", slack_message['channel'])
	except HTTPError as e:
		logger.error("Request failed: %d %s", e.code, e.reason)
	except URLError as e:
		logger.error("Server connection failed: %s", e.reason)
	return

