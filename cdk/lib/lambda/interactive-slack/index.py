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

def lambda_handler(event, context):
	#if the user selected a severity
	if event["actions"][0]["type"] == "static_select":
		findingID = event["actions"][0]["action_id"].split("|",1)[1]
		severity = event["actions"][0]["value"]
		findingUpdate = makeFindingUpdate(findingID, severity)
		response = sechub.batch_update_findings(findingUpdate)
	#if they clicked a button
	else:
		response = {"statusCode": 200}
	return response


def makeFindingUpdate(id, severity):
	return {
		"FindingIdentifiers": [ 
			{ 
				"Id": id,
				"ProductArn": "arn:aws:securityhub:ap-southeast-2:659855141795:product/659855141795/default"
			}
		],
		"Severity": { 
			"Label": severity
		}
	}


	 
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

