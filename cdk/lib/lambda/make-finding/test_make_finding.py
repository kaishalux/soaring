from os.path import dirname
import pytest_mock
import index
import os
import json

def import_event(filename):

    file = "lib/lambda/make-finding/" + filename + ".json"
    with open(file, "r") as f:
        event = json.load(f)
    
    return event

def test_user_type_correct_split(mocker):
    
    secrets_manager = mocker.patch('boto3.session.Session')
    secrets_manager.return_value.client.return_value.get_secret_value.return_value = mocker.MagicMock({"SecretString":"FAKE-API-KEY"})

    # testing the user type 
    event = import_event("test_message_pii")

    result = index.lambda_handler(event, None)

    assert result["AwsAccountId"] == "659855141795"

