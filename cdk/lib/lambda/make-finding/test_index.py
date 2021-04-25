import pytest_mock
import index


def test_user_type_correct_split(mocker):
    # testing the user type 
    event = {
        "detail": {
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAZTITONORSWEDWVJJE:Jas",
                "arn": "arn:aws:sts::659855141795:assumed-role/lambda-soaring-dev/Jas",
                "accountId": "659855141795",
                "accessKeyId": "ASIAZTITONOR5WIA5OES",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROAZTITONORSWEDWVJJE",
                        "arn": "arn:aws:iam::659855141795:role/lambda-soaring-dev",
                        "accountId": "659855141795",
                        "userName": "lambda-soaring-dev"
                    },
                    "attributes": {
                        "creationDate": "2021-04-15T07:16:36Z",
                        "mfaAuthenticated": "true"
                    }
                }
            }
        }
    } 

    result = index.lambda_handler(event, None)

    assert result["soaringEventType"] == "CANARY"
    assert result["soaringBucketType"] == "CANARY"

def test_sets_correct_type_for_pii_bucket(mocker):
    # Mocks the Boto3 call so it doesn't actually make a real API call
    s3 = mocker.patch('boto3.resource')
    s3.return_value.BucketTagging.return_value = mocker.MagicMock(tag_set=[{
        "Key": "SensitiveDataClassification",
        "Value": "PII"
    }])

    event = {
        "detail": {
            "eventName": "",
            "requestParameters": {
                "bucketName": ""
            }
        }
    }

    result = index.lambda_handler(event, None)

    assert result["soaringEventType"] == "PII"
    assert result["soaringBucketType"] == "PII"
