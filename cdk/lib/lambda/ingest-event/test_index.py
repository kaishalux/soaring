import pytest_mock
import index

def test_sets_correct_type_for_canary_bucket(mocker):
    # Mocks the Boto3 call so it doesn't actually make a real API call
    s3 = mocker.patch('boto3.resource')
    s3.return_value.BucketTagging.return_value = mocker.MagicMock(tag_set=[{
        "Key": "DataSecurityClassification",
        "Value": "CanaryBucket"
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

    assert result["soaringEventType"] == "CANARY"
    assert result["soaringBucketType"] == "CANARY"
