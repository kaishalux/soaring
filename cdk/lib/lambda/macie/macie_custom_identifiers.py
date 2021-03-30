# add custom identifiers 
import boto3 

def create_custom_data_identifier(**kwargs):

    macie_client = boto3.client('macie2')

    response = macie_client.create_custom_data_identifier(
        clientToken = 'string',
        description = 'string',
        ignoreWords = [
            'string',
        ],
        keywords=[
            'string',
        ],
        maximumMatchDistance = 123,
        name = 'string',
        regex = 'string',
        tags ={
            'string': 'string'
        }
    )


