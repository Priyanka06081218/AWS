import boto3
import json
import os

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket_name = os.environ['BUCKET_NAME']
    file_name = event['queryStringParameters']['file_name']

    pre_signed_url = s3.generate_presigned_url(
        'put_object',
        Params={'Bucket': bucket_name, 'Key': file_name},
        ExpiresIn=3600  # URL valid for 1 hour
    )

    return {
        'statusCode': 200,
        'body': json.dumps({'upload_url': pre_signed_url})
    }
