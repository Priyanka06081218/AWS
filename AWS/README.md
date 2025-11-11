A robust tool that enables developers to design and administer APIs at scale is Amazon API Gateway. The 10MB request payload size limit is a significant drawback, though. When users need to upload large files, this could be an issue.

The provided code illustrates the most effective method for getting around the API Gateway payload cap with pre-signed S3 URLs, guaranteeing scalable and effective file uploads.


# Using Pre-Signed S3 URLs for better Architecture:

Using pre-signed S3 URLs, which let clients upload files straight to S3, circumventing API Gateway's size restrictions, is a more effective way.

How It Operates: 

The API Gateway receives a request from the mobile client.

A Lambda function is called by the API Gateway.

Lambda creates an S3 URL that has already been signed.

The pre-signed URL is returned to API Gateway by Lambda.

The mobile client receives the URL from the API Gateway.

Using the pre-signed URL, the mobile client uploads the file straight to S3.


Why This Is More Effective
✔ Gets Around API Gateway Payload Limit: The file is uploaded straight to S3, circumventing the 10MB limit.
✔ Lowers Costs: By handling only minor requests (to create the URL), API Gateway and Lambda lower the cost of data transfer.
✔ Enhances Performance: Direct uploads to S3 are more effective and quicker.
✔ Extremely Scalable: This method can easily manage big file uploads.

Example implementtion:

Step 1: Create a Lambda Function to Generate a Pre-Signed URL
The Python code in the file API_Gateway_payaload_limit.py (using Boto3) generates a pre-signed URL for an S3 bucket

Step 2: Install the API Gateway to Call Lambda
Make an HTTP endpoint for the API Gateway.

To use the Lambda function, set up an integration request.

Launch the API Gateway.

Step 3: Use the pre-signed URL to upload the file.
The mobile client can upload the file straight to S3 after receiving the pre-signed URL:

curl -X PUT -T "file.txt" "<pre-signed-URL>"


