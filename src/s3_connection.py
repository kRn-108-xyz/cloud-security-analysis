
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

BUCKET_NAME = "cloud-security-analysis"
FILE_NAME = "security_logs.csv"

def main():
    try:
        s3 = boto3.client("s3")

        response = s3.get_object(
            Bucket=BUCKET_NAME,
            Key=FILE_NAME
        )

        content = response["Body"].read().decode("utf-8")

        print("AWS S3 connection successful!")
        print(f"Bucket: {BUCKET_NAME}")
        print(f"File: {FILE_NAME}")
        print("\nFirst five lines of security logs:")

        for line in content.splitlines()[:5]:
            print(line)

    except NoCredentialsError:
        print("AWS credentials not found. Run: aws configure")

    except ClientError as error:
        print("AWS error:", error.response["Error"]["Code"])
        print(error.response["Error"]["Message"])

if __name__ == "__main__":
    main()
