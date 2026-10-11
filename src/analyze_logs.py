
import boto3
import pandas as pd
from io import BytesIO

BUCKET_NAME = "cloud-security-analysis"
FILE_NAME = "security_logs.csv"

def main():
    print("Connecting to AWS S3...")

    s3 = boto3.client("s3")

    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=FILE_NAME
    )

    df = pd.read_csv(BytesIO(response["Body"].read()))

    print("\n===== SECURITY LOG ANALYSIS =====")
    print(f"Total events: {len(df)}")

    print("\nEvent counts:")
    print(df["event_type"].value_counts().to_string())

    print("\nEvent percentages:")
    percentages = df["event_type"].value_counts(normalize=True) * 100
    print(percentages.round(2).to_string())

    print("\nPotential security alerts:")
    alerts = df[
        df["event_type"].isin(
            ["Failed Login", "Port Scan", "Malware Alert", "Suspicious File"]
        )
    ]

    print(f"Potential alert events: {len(alerts)}")
    print(alerts.head(10).to_string(index=False))

    print("\nAnalysis completed.")

if __name__ == "__main__":
    main()
