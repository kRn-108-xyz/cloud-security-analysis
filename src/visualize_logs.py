
import boto3
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from pathlib import Path

BUCKET_NAME = "cloud-security-analysis"
FILE_NAME = "security_logs.csv"

def main():
    print("Downloading logs from AWS S3...")

    s3 = boto3.client("s3")
    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=FILE_NAME
    )

    df = pd.read_csv(BytesIO(response["Body"].read()))

    counts = df["event_type"].value_counts()

    # Chart 1: Security event distribution
    plt.figure(figsize=(10, 6))
    counts.plot(kind="bar")
    plt.title("Cybersecurity Event Distribution")
    plt.xlabel("Event Type")
    plt.ylabel("Number of Events")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("security_event_chart.png", dpi=150)
    plt.show()

    # Chart 2: Security event percentages
    plt.figure(figsize=(8, 8))
    counts.plot(kind="pie", autopct="%1.1f%%", startangle=90)
    plt.title("Security Events by Percentage")
    plt.ylabel("")
    plt.tight_layout()
    plt.savefig("security_event_pie_chart.png", dpi=150)
    plt.show()

    print("Charts saved:")
    print("security_event_chart.png")
    print("security_event_pie_chart.png")

if __name__ == "__main__":
    main()
