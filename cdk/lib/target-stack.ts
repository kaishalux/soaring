/**
 * This file contains the target stack for
 */

import * as s3 from "@aws-cdk/aws-s3";
import * as s3deploy from "@aws-cdk/aws-s3-deployment";
import * as cdk from '@aws-cdk/core';
import { RemovalPolicy, Tags } from "@aws-cdk/core";
import * as path from "path";

export class TargetStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 1. Demo of a bucket which holds PII or sensitive information
    const bucketTargetPii = new s3.Bucket(this, "CustomerReports", {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      bucketName: "soaring-1-customer-reports",
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true
    });

    new s3deploy.BucketDeployment(this, 'DeployFiles1', {
      sources: [s3deploy.Source.asset(path.join(__dirname, "s3/soaring-1-customer-reports"))],       
      destinationBucket: bucketTargetPii
    });

    // 2. Demo as a "canary" bucket which acts as an alarm when someone is trying to look for data e.g. from phishing/leaked credentials
    const bucketTargetCanary = new s3.Bucket(this, "CompanyConfidentialSecrets", {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      bucketName: "soaring-2-company-confidential-secrets",
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true
    });

    new s3deploy.BucketDeployment(this, 'DeployFiles2', {
      sources: [s3deploy.Source.asset(path.join(__dirname, "s3/soaring-2-company-confidential-secrets"))],       
      destinationBucket: bucketTargetCanary
    });

    Tags.of(this).add("OWNER", "team");
    Tags.of(bucketTargetPii).add("SensitiveDataClassification", "PII");
    Tags.of(bucketTargetCanary).add("DataSecurityClassification", "CanaryBucket")
  }
}
