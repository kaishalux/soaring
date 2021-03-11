/**
 * This file contains the target stack for
 */

import * as cdk from '@aws-cdk/core';
import * as s3 from "@aws-cdk/aws-s3";
import * as iam from "@aws-cdk/aws-iam";

export class TargetStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 1. Demo as a "canary" bucket which acts as an alarm when someone is trying to look for data e.g. from phishing/leaked credentials
    const bucketTargetCanary = new s3.Bucket(this, "CompanyConfidentialSecrets", {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL
    });

    // People who own the secrets but should only never access them (as the bucket is a canary).
    // const executivesGroup = new iam.Group(this, "Executives");
    // bucketTargetCanary.grantReadWrite(executivesGroup);
  }
}
