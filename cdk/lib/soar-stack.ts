/**
 * This file contains the SOAR stack
 */

import { Effect, PolicyStatement } from '@aws-cdk/aws-iam';
import * as lambda from '@aws-cdk/aws-lambda';
import * as sfn from '@aws-cdk/aws-stepfunctions';
import * as tasks from '@aws-cdk/aws-stepfunctions-tasks';
import * as cdk from '@aws-cdk/core';
import { Duration, Tags } from "@aws-cdk/core";
import * as path from "path";
import { Extract } from './soar/extract';


export class SoarStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Add Lambdas
    const macieJobLambda = new lambda.Function(this, "MacieJobLambda", {
      code: lambda.Code.fromAsset(path.join(__dirname, "lambda/macie-job")),
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "index.lambda_handler",
      memorySize: 512,
      timeout: Duration.seconds(15)
    });

    macieJobLambda.addToRolePolicy(new PolicyStatement({
      effect: Effect.ALLOW,
      actions: [
        "macie2:CreateClassificationJob"
      ],
      resources: ["*"]
    }));

    const macieStatusLambda = new lambda.Function(this, "MacieStatusLambda", {
      code: lambda.Code.fromAsset(path.join(__dirname, "lambda/macie-status")),
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "index.lambda_handler",
      memorySize: 512,
      timeout: Duration.seconds(15)
    });

    macieStatusLambda.addToRolePolicy(new PolicyStatement({
      effect: Effect.ALLOW,
      actions: [
        "macie2:DescribeClassificationJob"
      ],
      resources: ["*"]
    }));

    const macieFindingLambda = new lambda.Function(this, "MacieFindingLambda", {
      code: lambda.Code.fromAsset(path.join(__dirname, "lambda/macie-finding")),
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "index.lambda_handler",
      memorySize: 512,
      timeout: Duration.seconds(15)
    });

    macieFindingLambda.addToRolePolicy(new PolicyStatement({
      effect: Effect.ALLOW,
      actions: [
        "macie2:GetFindings"
      ],
      resources: ["*"]
    }));

    // const getIdentityLambda = new lambda.Function(this, "IdLambda", {
    //   code: lambda.Code.fromAsset(path.join(__dirname, "lambda/get-identity")),
    //   runtime: lambda.Runtime.NODEJS_12_X,
    //   handler: "index.exports.handler",
    //   memorySize: 512,
    //   timeout: Duration.seconds(15)
    // });

    // const findingLambda = new lambda.Function(this, "FindingLambda", {
    //   code: lambda.Code.fromAsset(path.join(__dirname, "lambda/finding")),
    //   runtime: lambda.Runtime.PYTHON_3_8,
    //   handler: "index.lambda_handler",
    //   memorySize: 512,
    // });

    // findingLambda.addToRolePolicy(new PolicyStatement({
    //   effect: Effect.ALLOW,
    //   actions: [
    //     "securityhub:BatchImportFindings"
    //   ],
    //   resources: ["arn:aws:securityhub:ap-southeast-2:659855141795:product/659855141795/default"]
    // }));



    // Configure steps
    const macieJob = new tasks.LambdaInvoke(this, "MacieJobStep", {
      "lambdaFunction": macieJobLambda,
      "retryOnServiceExceptions": false,
      "inputPath": "$",
      "outputPath": "$"
    });

    const macieStatus = new tasks.LambdaInvoke(this, "MacieStatusStep", {
      "lambdaFunction": macieStatusLambda,
      "retryOnServiceExceptions": false,
      "inputPath": "$.Payload",
      "outputPath": "$"
    });

    const macieFinding = new tasks.LambdaInvoke(this, "MacieFindingStep", {
      "lambdaFunction": macieFindingLambda,
      "retryOnServiceExceptions": false,
      "inputPath": "$.Payload",
      "outputPath": "$"
    });
    
    const waitForMacieJob = new sfn.Wait(this, "waitForMacieJob", {
      "time": sfn.WaitTime.duration(Duration.seconds(60))
    });
    waitForMacieJob.next(macieStatus)
    
    const checkMacieStatus = new sfn.Choice(this, "checkMacieStatus");

    // const getIdentity = new tasks.LambdaInvoke(this, "IdStep", {
    //   "lambdaFunction": getIdentityLambda,
    //   "retryOnServiceExceptions": false,
    //   "inputPath": "$",
    //   "outputPath": "$"
    // });

    // const finding = new tasks.LambdaInvoke(this, "FindingsStep", {
    //   "lambdaFunction": findingLambda,
    //   "retryOnServiceExceptions": false,
    //   "inputPath": "$",
    //   "outputPath": "$"
    // })


    // Configure step function defintion
    const sfnDefinition = sfn.Chain
      .start(macieJob)
      .next(macieStatus)
      .next(checkMacieStatus
        .when(sfn.Condition.stringEquals('$.Payload.macieJobs.jobStatus', 'COMPLETE'),
          macieFinding
          // .next(getIdentity)
          // .next(finding)
          )
        .otherwise(waitForMacieJob));

    // Set up rest of infrastructure
    const stateMachine = new sfn.StateMachine(this, "SoaringSoln-Macie", {
      "stateMachineName": "soar-stack-macie",
      "stateMachineType": sfn.StateMachineType.STANDARD,
      "definition": sfnDefinition
    });
    

    new Extract(this, "ExtractComponent", { sfn: stateMachine });
    Tags.of(this).add("OWNER", "team");
  }
}
