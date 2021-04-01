/**
 * This file contains the SOAR stack
 */

import { Effect, PolicyStatement } from '@aws-cdk/aws-iam';
import * as lambda from '@aws-cdk/aws-lambda';
import * as sfn from '@aws-cdk/aws-stepfunctions';
import * as tasks from '@aws-cdk/aws-stepfunctions-tasks';
import * as cdk from '@aws-cdk/core';
import { Tags } from "@aws-cdk/core";
import * as path from "path";
import { Extract } from './soar/extract';


export class SoarStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Add Lambdas
    const identityContextAdder = new lambda.Function(this, "IdLambda", {
      code: lambda.Code.fromAsset(path.join(__dirname, "lambda/identityadder")),
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "index.lambda_handler",
      memorySize: 512,
    });

    const finding = new lambda.Function(this, "FindingLambda", {
      code: lambda.Code.fromAsset(path.join(__dirname, "lambda/finding")),
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "index.lambda_handler",
      memorySize: 512,
    });

    finding.addToRolePolicy(new PolicyStatement({
      effect: Effect.ALLOW,
      actions: [
        "securityhub:BatchImportFindings"
      ],
      resources: ["arn:aws:securityhub:ap-southeast-2:659855141795:product/659855141795/default"]
    }));

    // Configure step function defintion
    const sfnDefinition = new tasks.LambdaInvoke(this, "IdStep", {
      "lambdaFunction": identityContextAdder,
      "retryOnServiceExceptions": false,
      "inputPath": "$",
      "outputPath": "$"
    }).next(new tasks.LambdaInvoke(this, "FindingsStep", {
      "lambdaFunction": finding,
      "retryOnServiceExceptions": false,
      "inputPath": "$",
      "outputPath": "$"
    }));

    // Set up rest of infrastructure
    const stateMachine = new sfn.StateMachine(this, "SoaringSoln", {
      "stateMachineName": "soar-stack",
      "stateMachineType": sfn.StateMachineType.EXPRESS,
      "definition": sfnDefinition
    });

    new Extract(this, "ExtractComponent", { sfn: stateMachine });
    Tags.of(this).add("OWNER", "team");
  }
}
