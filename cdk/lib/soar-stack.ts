/**
 * This file contains the SOAR stack
 */

import { Effect, PolicyStatement } from "@aws-cdk/aws-iam";
import * as lambda from "@aws-cdk/aws-lambda";
import * as nodeLambda from "@aws-cdk/aws-lambda-nodejs";
import * as sfn from "@aws-cdk/aws-stepfunctions";
import * as tasks from "@aws-cdk/aws-stepfunctions-tasks";
import * as apigw from '@aws-cdk/aws-apigateway';
import * as cdk from "@aws-cdk/core";
import { Duration, Tags } from "@aws-cdk/core";
import * as path from "path";
import { Extract } from "./soar/extract";

export class SoarStack extends cdk.Stack {
	constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
		super(scope, id, props);

		// Add Lambdas
		const ingestEventLambda = new lambda.Function(this, "IngestEventLambda", {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/ingest-event")),
			runtime: lambda.Runtime.PYTHON_3_8,
			handler: "index.lambda_handler",
			memorySize: 512,
			timeout: Duration.seconds(15),
		});

		ingestEventLambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: ["s3:GetBucketTagging"],
				resources: ["*"],
			})
		);

		const macieJobLambda = new lambda.Function(this, "MacieJobLambda", {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/macie-job")),
			runtime: lambda.Runtime.PYTHON_3_8,
			handler: "index.lambda_handler",
			memorySize: 512,
			timeout: Duration.seconds(15),
		});

		macieJobLambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: ["macie2:CreateClassificationJob"],
				resources: ["*"],
			})
		);

		const macieStatusLambda = new lambda.Function(this, "MacieStatusLambda", {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/macie-status")),
			runtime: lambda.Runtime.PYTHON_3_8,
			handler: "index.lambda_handler",
			memorySize: 512,
			timeout: Duration.seconds(15),
		});

		macieStatusLambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: ["macie2:DescribeClassificationJob"],
				resources: ["*"],
			})
		);

		const macieFindingLambda = new lambda.Function(this, "MacieFindingLambda", {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/macie-finding")),
			runtime: lambda.Runtime.PYTHON_3_8,
			handler: "index.lambda_handler",
			memorySize: 512,
			timeout: Duration.seconds(15),
		});

		macieFindingLambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: ["macie2:GetFindings", "macie2:ListFindings"],
				resources: ["*"]
			})
		);

		const addGeoIpLambda = new nodeLambda.NodejsFunction(this, "AddGeoIp", {
			entry: path.join(__dirname, "lambda/add-geoip", "index.js"),
			handler: "lambda_handler",
			memorySize: 512,
		});

        addGeoIpLambda.addToRolePolicy(
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ["secretsmanager:GetSecretValue"],
                resources: ["*"]
            })
        )

		const addSeverityLambdaDir = "lambda/add-severity";
		const addSeverityLambda = new nodeLambda.NodejsFunction(
			this,
			"AddSeverity",
			{
				entry: path.join(__dirname, addSeverityLambdaDir, "index.js"),
				handler: "handler",
				memorySize: 512,
				bundling: {
					nodeModules: ["jsonpath"],
					target: "es2020",
					commandHooks: {
						afterBundling: (inputDir, outputDir) => [
							`mkdir ${outputDir}/config`,
							`cp -r ${inputDir}/lib/${addSeverityLambdaDir}/config/ ${outputDir}`,
						],
						beforeBundling: (_inputDir, _outputDir) => [],
						beforeInstall: (_inputDir, _outputDir) => [],
					},
				},
			}
		);

		const makeFindingLambda = new lambda.Function(this, "MakeFindingLambda", {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/make-finding")),
			runtime: lambda.Runtime.PYTHON_3_8,
			handler: "index.lambda_handler",
			memorySize: 512,
			timeout: Duration.seconds(15),
		});

		makeFindingLambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: ["secretsmanager:GetSecretValue"],
				resources: ["*"]
			})
		)

		const getIdentityLambda = new lambda.Function(this, "GetIdentityLambda", {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/get-identity")),
			runtime: lambda.Runtime.NODEJS_12_X,
			handler: "index.handler",
			memorySize: 512,
			timeout: Duration.seconds(15)
		});

        getIdentityLambda.addToRolePolicy(
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    "iam:ListGroupsForUser",
                    "iam:ListAttachedUserPolicies",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListAttachedGroupPolicies"
                ],
                resources: ["*"]
            })
        )

		const pushFindingLambda = new lambda.Function(this, "PushFindingLambda", {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/push-finding")),
			runtime: lambda.Runtime.PYTHON_3_8,
			handler: "index.lambda_handler",
			memorySize: 512,
		});

		pushFindingLambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: [
					"securityhub:BatchImportFindings",
					"secretsmanager:GetSecretValue"
				],
				resources: [
					"arn:aws:securityhub:ap-southeast-2:659855141795:product/659855141795/default",
					"*"
				],
			})
		);

		const interactiveSlackLambda = new lambda.Function(this, 'InteractiveSlackLambda', {
			code: lambda.Code.fromAsset(path.join(__dirname, "lambda/interactive-slack")),
			runtime: lambda.Runtime.PYTHON_3_8,    // execution environment
			memorySize: 512,
			handler: 'index.lambda_handler'        // file is "hello", function is "handler"
		});
		
			// defines an API Gateway REST API resource backed by our "hello" function.
		new apigw.LambdaRestApi(this, 'Endpoint', {
			handler: interactiveSlackLambda
		});

		interactiveSlackLambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: [
					"securityhub:BatchUpdateFindings"
				],
				resources: [
					"arn:aws:securityhub:ap-southeast-2:659855141795:hub/default"
				],
			})
		);

		// Configure steps
		const ingestEvent = new tasks.LambdaInvoke(this, "IngestEventStep", {
			lambdaFunction: ingestEventLambda,
			retryOnServiceExceptions: false,
			inputPath: "$",
			outputPath: "$",
		});

		const eventTypeChoice = new sfn.Choice(this, "EventTypeChoice");
        const canaryPass = new sfn.Pass(this, "CanaryPassStep");

		const macieJob = new tasks.LambdaInvoke(this, "MacieJobStep", {
			lambdaFunction: macieJobLambda,
			retryOnServiceExceptions: false,
			inputPath: "$.Payload",
			outputPath: "$",
		});

		const macieStatus = new tasks.LambdaInvoke(this, "MacieStatusStep", {
			lambdaFunction: macieStatusLambda,
			retryOnServiceExceptions: false,
			inputPath: "$.Payload",
			outputPath: "$",
		});

		const macieFinding = new tasks.LambdaInvoke(this, "MacieFindingStep", {
			lambdaFunction: macieFindingLambda,
			retryOnServiceExceptions: false,
			inputPath: "$.Payload",
			outputPath: "$",
		});

		const waitForMacieJob = new sfn.Wait(this, "WaitForMacieJob", {
			time: sfn.WaitTime.duration(Duration.seconds(60)),
		});
		waitForMacieJob.next(macieStatus);

		const checkMacieStatus = new sfn.Choice(this, "CheckMacieStatus");

        const getIdentity = new tasks.LambdaInvoke(this, "GetIdentityStep", {
            "lambdaFunction": getIdentityLambda,
            "retryOnServiceExceptions": false,
            "inputPath": "$.Payload",
            "outputPath": "$"
        });

        const addGeoIpStep = new tasks.LambdaInvoke(this, "AddGeoIpStep", {
			lambdaFunction: addGeoIpLambda,
			retryOnServiceExceptions: false,
			inputPath: "$.Payload",
			outputPath: "$",
		});

		const addSeverityStep = new tasks.LambdaInvoke(this, "AddSeverityStep", {
			lambdaFunction: addSeverityLambda,
			retryOnServiceExceptions: false,
			inputPath: "$.Payload",
			outputPath: "$",
		});

		const makeFinding = new tasks.LambdaInvoke(this, "MakeFindingStep", {
			lambdaFunction: makeFindingLambda,
			retryOnServiceExceptions: false,
			inputPath: "$.Payload",
			outputPath: "$",
		});

		const pushFinding = new tasks.LambdaInvoke(this, "PushFindingStep", {
			lambdaFunction: pushFindingLambda,
			retryOnServiceExceptions: false,
			inputPath: "$.Payload",
			outputPath: "$",
		});


		// Configure step function defintion
		const sfnDefinition = sfn.Chain
			.start(ingestEvent)
			.next(eventTypeChoice
				.when(
					sfn.Condition.stringEquals(
						"$.Payload.soaringEventType",
						"PII"
					),
					macieJob
					.next(macieStatus)
					.next(
						checkMacieStatus
							.when(
								sfn.Condition.stringEquals(
									"$.Payload.macieJobs.jobStatus",
									"COMPLETE"
								),
								macieFinding
							)
							.otherwise(waitForMacieJob)
					)
				)
                .when(
                    sfn.Condition.stringEquals(
                        "$.Payload.soaringEventType",
						"CANARY"
                    ),
                    canaryPass
                )
				.afterwards()
			)
            .next(getIdentity)
            .next(addGeoIpStep)
            .next(addSeverityStep)
            .next(makeFinding)
            .next(pushFinding);

		// Set up rest of infrastructure
		const stateMachine = new sfn.StateMachine(this, "SoaringSoln", {
			stateMachineName: "soar-stack",
			stateMachineType: sfn.StateMachineType.STANDARD,
			definition: sfnDefinition,
		});

		new Extract(this, "ExtractComponent", { sfn: stateMachine });
		Tags.of(this).add("OWNER", "team");
	}
}
