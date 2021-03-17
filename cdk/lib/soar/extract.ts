/**
 * This file contains the SOAR stack
 */

import { ReadWriteType, Trail } from '@aws-cdk/aws-cloudtrail';
import { EventBus, Rule } from '@aws-cdk/aws-events';
import { SfnStateMachine } from '@aws-cdk/aws-events-targets';
import { StateMachine } from '@aws-cdk/aws-stepfunctions';
import * as cdk from '@aws-cdk/core';
import * as patterns from "./patterns.json";

export interface ExtractProps {
    sfn: StateMachine;
}

export class Extract extends cdk.Construct {
    constructor(scope: cdk.Construct, id: string, props: ExtractProps) {
        super(scope, id);

        // Enable CloudTrail
        const auditTrail = new Trail(this, "SecurityTrail", {
            "enableFileValidation": true,
            "managementEvents": ReadWriteType.ALL,
        });

        auditTrail.logAllS3DataEvents();

        // Enable EventBridge
        const targetSfn = new SfnStateMachine(props.sfn);

        // Configure EventBridge pattern matches in patterns.json
        // See https://docs.aws.amazon.com/eventbridge/latest/userguide/filtering-examples-structure.html
        Object.entries(patterns).forEach(([key, pattern]) => {
            new Rule(this, key, {
                "enabled": true,
                "eventPattern": pattern,
                "targets": [targetSfn]
            });
        });
    }
}
