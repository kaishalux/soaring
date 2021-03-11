#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { TargetStack } from '../lib/target-stack';

const platformEnv = {
    region: "ap-southeast-2"
}

const app = new cdk.App();
new TargetStack(app, 'TargetStack', {
    env: platformEnv
});
