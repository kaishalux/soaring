#!/usr/bin/env node
import * as cdk from "@aws-cdk/core";
import { TargetStack } from "../lib/target-stack";
import { SoarStack } from "../lib/soar-stack";

const platformEnv = {
  region: "ap-southeast-2",
};

const app = new cdk.App();
new TargetStack(app, "TargetStack", {
  env: platformEnv,
});

new SoarStack(app, "SoarStack", {
  env: platformEnv,
});
