import { SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as Cdk from '../lib/target-stack';

// Snapshots the state of the stack (if it doesn't match update the tests)
it('matches the snapshot', () => {
  const app = new cdk.App();
  const stack = new Cdk.TargetStack(app, 'MyTestStack');
  expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});
