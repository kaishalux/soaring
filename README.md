# SOARing

By [@jasnkapdia](https://github.com/jasnkapadia) [@soogoi](https://github.com/soogoi) [@taliagok](https://github.com/taliagok) [@immanuelabosh](https://github.com/immanuelabosh) [@gawdn](https://github.com/gawdn)

_This project was made for UNSW Security Engineering Workshop as a SECEdu x AWS initiative._

SOARing is an user-extensible security alerting platform. It has two primary goals:

- Reduce alert fatigue
- Increase useful context for SecOps

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE) for the full license.

## Installation

### Prerequisites

- [Node.js](https://nodejs.org/) v.15.11.x
- [Python](https://www.python.org/downloads/) v3.9.x
- AWS CLI
- An AWS environment you want to deploy to

### Steps

1. Install the prerequisites.
1. Clone this repository.
1. Open a terminal in `./cdk` and install NPM dependencies using

```bash
npm install
```

---

## Technology Stack

- AWS CDK for infrastructure
- TypeScript for CDK
- Python for Lambdas

## Usage

1. Configure your [AWS credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html) for the AWS environment you want to deploy to
1. You may wish to change the region where the stack deploys. By default it deploys to `ap-southeast-2`. You can change it in `cdk/bin/cdk.ts`

1. Deploy the example target stack and the SOAR stack to your AWS environment using

   ```bash
   cdk deploy --all
   ```

   or to only install the SOAR solution you can do

   ```bash
   cdk deploy SoarStack
   ```

1. The alerting configuration is setup with some default rules. You may edit them in `./lib/lambda/add-severity/config.yml` and `./lib/lambda/add-severity/patterns.yml`. See [Configuration](#configuration) for the rules.

## Configuration

The alerting configuration is setup with some default rules. You may edit them in `./lib/lambda/add-severity/config.yml` and `./lib/lambda/add-severity/patterns.yml`.

First set up some patterns. These rules match on the event JSON passed in by EventBridge.

```yaml
rule_id:
  description: Rule description (displayed in alert)
  # JSON Path to select field to match against in event JSON
  path: $.soaringBucketType
  # Pattern to match using
  pattern:
    # There are three types of pattern matches
    #   matches: value is regex pattern
    #   anything_but: value is regex pattern but inverted
    #   custom: uses a custom JS function defined in `./lib/lambda/add-severity/matchers/index.js`
    type: matches
    value: OTHER
```

We then need to configure the `config.yml`. The top holds the weightings for severities. We **don't** recommend changing these values as they are used by Security Hub. The baseline is the minimum weighting required for an alert to be sent.

```yaml
baseline: 1
severity:
  INFORMATIONAL: 0.2
  LOW: 0.5
  MEDIUM: 1
  HIGH: 2
  CRITICAL: 4
```

Below that are patterns.
There are "top-level-rules" which matches the id of the pattern defined in `patterns.yml`. Each rule has a severity which is defined above. Each top-level-rule has cofactors which raise the severity of the top-level-rule if they match. Note that severities can differ between rules since the relevance of the cofactor changes depending on the rule.

```yaml
top_level_pattern_id:
  severity: INFORMATIONAL
  cofactors:
    - id: example_cofactor
      severity: HIGH
    - id: another_example_cofactor
      severity: LOW
```

## Development

To run tests run the following command in the `cdk/` directory.

```bash
npm test
```

## Additional Documentation

Additional documentation including product and solution brainstorm, well-architected review and project timeline is contained in `docs/`.

## Getting help

If you have questions, concerns, bug reports, etc, please file an issue in this repository's Issue Tracker.

## Getting involved

You might like to get involved if you're interested in providing extra features, fixing bugs, or otherwise want to help support this product.

### Contributing

To get started please fork the repository. You may then pull request your changes from your fork.
