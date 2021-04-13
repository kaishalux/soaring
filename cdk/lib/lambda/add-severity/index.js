import yaml from "js-yaml";
import * as severities from "./lib/severities";

// This soft-caches the files in Lambda memory
import fs from "fs";
const config = yaml.load(fs.readFileSync("./config/config.yml"));
const patternDefinitions = yaml.load(fs.readFileSync("./config/patterns.yml"))
  .patterns;

const baseline = config.baseline;

function matchTopLevelPatterns(event) {
  let totalSeverity = 0;
  const matches = [];

  Object.entries(config.patterns).forEach(([key, value]) => {
    // Check top-level patterns
    let localSeverity = severities.getSeverity(key, event, value.severity);

    // If matches add on co-factor severities
    if (localSeverity !== null) {
      const match = {
        id: key,
        description: patternDefinitions[key]?.description || "<No description>",
        cofactors: [],
      };

      // Calculate cofactor severities
      value.cofactors.forEach((cofactor) => {
        const cofactorSeverity = severities.getSeverity(
          cofactor.id,
          event,
          cofactor.severity
        );

        if (cofactorSeverity !== null) {
          localSeverity += cofactorSeverity;
          match["cofactors"].push({
            id: cofactor.id,
            description:
              patternDefinitions[cofactor.id]?.description ||
              "<No description>",
            severity: severities.getDisplaySeverity(cofactorSeverity),
          });
        }
      });

      match["severity"] = severities.getDisplaySeverity(localSeverity);
      matches.push(match);
      totalSeverity += localSeverity;
    }
  });

  return {
    severity: severities.getDisplaySeverity(totalSeverity),
    matches,
    shouldAlert: totalSeverity >= baseline,
  };
}

module.exports.handler = async (event, _context) => {
  const result = event;
  result["severity"] = matchTopLevelPatterns(event);
  return result;
};
