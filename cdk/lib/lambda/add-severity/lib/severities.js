import yaml from "js-yaml";
import * as matching from "./matching";

import fs from "fs";
const config = yaml.load(fs.readFileSync("./config/config.yml"));
const severities = config.severity;

export function getSeverity(name, event, severity) {
  if (matching.matchPattern(event, name)) {
    return severities[severity];
  }

  return null;
}

export function getNamedSeverity(severity) {
  return (
    Object.keys(severities).find((key) => severity <= severities[key]) ||
    "CRITICAL"
  );
}

export function getDisplaySeverity(severity) {
  return {
    description: getNamedSeverity(severity),
    score: severity,
  };
}
