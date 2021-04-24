const yaml = require("js-yaml");
const matching = require("./matching");

const fs = require("fs");
const path = require("path");
const config = yaml.load(
  fs.readFileSync(path.join(__dirname, "../config/config.yml"))
);
const severities = config.severity;

function getSeverity(name, event, severity) {
  if (matching.matchPattern(event, name)) {
    return severities[severity];
  }

  return null;
}

function getNamedSeverity(severity) {
  return (
    Object.keys(severities).find((key) => severity <= severities[key]) ||
    "CRITICAL"
  );
}

function getDisplaySeverity(severity) {
  return {
    description: getNamedSeverity(severity),
    score: severity,
  };
}

module.exports = {
  getSeverity,
  getNamedSeverity,
  getDisplaySeverity,
};
