import yaml from "js-yaml";
import jsonpath from "jsonpath";
import * as matchers from "../matchers";

import fs from "fs";
const patternDefinitions = yaml.load(fs.readFileSync("./config/patterns.yml"));

function matchRegex(patternName, definition, data) {
  if (typeof definition?.pattern?.value !== "string") {
    throw new TypeError(
      `Pattern matcher value for ${patternName} must be a string.`
    );
  }

  const pattern = new RegExp(definition.pattern.value);
  return pattern.test(data);
}

function matchAnythingBut(patternName, definition, data) {
  return !matchRegex(patternName, definition, data);
}

function matchCustom(patternName, definition, data) {
  if (
    Object.prototype.hasOwnProperty.call(matchers, definition.pattern.value)
  ) {
    return matchers[definition.pattern.value](data);
  }

  throw new Error(
    `Custom pattern matcher ${definition.pattern.value} for ${patternName} does not exist.`
  );
}

function getMatcher(patternName, definition, data) {
  const patternMatchers = {
    matches: matchRegex,
    anything_but: matchAnythingBut,
    custom: matchCustom,
  };

  if (
    !Object.prototype.hasOwnProperty.call(
      patternMatchers,
      definition.pattern.type
    )
  ) {
    throw new Error(
      `Pattern matcher type ${definition.pattern.type} for ${patternName} is not valid.`
    );
  }

  return patternMatchers[definition.pattern.type](
    patternName,
    definition,
    data
  );
}

/** Logic for matching patterns */
export function matchPattern(event, patternName) {
  const definition = patternDefinitions.patterns[patternName];
  if (definition?.path === undefined)
    throw new TypeError(`Missing path for ${patternName}`);
  if (definition?.pattern === undefined)
    throw new TypeError(`Missing pattern for ${patternName}`);

  let data;
  try {
    data = jsonpath.value(event, definition.path);
  } catch (e) {
    console.log(`Skipping: Couldn't match event using ${patternName}`);
    return false;
  }

  const isMatching = getMatcher(patternName, definition, data);
  return isMatching;
}
