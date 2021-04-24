/**
 * Custom pattern matchers
 * The data passed in is determined by the path
 */
const cidr = require("ip-cidr");

/**
 * Checks if IP outside of domain range
 * @param {*} data
 */
function isOutOfOperatingZone(data) {
  // Domain ranges
  const ranges = [
    new cidr("129.94.0.0/16"),
    new cidr("131.236.0.0/16"),
    new cidr("149.171.0.0/16"),
  ];

  return !ranges.some((block) => block.contains(data));
}

module.exports = {
  isOutOfOperatingZone,
};
