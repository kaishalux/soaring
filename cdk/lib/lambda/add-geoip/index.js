import bent from "bent";
const AWS = require("aws-sdk");
const region = "ap-southeast-2";

// Requires secret to already exist in form {"secret": "XXXXX"}
const secretName = "prod/Soaring/ipstack";

// Cache secret manager
const secretManagerClient = new AWS.SecretsManager({
  region,
});

async function getApiKey() {
  const apiKey = await secretManagerClient
    .getSecretValue({ SecretId: secretName })
    .promise();
  return JSON.parse(apiKey.SecretString).secret;
}

async function getGeoIpDetails(sourceIpAddress) {
  const apiCall = bent(`http://api.ipstack.com/`, "GET", "json", 200);
  const apiKey = await getApiKey();
  const response = await apiCall(`${sourceIpAddress}?access_key=${apiKey}`);
  return response;
}

function getIpAddress(event) {
  const sourceIpAddress = event?.detail?.sourceIPAddress;
  if (sourceIpAddress === undefined) {
    throw new TypeError("Source IP address is missing from event.");
  }

  return sourceIpAddress;
}

export async function lambda_handler(event, _context) {
  // Ensure structure is as-expected
  const result = event;
  if (result?.detail === undefined) {
    throw new TypeError("Details is missing from event.");
  }
  // Grab GeoIP details
  const sourceIpAddress = getIpAddress(event);
  const geoIpDetails = await getGeoIpDetails(sourceIpAddress);

  // Insert into result
  result.detail.ipDetails = geoIpDetails;
  return result;
}
