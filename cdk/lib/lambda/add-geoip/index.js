import bent from 'bent';
const apiKey = "e90b18e397b16a81c7d280bff4e369bc";

export async function lambda_handler(event, _context) {
    // Ensure structure is as-expected
    const result = event;
    if (result?.detail === undefined) {
        console.error(event);
        throw new TypeError("Details is missing from event.");
    }

    // Grab GeoIP details
    const sourceIpAddress = getIpAddress(event);
    const geoIpDetails = await getGeoIpDetails(sourceIpAddress);

    // Insert into result
    result.detail.ipDetails = geoIpDetails;
    return result;
}

async function getGeoIpDetails(sourceIpAddress) {
    const apiCall = bent(`http://api.ipstack.com/`, "GET", "json", 200);
    const response = await apiCall(`${sourceIpAddress}?access_key=${apiKey}`);
    return response;
}

function getIpAddress(event) {
    const sourceIpAddress = event?.detail?.sourceIPAddress;
    if (sourceIpAddress === undefined) {
        console.error(event);
        throw new TypeError("Source IP address is missing from event.");
    }

    return sourceIpAddress;
}
