console.log('Loading function');

const aws = require('aws-sdk');
const zlib = require('zlib');

const s3 = new aws.S3();
const iam = new aws.IAM();

exports.handler = async (event, context) => {
    // console.log('Received event:', JSON.stringify(event, null, 2));

    const bucket = event.Records[0].s3.bucket.name;
    const key = event.Records[0].s3.object.key;
    const params = {
        Bucket: bucket,
        Key: key,
    };

    try {
        const data = await s3.getObject(params).promise();
        return new Promise((resolve, reject) => {
            try {
                zlib.gunzip(data.Body, (err, buffer) => {
                    if (err) return reject(err);
                    const body = buffer.toString();
                    // console.log(body);
                    var json;
                    try {
                        json = JSON.parse(body);
                        console.log(json);
                    } catch (err) {
                        return reject(err);
                    }

                    // const params = {
                    //     UserName: json.Records[0].userIdentity.userName
                    // };
                    // try {
                    //     iam.listGroupsForUser(params, (err, data) => {
                    //         if (err) return reject(err);
                    //         // console.log(data);
                    //         resolve(data.Groups);
                    //     });
                    // } catch (err) {
                    //     reject(err);
                    // }
                    var result = {};
                    result.Users = [];
                    var n = 0;
                    for (var i = 0; i < json.Records.length; i++) {
                        // Initial user
                        if (n == 0) {
                            result.Users.push({
                                userIdentity: json.Records[i].userIdentity,
                                // Groups: getGroups(json.Records[i].userIdentity.userName),
                                Events: []
                            });
                            n++;
                        }

                        for (var j = 0; j < n; j++) {
                            if (result.Users[j].userIdentity.userName != json.Records[i].userIdentity.userName) {
                                // New user
                                result.Users.push({
                                    userIdentity: json.Records[i].userIdentity,
                                    Events: [{
                                        eventTime: json.Records[i].eventTime,
                                        eventName: json.Records[i].eventName
                                    }]
                                });
                                n++;
                                break;
                            } else {
                                // Append record to existing user
                                result.Users[j].Events.push({
                                    eventTime: json.Records[i].eventTime,
                                    eventName: json.Records[i].eventName
                                });
                                break;
                            }
                        }
                    }
                    resolve(result);
                });
            } catch (err) {
                reject(err);
            }
        });
    } catch (err) {
        console.log(err);
        const message = `Error getting object ${key} from bucket ${bucket}. Make sure they exist and your bucket is in the same region as this function.`;
        console.log(message);
        throw new Error(message);
    }
};
