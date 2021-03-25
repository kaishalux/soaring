console.log('Loading function');

const aws = require('aws-sdk');
const zlib = require('zlib');

const s3 = new aws.S3();
const iam = new aws.IAM();

exports.handler = async (event, context) => {
    // console.log('Received event:', JSON.stringify(event, null, 2));

    const bucket = event.Records[0].s3.bucket.name;
    const key = event.Records[0].s3.object.key;

    const data = await getObject(bucket, key);
    const log = await getLog(data.Body);

    var result = await groupEventsByUser(log);

    for (var i = 0; i < result.Users.length; i++) {
        var username = result.Users[i].userIdentity.arn.split("/").pop();
        // result.Users[i].Policies = await getUserPolicies(username);

        result.Users[i].Groups = await getGroups(username);
        result.Users[i].Groups.Policies = [];
        for (var j = 0; j < result.Users[i].Groups.length; j++) {
            result.Users[i].Groups[j].Policies = await getGroupPolicies(result.Users[i].Groups[j].GroupName);
        }
    }

    return result;
};

const getObject = async (bucket, key) => {
    const params = {
        Bucket: bucket,
        Key: key,
    };
    try {
        const data = await s3.getObject(params).promise();
        return(data);
    } catch (err) {
        console.log(err);
        const message = `Error getting object ${key} from bucket ${bucket}. Make sure they exist and your bucket is in the same region as this function.`;
        throw new Error(message);
    }
};

const getLog = async (data) => {
    return new Promise((resolve, reject) => {
        try {
            zlib.gunzip(data, (err, buffer) => {
                if (err) return reject(err);
                const body = buffer.toString();
                // console.log(body);
                var json;
                try {
                    json = JSON.parse(body);
                    // console.log(json);
                    resolve(json);
                } catch (err) {
                    return reject(err);
                }
            });
        } catch (err) {
            reject(err);
        }
    });
};

const groupEventsByUser = async (data) => {
    var result = {};
    result.Users = [];
    for (var i = 0; i < data.Records.length; i++) {
        // Initial user
        if (result.Users.length == 0) {
            result.Users.push({
                userIdentity: data.Records[i].userIdentity,
                Policies: [],
                Groups: [],
                Events: []
            });
        }

        for (var j = 0; j < result.Users.length; j++) {
            if (result.Users[j].userIdentity.arn != data.Records[i].userIdentity.arn) {
                // New user
                result.Users.push({
                    userIdentity: data.Records[i].userIdentity,
                    Events: [{
                        eventTime: data.Records[i].eventTime,
                        eventName: data.Records[i].eventName
                    }]
                });
                break;
            } else {
                // Append record to existing user
                result.Users[j].Events.push({
                    eventTime: data.Records[i].eventTime,
                    eventName: data.Records[i].eventName
                });
                break;
            }
        }
    }

    return result;
};

const getGroups = async (user) => {
    var params = { UserName: user };
    // console.log(params);
    return new Promise((resolve, reject) => {
        try {
            iam.listGroupsForUser(params, (err, data) => {
                if (err) return reject(err);
                // console.log(data);
                resolve(data.Groups);
            });
        } catch (err) {
            reject(err);
        }
    });
};

const getUserPolicies = async (user) => {
    var params = { UserName: user };
    return new Promise((resolve, reject) => {
        try {
            iam.listAttachedUserPolicies(params, (err, data) => {
                if (err) return reject(err);
                resolve(data.AttachedPolicies);
            });
        } catch (err) {
            reejct(err);
        }
    });
};

const getRolePolicies = async (role) => {
    var params = { RoleName: role };
    return new Promise((resolve, reject) => {
        try {
            iam.listAttachedRolePolicies(params, (err, data) => {
                if (err) return reject(err);
                resolve(data.AttachedPolicies);
            });
        } catch (err) {
            reejct(err);
        }
    });
};

const getGroupPolicies = async (group) => {
    var params = { GroupName: group };
    return new Promise((resolve, reject) => {
        try {
            iam.listAttachedGroupPolicies(params, (err, data) => {
                if (err) return reject(err);
                resolve(data.AttachedPolicies);
            });
        } catch (err) {
            reejct(err);
        }
    });
};