const aws = require('aws-sdk');
const iam = new aws.IAM();

exports.handler = async (event, context) => {
    if (typeof(event[0].user.userIdentity.arn) == "undefined") return;

    const username = event[0].user.userIdentity.arn.split("/").pop();
    event[0].user.userPolicies = await getUserPolicies(username);

    if (typeof(event[0].user.userIdentity.sessionContext) != "undefined") {
        var role = event[0].user.userIdentity.sessionContext.sessionIssuer.userName;
        event[0].user.rolePolicies = await getRolePolicies(role);
    }

    event[0].user.groups = await getGroups(username);
    for (var i = 0; i < event[0].user.groups.length; i++) {
        event[0].user.groups[i].Policies = await getGroupPolicies(event[0].user.groups[i].GroupName);
    }

    return event;
};

const getGroups = async (user) => {
    const params = { UserName: user };
    return new Promise((resolve, reject) => {
        try {
            iam.listGroupsForUser(params, (err, data) => {
                if (err) return reject(err);
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
            reject(err);
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
            reject(err);
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
            reject(err);
        }
    });
};
