const aws = require('aws-sdk');
const iam = new aws.IAM();

exports.handler = async (event, context) => {
    const response = event;

    if (typeof(response.detail.userIdentity.arn) == "undefined") return;

    const username = response.detail.userIdentity.arn.split("/").pop();
    response.detail.userPolicies = await getUserPolicies(username);

    if (typeof(response.detail.userIdentity.sessionContext) != "undefined") {
        const role = response.detail.userIdentity.sessionContext.sessionIssuer.userName;
        response.detail.rolePolicies = await getRolePolicies(role);
    }

    response.detail.userGroups = await getGroups(username);
    for (const group of response.detail.userGroups) {
        group.Policies = await getGroupPolicies(group.GroupName);
    }

    return event;
};

const getGroups = async (user) => {
    const params = { UserName: user };
    const result = await iam.listGroupsForUser(params).promise();
    return result.Groups;
};

const getUserPolicies = async (user) => {
    const params = { UserName: user };
    const result = await iam.listAttachedUserPolicies(params).promise();
    return result.AttachedPolicies;
};

const getRolePolicies = async (role) => {
    const params = { RoleName: role };
    const result = await iam.listAttachedRolePolicies(params).promise();
    return result.AttachedPolicies;
};

const getGroupPolicies = async (group) => {
    const params = { GroupName: group };
    const result = await iam.listAttachedGroupPolicies(params).promise();
    return result.AttachedPolicies;
};
