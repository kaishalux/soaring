const aws = require('aws-sdk');
const iam = new aws.IAM();

exports.handler = async (event, context) => {
    const response = event[0];

    if (typeof(response.user.userIdentity.arn) == "undefined") return;

    const username = response.user.userIdentity.arn.split("/").pop();
    response.user.userPolicies = await getUserPolicies(username);

    if (typeof(response.user.userIdentity.sessionContext) != "undefined") {
        const role = response.user.userIdentity.sessionContext.sessionIssuer.userName;
        response.user.rolePolicies = await getRolePolicies(role);
    }

    response.user.groups = await getGroups(username);
    for (const group of response.user.groups) {
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
