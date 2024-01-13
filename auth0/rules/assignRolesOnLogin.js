const { ManagementClient } = require('auth0');

exports.onExecutePostLogin = async (event, api) => {
    // This rule does not apply to unverified users - never assign a privileged role without verification!
    if (!event.user.email || !event.user.email_verified) {
        return;
    }

    const maybeEmailDomain = 'ifloydrose@gmail.com';
    // const emailSplit = event.user.email.split('@');
    // const isMaybeEmployee = emailSplit[emailSplit.length - 1].toLowerCase() === maybeEmailDomain;

    if (event.user.email.toLowerCase() !== maybeEmailDomain) {
        return;
    }

    const cli = new ManagementClient({
        domain: event.secrets.AUTH0_DOMAIN,
        clientId: event.secrets.AUTH0_CLIENT_ID,
        clientSecret: event.secrets.AUTH0_CLIENT_SECRET,
        scope: 'update:users',
    });

    const admins = [maybeEmailDomain];

    const rolesToAssign = [];

    // https://auth0.com/docs/rules/configuration#use-the-configuration-object
    if (admins.includes(event.user.email)) {
        rolesToAssign.push(event.secrets.ADMIN_ROLE_ID);
    }

    // https://auth0.com/docs/rules/configuration#use-the-configuration-object
    // if (isMaybeEmployee) {
    //     rolesToAssign.push(event.secrets.BETA_TESTER_ROLE_ID);
    // }

    // If we make it here, we know the user has verified their email and their email is in the Maybe Finance Gmail domain
    try {
        await cli.assignRolestoUser({ id: event.user.user_id }, { roles: rolesToAssign });
    } catch (err) {
        console.log(err);
    }
};
