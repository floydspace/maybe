exports.onExecutePostLogin = async (event, api) => {
    // Does not have to be a valid URL, just has to be unique and start with http / https
    const namespace = 'https://maybe.co';

    const assignedRoles = (event.authorization || {}).roles;

    let identityClaim;

    if (event.user.identities && event.user.identities.length) {
        const primaryIdentities = event.user.identities.filter((identity) => {
            // https://auth0.com/docs/manage-users/user-accounts/user-account-linking#how-it-works
            const isSecondary = 'profileData' in identity;

            return !isSecondary;
        });

        if (primaryIdentities.length === 0) {
            identityClaim = undefined;
        }

        // Based on prior checks, this should represent the primary identity
        const primaryIdentity = primaryIdentities[0];

        identityClaim = {
            connection: primaryIdentity.connection,
            provider: primaryIdentity.provider,
            isSocial: primaryIdentity.isSocial,
        };
    }

    // Access token claims are populated on the parsed server-side JWT
    api.accessToken.setCustomClaim(`${namespace}/name`, event.user.name);
    api.accessToken.setCustomClaim(`${namespace}/email`, event.user.email);
    api.accessToken.setCustomClaim(`${namespace}/picture`, event.user.picture);
    api.accessToken.setCustomClaim(`${namespace}/roles`, assignedRoles);
    api.accessToken.setCustomClaim(`${namespace}/user-metadata`, event.user.user_metadata);
    api.accessToken.setCustomClaim(`${namespace}/app-metadata`, event.user.app_metadata);
    api.accessToken.setCustomClaim(`${namespace}/primary-identity`, identityClaim);

    // ID token claims are populated in the parsed client-side React hook
    api.idToken.setCustomClaim(`${namespace}/roles`, assignedRoles);
    api.idToken.setCustomClaim(`${namespace}/user-metadata`, event.user.user_metadata);
    api.idToken.setCustomClaim(`${namespace}/app-metadata`, event.user.app_metadata);
    api.idToken.setCustomClaim(`${namespace}/primary-identity`, identityClaim);
};
