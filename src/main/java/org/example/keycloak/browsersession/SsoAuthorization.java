package org.example.keycloak.browsersession;

import org.keycloak.TokenVerifier;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.SessionExpirationUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionCrossDCManager;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.util.TokenUtil;

import static java.util.concurrent.TimeUnit.SECONDS;

final class SsoAuthorization {
    static String tokenType(String type) {
        if (TokenUtil.TOKEN_TYPE_BEARER.equalsIgnoreCase(type)) {
            return TokenUtil.TOKEN_TYPE_BEARER;
        }
        if (DPoPUtil.DPOP_SCHEME.equalsIgnoreCase(type)) {
            return DPoPUtil.DPOP_SCHEME;
        }
        return null;
    }

    static boolean isAllowedClient(ClientModel client) {
        if (client == null || !client.isEnabled() || client.isPublicClient() || client.isBearerOnly()
                || !OIDCLoginProtocol.LOGIN_PROTOCOL.equals(client.getProtocol())
                || !"true".equalsIgnoreCase(client.getAttribute("browser-session.enabled"))) {
            return false;
        }
        String authenticator = client.getClientAuthenticatorType();
        return authenticator == null || ClientIdAndSecretAuthenticator.PROVIDER_ID.equals(authenticator);
    }

    static AuthorizedSession verify(KeycloakSession session, ClientModel client, String type, String encodedToken)
            throws VerificationException {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        AccessToken token = session.tokens().decode(encodedToken, AccessToken.class);
        if (token == null || token.getId() == null || token.getIat() == null || token.getExp() == null
                || token.getExp() <= Time.currentTime() || token.getSessionState() == null
                || !type.equalsIgnoreCase(token.getType()) || !client.getClientId().equals(token.getIssuedFor())) {
            throw new VerificationException("Invalid access token");
        }

        TokenVerifier.createWithoutSignature(token).withChecks(
                TokenVerifier.IS_ACTIVE,
                new TokenVerifier.RealmUrlCheck(Urls.realmIssuer(context.getUri().getBaseUri(), realm.getName())),
                new TokenManager.NotBeforeCheck(Math.max(realm.getNotBefore(), client.getNotBefore())),
                new TokenManager.TokenRevocationCheck(session)).verify();

        UserSessionModel userSession = new UserSessionCrossDCManager(session)
                .getUserSessionWithClient(realm, token.getSessionState(), false, client.getId());
        if (!AuthenticationManager.isSessionValid(realm, userSession)
                || userSession.getState() != UserSessionModel.State.LOGGED_IN
                || token.isIssuedBeforeSessionStart(userSession.getStarted())) {
            throw new VerificationException("Inactive user session");
        }

        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
        if (clientSession == null || token.isIssuedBeforeSessionStart(clientSession.getStarted())
                || !isClientSessionActive(realm, client, userSession, clientSession)) {
            throw new VerificationException("Inactive client session");
        }

        UserModel user = userSession.getUser();
        if (user == null || !user.isEnabled() || user.getServiceAccountClientLink() != null) {
            throw new VerificationException("Ineligible user");
        }
        TokenVerifier.createWithoutSignature(token)
                .withChecks(TokenManager.NotBeforeCheck.forModel(session, realm, user)).verify();
        verifyTokenBinding(session, client, type, encodedToken, token);
        return new AuthorizedSession(token, userSession);
    }

    private static boolean isClientSessionActive(RealmModel realm, ClientModel client, UserSessionModel userSession,
                                                  AuthenticatedClientSessionModel clientSession) {
        long idle = SessionExpirationUtils.calculateClientSessionIdleTimestamp(false, userSession.isRememberMe(),
                SECONDS.toMillis(clientSession.getTimestamp()), realm, client);
        long max = SessionExpirationUtils.calculateClientSessionMaxLifespanTimestamp(false, userSession.isRememberMe(),
                SECONDS.toMillis(clientSession.getStarted()), SECONDS.toMillis(userSession.getStarted()), realm, client);
        return SECONDS.toMillis(Time.currentTime()) < Math.min(idle, max);
    }

    private static void verifyTokenBinding(KeycloakSession session, ClientModel client, String type,
                                           String encodedToken, AccessToken token) throws VerificationException {
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
        AccessToken.Confirmation confirmation = token.getConfirmation();
        if (TokenUtil.TOKEN_TYPE_BEARER.equals(type)) {
            if (confirmation != null || config.isUseDPoP() || config.isUseMtlsHokToken()) {
                throw new VerificationException("Bearer token is not permitted");
            }
            return;
        }

        if (!Profile.isFeatureEnabled(Profile.Feature.DPOP) || config.isUseMtlsHokToken()
                || confirmation == null || confirmation.getCertThumbprint() != null) {
            throw new VerificationException("DPoP token is not permitted");
        }

        KeycloakContext context = session.getContext();
        var proofs = context.getHttpRequest().getHttpHeaders().getRequestHeader("DPoP");
        if (proofs == null || proofs.size() != 1) {
            throw new VerificationException("A DPoP proof is required");
        }
        try {
            DPoP proof = new DPoPUtil.Validator(session).request(context.getHttpRequest()).uriInfo(context.getUri())
                    .accessToken(encodedToken).validate();
            DPoPUtil.validateBinding(token, proof);
        } catch (RuntimeException malformedProof) {
            // Keycloak's validator can throw unchecked exceptions when parsing malformed JOSE headers or JWKs.
            throw new VerificationException("Invalid DPoP proof");
        }
    }

    record AuthorizedSession(AccessToken token, UserSessionModel userSession) {
    }
}
