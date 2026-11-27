package org.example.keycloak.browsersession;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.common.util.UriUtils;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.protocol.oidc.utils.WebOriginsUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionManager;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Provider
@Vetoed
@Produces(MediaType.APPLICATION_JSON)
public final class SsoResource {
    private static final String AUTH_METHOD = "sso";
    private static final String CLIENT = "client";
    private static final String EXPIRATION = "expiration";
    private static final String ORIGIN = "Origin";
    private static final Pattern CHALLENGE_FORMAT = Pattern.compile("[A-Za-z0-9_-]{43}");

    private final KeycloakSession session;
    private final KeycloakContext context;
    private final RealmModel realm;
    private final int challengeTtl;

    SsoResource(KeycloakSession session, int challengeTtl) {
        this.session = session;
        this.context = session.getContext();
        this.realm = context.getRealm();
        this.challengeTtl = challengeTtl;
    }

    @POST
    @Path("init")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response init() {
        prepareResponse();
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (form == null) {
            throw error(400, "invalid_request", null);
        }
        String state = singleValue(form.get("state"));
        String token = singleValue(form.get("token"));
        String type = SsoAuthorization.tokenType(singleValue(form.get("token_type")));
        if (state == null || token == null || token.isBlank() || type == null) {
            throw error(400, "invalid_request", null);
        }

        EventBuilder event = event(EventType.CLIENT_LOGIN);
        ClientModel client = authenticateClient(form, event);
        SsoAuthorization.AuthorizedSession authorization = verifyToken(client, type, token);

        int now = Time.currentTime();
        long expiresIn = Math.min(challengeTtl, authorization.token().getExp() - now);
        if (expiresIn <= 0) {
            throw error(401, "invalid_token", type + " error=\"invalid_token\"");
        }
        String challenge = Base64Url.encode(SecretGenerator.getInstance().randomBytes(32));
        String key = challengeKey(challenge, state, type, token);
        session.singleUseObjects().put(key, expiresIn,
                Map.of(CLIENT, client.getId(), EXPIRATION, Long.toString(now + expiresIn)));
        event.session(authorization.userSession()).success();
        return Response.ok(Map.of("challenge", challenge, "expires_in", expiresIn, "state", state)).build();
    }

    @OPTIONS
    @Path("challenge")
    public Response preflight() {
        prepareResponse();
        context.getHttpResponse().setHeader("Vary", ORIGIN);
        String origin = requestOrigin();
        if (origin != null) {
            setCorsOrigin(origin);
            context.getHttpResponse().setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
            context.getHttpResponse().setHeader("Access-Control-Allow-Headers",
                    "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, "
                            + "Access-Control-Request-Headers, DPoP, Authorization");
            context.getHttpResponse().setHeader("Access-Control-Max-Age", "3600");
        }
        return Response.ok().build();
    }

    @GET
    @Path("challenge")
    public Response exchange() {
        prepareResponse();
        context.getHttpResponse().setHeader("Vary", ORIGIN);
        // A JAX-RS implementation can route HEAD to the GET handler.
        if (!"GET".equals(context.getHttpRequest().getHttpMethod())) {
            return Response.status(Response.Status.METHOD_NOT_ALLOWED).allow("GET", "OPTIONS")
                    .type(MediaType.APPLICATION_JSON_TYPE).build();
        }

        MultivaluedMap<String, String> query = context.getUri().getQueryParameters();
        String state = singleValue(query.get("state"));
        String challenge = singleValue(query.get("challenge"));
        if (state == null || challenge == null || !CHALLENGE_FORMAT.matcher(challenge).matches()) {
            throw error(400, "invalid_request", null);
        }
        String header = singleValue(context.getHttpRequest().getHttpHeaders().getRequestHeader(HttpHeaders.AUTHORIZATION));
        String[] credentials = header == null ? new String[0] : header.strip().split(" +", 2);
        String type = credentials.length == 2 ? SsoAuthorization.tokenType(credentials[0]) : null;
        if (type == null || credentials[1].isBlank()) {
            throw error(401, "invalid_token", "Bearer, DPoP");
        }
        String token = credentials[1];

        SingleUseObjectProvider challenges = session.singleUseObjects();
        String key = challengeKey(challenge, state, type, token);
        Map<String, String> issued = challenges.get(key);
        if (isExpired(issued)) {
            throw error(400, "invalid_grant", null);
        }
        ClientModel client = realm.getClientById(issued.get(CLIENT));
        if (!SsoAuthorization.isAllowedClient(client)) {
            throw error(403, "unauthorized_client", null);
        }
        context.setClient(client);
        allowBrowserOrigin(client);
        SsoAuthorization.AuthorizedSession authorization = verifyToken(client, type, token);

        // Only the request that removes the challenge may create a session, including on a clustered server.
        if (isExpired(challenges.remove(key))) {
            throw error(400, "invalid_grant", null);
        }
        createBrowserSession(client, authorization.userSession());
        return Response.ok(Map.of(), MediaType.APPLICATION_JSON_TYPE).build();
    }

    private ClientModel authenticateClient(MultivaluedMap<String, String> form, EventBuilder event) {
        String authorization = singleValue(context.getHttpRequest().getHttpHeaders().getRequestHeader(HttpHeaders.AUTHORIZATION));
        String clientId = singleValue(form.get("client_id"));
        String secret = singleValue(form.get("client_secret"));
        if (authorization != null && (clientId != null || secret != null)) {
            throw error(400, "invalid_request", null);
        }
        String challenge = authorization == null ? null : "Basic realm=\"sso\"";
        if (authorization == null ? clientId == null || clientId.isBlank() || secret == null || secret.isEmpty()
                : !authorization.regionMatches(true, 0, "Basic ", 0, 6) || authorization.substring(6).isBlank()) {
            throw error(401, "invalid_client", challenge);
        }

        AuthenticationProcessor processor = AuthorizeClientUtil.getAuthenticationProcessor(session, event);
        if (processor.authenticateClient() != null) {
            throw error(401, "invalid_client", challenge);
        }
        ClientModel client = processor.getClient();
        if (!SsoAuthorization.isAllowedClient(client)) {
            throw error(403, "unauthorized_client", null);
        }
        context.setClient(client);
        return client;
    }

    private SsoAuthorization.AuthorizedSession verifyToken(ClientModel client, String type, String token) {
        try {
            return SsoAuthorization.verify(session, client, type, token);
        } catch (VerificationException exception) {
            throw error(401, "invalid_token", type + " error=\"invalid_token\"");
        }
    }

    private void createBrowserSession(ClientModel client, UserSessionModel source) {
        UserModel user = source.getUser();
        UserSessionModel browserSession = new UserSessionManager(session).createUserSession(null, realm, user,
                user.getUsername(), context.getConnection().getRemoteAddr(), AUTH_METHOD, false, null, null,
                UserSessionModel.SessionPersistenceState.PERSISTENT);
        browserSession.setState(UserSessionModel.State.LOGGED_IN);
        String authTime = source.getNote(AuthenticationManager.AUTH_TIME);
        browserSession.setNote(AuthenticationManager.AUTH_TIME, authTime == null ? Integer.toString(source.getStarted()) : authTime);
        AuthenticationManager.createLoginCookie(session, realm, user, browserSession, context.getUri(), context.getConnection());
        AuthenticationManager.expireRememberMeCookie(session);

        boolean secure = isHttps();
        NewCookie ssoCookie = new NewCookie.Builder("KC_SSO_SESSION")
                .value(browserSession.getId())
                .path(AuthenticationManager.getRealmCookiePath(realm, context.getUri()))
                .httpOnly(true)
                .secure(secure)
                .sameSite(secure ? NewCookie.SameSite.NONE : NewCookie.SameSite.LAX)
                .build();
        context.getHttpResponse().setCookieIfAbsent(ssoCookie);
        event(EventType.LOGIN).client(client).user(user).session(browserSession)
                .detail(Details.AUTH_METHOD, AUTH_METHOD).success();
    }

    private void prepareResponse() {
        context.getHttpResponse().setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        context.getHttpResponse().setHeader("Pragma", "no-cache");
        context.getHttpResponse().setHeader("Referrer-Policy", "no-referrer");
        if (!realm.isEnabled() || (!isHttps() && realm.getSslRequired().isRequired(context.getConnection()))) {
            throw error(403, "access_denied", null);
        }
    }

    private boolean isHttps() {
        return "https".equals(context.getUri().getBaseUri().getScheme());
    }

    private void allowBrowserOrigin(ClientModel client) {
        String origin = requestOrigin();
        if (origin == null) {
            return;
        }
        if (!UriUtils.getOrigin(context.getUri().getBaseUri()).equals(origin)
                && (!(origin.startsWith("https://") || origin.startsWith("http://"))
                || !WebOriginsUtils.resolveValidWebOrigins(session, client).contains(origin))) {
            throw error(403, "access_denied", null);
        }
        setCorsOrigin(origin);
    }

    private String requestOrigin() {
        return singleValue(context.getHttpRequest().getHttpHeaders().getRequestHeader(ORIGIN));
    }

    private void setCorsOrigin(String origin) {
        context.getHttpResponse().setHeader("Access-Control-Allow-Origin", origin);
        context.getHttpResponse().setHeader("Access-Control-Allow-Credentials", "true");
    }

    private EventBuilder event(EventType type) {
        return new EventBuilder(realm, session, context.getConnection()).event(type);
    }

    private String challengeKey(String challenge, String state, String type, String token) {
        return "browser-session:" + realm.getId() + ":" + digest(challenge + ':' + digest(state) + ':' + type + ':' + digest(token));
    }

    private static String digest(String value) {
        return Base64Url.encode(HashUtils.hash("SHA-256", value.getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean isExpired(Map<String, String> challenge) {
        return challenge == null || Long.parseLong(challenge.get(EXPIRATION)) <= Time.currentTime();
    }

    private static String singleValue(List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        if (values.size() != 1) {
            throw error(400, "invalid_request", null);
        }
        return values.get(0);
    }

    private static WebApplicationException error(int status, String code, String authenticationChallenge) {
        Response.ResponseBuilder response = Response.status(status).type(MediaType.APPLICATION_JSON_TYPE)
                .entity(Map.of("error", code));
        if (authenticationChallenge != null) {
            response.header(HttpHeaders.WWW_AUTHENTICATE, authenticationChallenge);
        }
        return new WebApplicationException(response.build());
    }
}
