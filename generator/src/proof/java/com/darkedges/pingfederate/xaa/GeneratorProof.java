package com.darkedges.pingfederate.xaa;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.wstrust.model.SecurityToken;
import org.sourceid.wstrust.model.StringSecurityToken;
import org.sourceid.wstrust.plugin.TokenProcessingException;
import org.sourceid.wstrust.plugin.generate.TokenContext;
import org.sourceid.websso.wrapper.OutMessageContext;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientManager;
import org.sourceid.oauth20.handlers.AccessTokenRequestException;
import org.sourceid.oauth20.handlers.process.exchange.TokenExchangeAudienceParameterValidator;
import org.sourceid.oauth20.exchange.domain.TokenExchangeGeneratorMapping;
import org.sourceid.oauth20.exchange.domain.TokenExchangeGeneratorPolicy;
import org.sourceid.oauth20.exchange.manager.TokenExchangeGeneratorPolicyManager;
import org.sourceid.oauth20.handlers.process.exchange.TokenExchangeRequest;
import org.sourceid.oauth20.handlers.process.exchange.execution.impl.TokenExchangeGeneratorPolicySelector;

/** Offline proof using actual PF 12.3.3 libraries. Run via build.ps1; never packaged in the plugin. */
public final class GeneratorProof {
    private static final long NOW = Instant.now().getEpochSecond();
    private static int passed;
    private static KeyPair key;

    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        key = kpg.generateKeyPair();
        IdJagTokenGenerator generator = generator();
        StringSecurityToken token = generator.generateToken(context());
        JwtClaims claims = verify(token, key);
        check("signed ID-JAG claims", claims.getIssuer().equals("https://pf.example.test")
                && claims.getSubject().equals("user-123")
                && claims.getAudience().equals(List.of("https://target.example.test"))
                && claims.getStringClaimValue("client_id").equals("target-client")
                && claims.getStringClaimValue("resource").equals("https://api.example.test/reports")
                && claims.getStringClaimValue("scope").equals("read:reports")
                && claims.getIssuedAt().getValue() == NOW
                && claims.getExpirationTime().getValue() == NOW + 300);
        check("unique jti", !claims.getJwtId().equals(verify(generator.generateToken(context()), key).getJwtId()));
        TokenContext shortToken = context();
        put(shortToken, "subject_exp", Long.toString(NOW + 30));
        check("lifetime capped at subject expiry", verify(generator.generateToken(shortToken), key)
                .getExpirationTime().getValue() == NOW + 30);
        reject(generator, "authenticated_client_id", "other-client", "wrong authenticated client");
        reject(generator, "subject_client_id", "other-client", "wrong subject client");
        rejectParameter(generator, "audience", "https://other.example.test", "wrong audience");
        rejectParameter(generator, "resource", "https://other.example.test/api", "wrong resource");
        rejectParameter(generator, "scope", "admin", "scope exceeds instance ceiling");
        reject(generator, "approved_scope", "write:reports", "scope exceeds user authorization");
        reject(generator, "subject_exp", Long.toString(NOW), "expired subject");
        reject(generator, "subject_exp", "not-a-time", "invalid expiry");
        TokenContext missing = context();
        missing.getSubjectAttributes().remove("sub");
        rejects("missing subject", () -> generator.generateToken(missing));
        TokenContext multi = context();
        request(multi, "audience", new String[]{"https://target.example.test", "https://other.example.test"});
        rejects("multiple audiences", () -> generator.generateToken(multi));
        TokenContext noRequest = context();
        noRequest.getSubjectAttributes().remove("http_request");
        rejects("missing request context", () -> generator.generateToken(noRequest));
        TokenContext duplicateResource = context();
        request(duplicateResource, "resource", new String[]{"https://api.example.test/reports", "https://api.example.test/reports"});
        rejects("duplicate resource", () -> generator.generateToken(duplicateResource));
        TokenContext duplicateScope = context();
        request(duplicateScope, "scope", new String[]{"read:reports", "read:reports"});
        rejects("duplicate scope", () -> generator.generateToken(duplicateScope));
        rejects("unconfigured generator", () -> new IdJagTokenGenerator().generateToken(context()));
        check("empty inParameters does not prevent issuing", context().getInParameters().isEmpty());
        serializeWithRealPfResponse(token);
        routeWithRealPfSelector();
        // Inspect available context labels without exposing a request or credential.
        for (org.sourceid.saml20.domain.SourceContextType type : List.of(
                org.sourceid.saml20.domain.SourceContextType.OAUTH_CLIENT,
                org.sourceid.saml20.domain.SourceContextType.OAUTH_SCOPES,
                org.sourceid.saml20.domain.SourceContextType.OAUTH_RESOURCES,
                org.sourceid.saml20.domain.SourceContextType.REQUEST)) {
            System.out.println("PF mapping context: " + type.getId() + " -> " + type.getDescription());
        }
        System.out.println("PASS: " + passed + " proof checks (real PF classes; no HTTP server involved)");
    }

    private static IdJagTokenGenerator generator() {
        IdJagTokenGenerator g = new IdJagTokenGenerator(
                () -> new IdJagTokenGenerator.SigningKey("test-key", key.getPrivate()),
                Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));
        List<Field> fields = new ArrayList<>();
        Map.of("Issuer", "https://pf.example.test", "Requesting Client ID", "primary-client",
                "Target Issuer", "https://target.example.test", "Target Client ID", "target-client",
                "Resource", "https://api.example.test/reports", "Allowed Scopes", "read:reports write:reports",
                "Lifetime Seconds", "300").forEach((n, v) -> fields.add(new Field(n, v)));
        g.configure(new Configuration(fields, List.of(), List.of()));
        return g;
    }

    private static TokenContext context() {
        TokenContext c = new TokenContext();
        c.setSubjectAttributes(new HashMap<>());
        put(c, "sub", "user-123");
        put(c, "authenticated_client_id", "primary-client");
        put(c, "subject_client_id", "primary-client");
        put(c, "subject_exp", Long.toString(NOW + 600));
        request(c, null, null);
        put(c, "approved_scope", "read:reports");
        return c;
    }
    private static void put(TokenContext c, String name, String value) {
        c.getSubjectAttributes().put(name, new AttributeValue(value));
    }
    private static void request(TokenContext c, String override, String[] values) {
        Map<String, String[]> params = new HashMap<>();
        params.put("audience", new String[]{"https://target.example.test"});
        params.put("resource", new String[]{"https://api.example.test/reports"});
        params.put("scope", new String[]{"read:reports"});
        if (override != null) params.put(override, values);
        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(GeneratorProof.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class}, (p, m, args) -> {
                    if (m.getName().equals("getParameterValues")) return params.get(args[0]);
                    return null;
                });
        c.getSubjectAttributes().put("http_request", new AttributeValue(List.of(), List.of(request)));
    }
    private static void rejectParameter(IdJagTokenGenerator g, String param, String value, String name) throws Exception {
        TokenContext c = context();
        request(c, param, new String[]{value});
        rejects(name, () -> g.generateToken(c));
    }
    private static JwtClaims verify(StringSecurityToken token, KeyPair pair) throws Exception {
        JsonWebSignature jwt = new JsonWebSignature();
        jwt.setCompactSerialization(token.getData());
        jwt.setKey(pair.getPublic());
        if (!jwt.verifySignature() || !"RS256".equals(jwt.getAlgorithmHeaderValue())
                || !IdJagTokenGenerator.JWT_TYPE.equals(jwt.getHeader("typ"))
                || !"test-key".equals(jwt.getKeyIdHeaderValue())) throw new AssertionError("Invalid JWT");
        return JwtClaims.parse(jwt.getPayload());
    }
    private static void reject(IdJagTokenGenerator g, String attr, String value, String name) throws Exception {
        TokenContext c = context();
        put(c, attr, value);
        rejects(name, () -> g.generateToken(c));
    }
    private static void rejects(String name, Checked action) throws Exception {
        try { action.run(); }
        catch (TokenProcessingException expected) { check(name, true); return; }
        throw new AssertionError("Expected rejection: " + name);
    }
    private static void check(String name, boolean value) {
        if (!value) throw new AssertionError(name);
        passed++;
        System.out.println("PASS: " + name);
    }
    interface Checked { void run() throws Exception; }

    private static void serializeWithRealPfResponse(StringSecurityToken token) throws Exception {
        // Reflection is deliberately TEST ONLY. Exercise the exact PF endpoint response
        // adapter rather than duplicating its logic in a mock HTTP server.
        Class<?> type = Class.forName("org.sourceid.oauth20.handlers.process.exchange.execution.impl."
                + "TokenGeneratorOutputGenerationStrategy$SecurityTokenTokenResponse");
        Constructor<?> ctor = type.getDeclaredConstructor(SecurityToken.class, String.class);
        ctor.setAccessible(true);
        Object response = ctor.newInstance(token, IdJagTokenGenerator.TYPE);
        Method serialize = type.getDeclaredMethod("tokenResponseToOutContext", OutMessageContext.class);
        serialize.setAccessible(true);
        OutMessageContext out = new OutMessageContext();
        serialize.invoke(response, out);
        check("real PF serializer preserves compact JWT", token.getData().equals(out.getParam("access_token")));
        check("real PF serializer returns id-jag and N_A", IdJagTokenGenerator.TYPE.equals(out.getParam("issued_token_type"))
                && "N_A".equals(out.getParam("token_type")));
        long expires = ((Number) out.getObjParam("expires_in")).longValue();
        check("real PF serializer returns expiry", expires > 0 && expires <= 300);
    }

    private static void routeWithRealPfSelector() throws Exception {
        TokenExchangeGeneratorPolicy group = new TokenExchangeGeneratorPolicy();
        group.setId("xaa-proof");
        group.setResourceUris(List.of("https://api.example.test/reports"));
        TokenExchangeGeneratorMapping mapping = new TokenExchangeGeneratorMapping();
        mapping.setTokenType(IdJagTokenGenerator.TYPE);
        mapping.setTokenGeneratorId("xaa-idjag");
        group.setMappings(List.of(mapping));
        TokenExchangeGeneratorPolicyManager manager = (TokenExchangeGeneratorPolicyManager) Proxy.newProxyInstance(
                GeneratorProof.class.getClassLoader(), new Class<?>[]{TokenExchangeGeneratorPolicyManager.class},
                (p, m, args) -> {
                    if (m.getName().equals("getPoliciesByResourceUri")) {
                        return group.matchRequestedResource((String) args[0]) ? Set.of(group) : Set.of();
                    }
                    throw new UnsupportedOperationException(m.getName());
                });
        Map<String, String> params = Map.of("subject_token", "fixture-only", "subject_token_type",
                "urn:ietf:params:oauth:token-type:id_token", "requested_token_type", IdJagTokenGenerator.TYPE,
                "resource", "https://api.example.test/reports", "audience", "https://target.example.test",
                "scope", "read:reports");
        HttpServletRequest servlet = (HttpServletRequest) Proxy.newProxyInstance(GeneratorProof.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class}, (p, m, args) -> {
                    if (m.getName().equals("getParameter")) return params.get(args[0]);
                    if (m.getName().equals("getParameterValues")) {
                        String v = params.get(args[0]);
                        return v == null ? null : new String[]{v};
                    }
                    return null;
                });
        Client client = new Client();
        client.setClientId("primary-client");
        TokenExchangeRequest request = new TokenExchangeRequest(servlet, client);
        check("real PF parser accepts id-jag token type", request.getRequestedTokenType().equals(IdJagTokenGenerator.TYPE));
        Map<String, Client> registeredClients = new HashMap<>();
        ClientManager clients = (ClientManager) Proxy.newProxyInstance(GeneratorProof.class.getClassLoader(),
                new Class<?>[]{ClientManager.class}, (p, m, args) -> {
                    if (m.getName().equals("getCachedClient")) return registeredClients.get(args[0]);
                    throw new UnsupportedOperationException(m.getName());
                });
        // No openid scope in this proof, so OIDC policy support is not consulted.
        TokenExchangeAudienceParameterValidator audiences = new TokenExchangeAudienceParameterValidator(clients, null);
        boolean rejected = false;
        try { audiences.validate(request); }
        catch (AccessTokenRequestException expected) { rejected = true; }
        check("real PF audience validator rejects an unregistered target issuer", rejected);
        Client compatibilityClient = new Client();
        compatibilityClient.setClientId("https://target.example.test");
        registeredClients.put(compatibilityClient.getClientId(), compatibilityClient);
        audiences.validate(request);
        check("real PF audience validator accepts issuer registered as local client ID", true);
        Set<TokenExchangeGeneratorPolicy> selected = new TokenExchangeGeneratorPolicySelector(manager).select(request, client);
        check("real PF selector routes resource to generator group", selected.contains(group));
        check("real PF mapping selects custom id-jag generator", group.getMapping(request.getRequestedTokenType())
                .getTokenGeneratorId().equals("xaa-idjag"));
    }
}
