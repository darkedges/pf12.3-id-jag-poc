package com.darkedges.pingfederate.xaa;

import com.pingidentity.access.JwksEndpointKeyAccessor;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.wstrust.model.StringSecurityToken;
import org.sourceid.wstrust.plugin.TokenProcessingException;
import org.sourceid.wstrust.plugin.generate.TokenContext;
import org.sourceid.wstrust.plugin.generate.TokenGenerator;
import org.sourceid.wstrust.plugin.process.TokenPluginDescriptor;

import java.net.URI;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

/**
 * Fixed-client, fixed-destination ID-JAG issuance proof for PF 12.3.3.
 * Inbound cryptographic validation and user authorization belong to the TEPP.
 * Every input below must be explicitly mapped; getInParameters() is not
 * populated by PF 12.3.3's token-generator OAuth exchange path.
 */
public final class IdJagTokenGenerator implements TokenGenerator {
    public static final String TYPE = "urn:ietf:params:oauth:token-type:id-jag";
    public static final String JWT_TYPE = "oauth-id-jag+jwt";
    public static final Set<String> CONTRACT = Set.of("sub", "authenticated_client_id",
            "subject_client_id", "subject_exp", "http_request", "approved_scope");

    private final PluginDescriptor descriptor;
    private final SigningKeys signingKeys;
    private final Clock clock;
    private volatile Settings settings;

    public IdJagTokenGenerator() {
        this(() -> {
            JwksEndpointKeyAccessor.JsonWebKeyWrapper key =
                    JwksEndpointKeyAccessor.newInstance().getCurrentRsaKey("RS256");
            if (key == null) throw new IllegalStateException("No PF RS256 signing key available");
            return new SigningKey(key.getKeyId(), key.getPrivateKey());
        }, Clock.systemUTC());
    }

    // Package-private injection only for offline tests; not a runtime config bypass.
    IdJagTokenGenerator(SigningKeys signingKeys, Clock clock) {
        this.signingKeys = signingKeys;
        this.clock = clock;
        GuiConfigDescriptor gui = new GuiConfigDescriptor("DarkEdges ID-JAG Generator (12.3.3 proof)");
        field(gui, "Issuer", "Exact PF issuer trusted by the receiving authorization server.", null);
        field(gui, "Requesting Client ID", "Allowed authenticated PF client; one per instance.", null);
        field(gui, "Target Issuer", "Exact downstream authorization server issuer (ID-JAG aud).", null);
        field(gui, "Target Client ID", "Client registration at the downstream authorization server.", null);
        field(gui, "Resource", "Single allowed API resource URI, also used for generator-group routing.", null);
        field(gui, "Allowed Scopes", "Space-delimited scope ceiling. Also requires approved_scope mapping.", null);
        field(gui, "Lifetime Seconds", "Maximum 300 seconds; also capped at validated subject expiry.", "300");
        descriptor = new TokenPluginDescriptor("DarkEdges ID-JAG Generator (12.3.3 proof)",
                this, gui, TYPE, CONTRACT);
    }

    private static void field(GuiConfigDescriptor gui, String name, String help, String defaultValue) {
        TextFieldDescriptor field = new TextFieldDescriptor(name, help);
        field.addValidator(new RequiredFieldValidator());
        if (defaultValue != null) field.setDefaultValue(defaultValue);
        gui.addField(field);
    }

    @Override public void configure(Configuration config) {
        // A failed reconfiguration must not retain an old issuing configuration.
        settings = null;
        settings = new Settings(config);
    }

    @Override public PluginDescriptor getPluginDescriptor() { return descriptor; }

    @Override public StringSecurityToken generateToken(TokenContext context) throws TokenProcessingException {
        try {
            Settings s = settings;
            if (s == null) throw new IllegalArgumentException("Generator is not configured");
            Map<String, AttributeValue> a = context.getSubjectAttributes();
            String sub = single(a, "sub");
            if (!s.requestingClient.equals(single(a, "authenticated_client_id"))
                    || !s.requestingClient.equals(single(a, "subject_client_id"))) {
                throw new IllegalArgumentException("Client binding rejected");
            }
            AttributeValue requestValue = a.get("http_request");
            Object requestObject = requestValue == null ? null : requestValue.getObjectValue();
            if (!(requestObject instanceof HttpServletRequest)) {
                throw new IllegalArgumentException("Missing trusted HTTP request context");
            }
            HttpServletRequest request = (HttpServletRequest) requestObject;
            if (!s.audience.equals(parameter(request, "audience"))
                    || !s.resource.equals(parameter(request, "resource"))) {
                throw new IllegalArgumentException("Destination rejected");
            }
            Set<String> requested = scopes(parameter(request, "scope"));
            Set<String> approved = scopes(single(a, "approved_scope"));
            if (!s.allowedScopes.containsAll(requested) || !approved.containsAll(requested)) {
                throw new IllegalArgumentException("Requested scopes are not authorized");
            }
            long now = clock.instant().getEpochSecond();
            long subjectExpiry;
            try { subjectExpiry = Long.parseLong(single(a, "subject_exp")); }
            catch (NumberFormatException e) { throw new IllegalArgumentException("Invalid subject expiry"); }
            long expiry = Math.min(now + s.lifetime, subjectExpiry);
            if (expiry <= now) throw new IllegalArgumentException("Subject token has expired");

            JwtClaims claims = new JwtClaims();
            claims.setIssuer(s.issuer);
            claims.setSubject(sub);
            // Single string audience to match this deliberately narrow profile.
            claims.setStringClaim("aud", s.audience);
            claims.setStringClaim("client_id", s.targetClient);
            claims.setStringClaim("resource", s.resource);
            claims.setStringClaim("scope", String.join(" ", requested));
            claims.setIssuedAt(NumericDate.fromSeconds(now));
            claims.setExpirationTime(NumericDate.fromSeconds(expiry));
            claims.setJwtId(UUID.randomUUID().toString());
            SigningKey key = signingKeys.current();
            if (key.privateKey == null || !"RSA".equals(key.privateKey.getAlgorithm())) {
                throw new IllegalArgumentException("RS256 signing key unavailable");
            }
            JsonWebSignature jwt = new JsonWebSignature();
            jwt.setAlgorithmHeaderValue("RS256");
            jwt.setHeader("typ", JWT_TYPE);
            jwt.setKeyIdHeaderValue(nonempty(key.kid));
            jwt.setKey(key.privateKey);
            jwt.setPayload(claims.toJson());
            StringSecurityToken result = new StringSecurityToken(TYPE, jwt.getCompactSerialization());
            result.setExpiryDate(Date.from(java.time.Instant.ofEpochSecond(expiry)));
            return result;
        } catch (IllegalArgumentException e) {
            // Only our fixed messages reach PF's OAuth error response; no input values.
            throw new TokenProcessingException(e.getMessage());
        } catch (Exception e) {
            throw new TokenProcessingException("ID-JAG generation failed");
        }
    }

    private static String single(Map<String, AttributeValue> attributes, String name) {
        AttributeValue v = attributes == null ? null : attributes.get(name);
        if (v == null || v.getValuesAsCollection().size() != 1) {
            throw new IllegalArgumentException("Missing or multivalued contract attribute: " + name);
        }
        return nonempty(v.getValue());
    }

    private static String parameter(HttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        if (values == null || values.length != 1) {
            throw new IllegalArgumentException("Missing or repeated request parameter: " + name);
        }
        return nonempty(values[0]);
    }

    private static String nonempty(String value) {
        if (value == null || value.isBlank() || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Missing or invalid configuration/contract value");
        }
        return value;
    }

    private static String httpsUri(String value) {
        URI uri = URI.create(nonempty(value));
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Configured issuer/resource must be an HTTPS URI");
        }
        return value;
    }

    private static Set<String> scopes(String value) {
        if (!value.matches("[\\x21\\x23-\\x5B\\x5D-\\x7E]+( [\\x21\\x23-\\x5B\\x5D-\\x7E]+)*")) {
            throw new IllegalArgumentException("Invalid scope syntax");
        }
        return new LinkedHashSet<>(Arrays.asList(value.split(" ")));
    }

    interface SigningKeys { SigningKey current() throws Exception; }
    static final class SigningKey {
        final String kid;
        final PrivateKey privateKey;
        SigningKey(String kid, PrivateKey privateKey) { this.kid = kid; this.privateKey = privateKey; }
    }

    private static final class Settings {
        final String issuer, requestingClient, audience, targetClient, resource;
        final Set<String> allowedScopes;
        final int lifetime;
        Settings(Configuration c) {
            issuer = httpsUri(c.getFieldValue("Issuer"));
            requestingClient = nonempty(c.getFieldValue("Requesting Client ID"));
            audience = httpsUri(c.getFieldValue("Target Issuer"));
            targetClient = nonempty(c.getFieldValue("Target Client ID"));
            resource = httpsUri(c.getFieldValue("Resource"));
            allowedScopes = scopes(nonempty(c.getFieldValue("Allowed Scopes")));
            lifetime = Integer.parseInt(c.getFieldValue("Lifetime Seconds"));
            if (lifetime < 1 || lifetime > 300) throw new IllegalArgumentException("Lifetime must be 1..300");
        }
    }
}
