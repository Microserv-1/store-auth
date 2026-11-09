package br.edu.insper.store;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class AuthController {
    private final Algorithm algorithm;
    private final RestClient account;
    private final long ttl;
    public record Credentials(@NotNull @Email @Size(min=3,max=254) String email, @NotNull @Size(min=8,max=128) String password) {}
    public record AccountIdentity(String id) {}
    public AuthController(@Value("${JWT_SECRET}") String secret,
                          @Value("${INTERNAL_AUTH_KEY}") String internalKey,
                          @Value("${ACCOUNT_URL}") String accountUrl,
                          @Value("${TOKEN_TTL_SECONDS:1800}") long tokenTtl) {
        if (secret.length() < 32) throw new IllegalStateException("JWT_SECRET too short");
        algorithm = Algorithm.HMAC256(secret);
        ttl = tokenTtl;
        if (ttl < 1 || ttl > 86400) throw new IllegalStateException("Invalid token lifetime");
        var factory = new JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build());
        factory.setReadTimeout(Duration.ofSeconds(5));
        if (internalKey.length() < 32) throw new IllegalStateException("INTERNAL_AUTH_KEY too short");
        account = RestClient.builder().baseUrl(accountUrl).requestFactory(factory)
            .defaultHeader("X-Internal-Auth-Key", internalKey).build();
    }
    @PostMapping("/auth/login")
    public Map<String, Object> login(@Valid @RequestBody Credentials credentials) {
        AccountIdentity identity;
        try {
            identity = account.post().uri("/internal/credentials/verify").body(credentials)
                .retrieve().body(AccountIdentity.class);
        } catch (HttpClientErrorException.Unauthorized e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        } catch (RestClientException e) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Account unavailable");
        }
        if (identity == null || identity.id() == null) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY);
        try { UUID.fromString(identity.id()); }
        catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.BAD_GATEWAY); }
        var now = Instant.now();
        String token = JWT.create().withSubject(identity.id()).withIssuer("store-auth").withAudience("store-api")
            .withIssuedAt(now).withExpiresAt(now.plusSeconds(ttl)).withJWTId(UUID.randomUUID().toString()).sign(algorithm);
        return Map.of("access_token", token, "token_type", "bearer", "expires_in", ttl);
    }
    @GetMapping("/auth/me")
    public Map<String, String> me(@RequestHeader(value="Authorization", defaultValue="") String authorization) {
        if (!authorization.regionMatches(true, 0, "Bearer ", 0, 7)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        try {
            var token = JWT.require(algorithm).withIssuer("store-auth").withAudience("store-api")
                .withClaimPresence("exp").withClaimPresence("iat").withClaimPresence("sub").build().verify(authorization.substring(7));
            UUID.fromString(token.getSubject());
            return Map.of("id-account", token.getSubject());
        } catch (JWTVerificationException | IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
    }
    @GetMapping({"/health-check", "/ready"})
    public Map<String, String> health() { return Map.of("status", "ok", "service", "auth"); }
}
