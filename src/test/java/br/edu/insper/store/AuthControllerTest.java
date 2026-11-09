package br.edu.insper.store;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;

class AuthControllerTest {
    @Test void accountVerificationIssuesInteroperableTokenAndRejectsInvalidPassword() throws Exception {
        String id = UUID.randomUUID().toString();
        String key = "internal-key-with-at-least-32-characters";
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/credentials/verify", exchange -> {
            String request = new String(exchange.getRequestBody().readAllBytes());
            boolean valid = request.contains("correct-password") && key.equals(exchange.getRequestHeaders().getFirst("X-Internal-Auth-Key"));
            byte[] body = (valid ? "{\"id\":\""+id+"\"}" : "{}").getBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(valid ? 200 : 401, body.length);
            exchange.getResponseBody().write(body); exchange.close();
        });
        server.start();
        try {
            var controller = new AuthController("test-signing-secret-with-at-least-32-characters", key,
                "http://127.0.0.1:"+server.getAddress().getPort(), 60);
            var session = controller.login(new AuthController.Credentials("test@example.com", "correct-password"));
            assertEquals(id, controller.me("Bearer "+session.get("access_token")).get("id-account"));
            var rejected = assertThrows(ResponseStatusException.class, () -> controller.login(new AuthController.Credentials("test@example.com", "wrong-password")));
            assertEquals(401, rejected.getStatusCode().value());
            assertThrows(ResponseStatusException.class, () -> controller.me("Bearer invalid"));
        } finally { server.stop(0); }
    }
}
