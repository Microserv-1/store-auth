# Store Auth

Java 21 / Spring Boot. `POST /auth/login` validates credentials through Account's internal API and returns a signed HS256 JWT. `GET /auth/me` validates the token. Health: `/health-check`, `/ready`; Prometheus: `/actuator/prometheus`.

Required environment: `JWT_SECRET`, `INTERNAL_AUTH_KEY` (32+ characters), `ACCOUNT_URL`. Optional `TOKEN_TTL_SECONDS` defaults to 1800. JWT issuer: `store-auth`; audience: `store-api`; subject: account UUID. Never expose the internal key to callers.

Tests and build: `mvn verify` with Java 21 or `docker build -t store-auth .`. The multi-stage Dockerfile executes tests during build. Jenkinsfile and `k8s/k8s.yaml` are service-owned.

See [store-root](https://github.com/Microserv-1/store-root) for integrated execution and [documentation](https://github.com/Microserv-1/store-docs-a) for provisional contracts, limitations and deployment requirements.
