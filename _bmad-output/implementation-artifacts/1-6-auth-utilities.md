---
story_id: "1.6"
story_key: "1-6-auth-utilities"
title: "Create Auth Utilities"
epic: "Epic 1: Foundation"
status: "done"
priority: "high"
---

# Story 1.6: Create Auth Utilities

## Story

As a developer building ALUSKORT services,
I want shared authentication utilities for OIDC token validation, mTLS context management, and standardized authentication errors,
so that all services enforce consistent, platform-neutral authentication without duplicating security logic.

## Acceptance Criteria

### AC-1.6.1: OIDC Token Validation - Valid Token
**Given** a valid JWT token signed by a trusted issuer
**When** validate_oidc_token(token) is called with the correct JWKS endpoint configured
**Then** the decoded token claims are returned as a dict containing sub, iss, aud, exp, and any custom claims

### AC-1.6.2: OIDC Token Validation - Expired Token
**Given** an expired JWT token
**When** validate_oidc_token(token) is called
**Then** an AuthenticationError is raised with message containing "expired"

### AC-1.6.3: OIDC Token Validation - Invalid Signature
**Given** a JWT token signed with an untrusted key
**When** validate_oidc_token(token) is called
**Then** an AuthenticationError is raised with message containing "signature"

### AC-1.6.4: OIDC Token Validation - Wrong Audience
**Given** a JWT token with an audience not matching the expected audience
**When** validate_oidc_token(token) is called with audience validation enabled
**Then** an AuthenticationError is raised with message containing "audience"

### AC-1.6.5: JWKS Key Fetching
**Given** a configured JWKS endpoint URL
**When** the OIDC validator initializes or a token uses an unknown kid
**Then** the JWKS keys are fetched from the endpoint and cached for subsequent validations

### AC-1.6.6: mTLS Context Creation
**Given** valid paths to a CA certificate, client certificate, and client key
**When** create_mtls_context(ca_cert, client_cert, client_key) is called
**Then** an ssl.SSLContext is returned configured for mutual TLS with PROTOCOL_TLS_CLIENT, the CA loaded as verify location, and the client cert/key loaded

### AC-1.6.7: mTLS Context Rejects Invalid Certificates
**Given** an invalid or non-existent certificate path
**When** create_mtls_context() is called
**Then** an AuthenticationError is raised with a descriptive message

### AC-1.6.8: AuthenticationError Exception
**Given** any authentication failure across the auth utilities
**When** an error is raised
**Then** it is an AuthenticationError with a descriptive message, an error_code string, and an optional detail dict

## Tasks/Subtasks

- [ ] Task 1: Create shared/auth/ directory structure
  - [ ] Subtask 1.1: Create shared/auth/__init__.py with exports for validate_oidc_token, create_mtls_context, AuthenticationError
  - [ ] Subtask 1.2: Create shared/auth/exceptions.py with AuthenticationError class
- [ ] Task 2: Implement AuthenticationError exception
  - [ ] Subtask 2.1: Define AuthenticationError(Exception) with message (str), error_code (str), and detail (Optional[dict]) attributes
  - [ ] Subtask 2.2: Define error code constants: TOKEN_EXPIRED, TOKEN_INVALID_SIGNATURE, TOKEN_INVALID_AUDIENCE, TOKEN_INVALID_ISSUER, TOKEN_MALFORMED, JWKS_FETCH_FAILED, MTLS_INVALID_CERT, MTLS_INVALID_KEY, MTLS_CA_NOT_FOUND
- [ ] Task 3: Implement OIDC token validation
  - [ ] Subtask 3.1: Create shared/auth/oidc.py
  - [ ] Subtask 3.2: Define OIDCValidator class with __init__ accepting jwks_url (str), audience (Optional[str]), issuer (Optional[str]), algorithms (list[str] default ["RS256"])
  - [ ] Subtask 3.3: Implement _fetch_jwks() -> dict that fetches JWKS from the configured endpoint using httpx or urllib and caches the result
  - [ ] Subtask 3.4: Implement _get_signing_key(token: str) -> jwt.algorithms.RSAAlgorithm that extracts the kid from the JWT header and finds the matching key in the JWKS
  - [ ] Subtask 3.5: Implement validate_oidc_token(token: str) -> dict that decodes and validates the JWT using PyJWT, returning the claims dict
  - [ ] Subtask 3.6: Handle all JWT exceptions (ExpiredSignatureError, InvalidSignatureError, InvalidAudienceError, InvalidIssuerError, DecodeError) and convert to AuthenticationError with appropriate error_code
- [ ] Task 4: Implement mTLS context management
  - [ ] Subtask 4.1: Create shared/auth/mtls.py
  - [ ] Subtask 4.2: Implement create_mtls_context(ca_cert_path: str, client_cert_path: str, client_key_path: str, check_hostname: bool = True) -> ssl.SSLContext
  - [ ] Subtask 4.3: Use ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), load CA cert with load_verify_locations(), load client cert/key with load_cert_chain()
  - [ ] Subtask 4.4: Validate that all certificate paths exist before attempting to load (raise AuthenticationError with MTLS_CA_NOT_FOUND or MTLS_INVALID_CERT if not)
  - [ ] Subtask 4.5: Catch ssl.SSLError and convert to AuthenticationError with descriptive message
- [ ] Task 5: Implement JWKS caching
  - [ ] Subtask 5.1: Cache JWKS keys in memory with a configurable TTL (default 3600 seconds / 1 hour)
  - [ ] Subtask 5.2: Implement cache invalidation when a kid is not found in the cached JWKS (force re-fetch)
  - [ ] Subtask 5.3: Implement max_retries (default 3) for JWKS fetch failures with exponential backoff
- [ ] Task 6: Create convenience functions
  - [ ] Subtask 6.1: Implement module-level validate_oidc_token(token, jwks_url, audience, issuer) convenience function that creates a one-shot OIDCValidator
  - [ ] Subtask 6.2: Export all public classes and functions from shared/auth/__init__.py
- [ ] Task 7: Write unit tests
  - [ ] Subtask 7.1: Create tests/test_auth/test_oidc.py
  - [ ] Subtask 7.2: Create tests/test_auth/test_mtls.py
  - [ ] Subtask 7.3: Create tests/test_auth/test_exceptions.py
  - [ ] Subtask 7.4: Mock JWKS endpoint (httpx or urllib) and test validate_oidc_token with a valid RS256-signed JWT
  - [ ] Subtask 7.5: Test validate_oidc_token raises AuthenticationError(TOKEN_EXPIRED) for expired JWT
  - [ ] Subtask 7.6: Test validate_oidc_token raises AuthenticationError(TOKEN_INVALID_SIGNATURE) for wrong-key JWT
  - [ ] Subtask 7.7: Test validate_oidc_token raises AuthenticationError(TOKEN_INVALID_AUDIENCE) for wrong audience
  - [ ] Subtask 7.8: Test JWKS cache: second call uses cached keys, not a new HTTP request
  - [ ] Subtask 7.9: Test JWKS cache invalidation on unknown kid
  - [ ] Subtask 7.10: Mock ssl.SSLContext and test create_mtls_context loads CA cert and client cert/key
  - [ ] Subtask 7.11: Test create_mtls_context raises AuthenticationError for non-existent cert path
  - [ ] Subtask 7.12: Test AuthenticationError has message, error_code, and detail attributes

## Dev Notes

### Architecture Requirements
- Auth is platform-neutral: OIDC / mTLS / API Keys (see docs/architecture.md Section 2)
- Use PyJWT (python-jose alternative also acceptable) for JWT decoding and validation
- Use ssl.SSLContext from Python stdlib for mTLS -- no external TLS libraries required
- JWKS endpoint is configurable per deployment (Azure AD, Keycloak, Auth0, Okta, etc.)
- mTLS is used for inter-service communication when deployed in high-security environments
- Auth utilities are used by ALL microservices for request authentication
- See docs/ai-system-design.md Section 2: Auth row specifies "OIDC / mTLS / API Keys"
- See docs/architecture.md Section 2: python-jose and cryptography listed as auth packages

### Technical Specifications
- Module: shared/auth/oidc.py - OIDCValidator class and validate_oidc_token() function
- Module: shared/auth/mtls.py - create_mtls_context() function
- Module: shared/auth/exceptions.py - AuthenticationError class
- OIDCValidator constructor: jwks_url (str), audience (Optional[str]), issuer (Optional[str]), algorithms (list[str], default ["RS256"]), jwks_cache_ttl (int, default 3600)
- validate_oidc_token returns: dict with decoded JWT claims (sub, iss, aud, exp, iat, custom claims)
- create_mtls_context returns: ssl.SSLContext configured for TLS 1.2+ client auth
- AuthenticationError: inherits from Exception, has message (str), error_code (str), detail (Optional[dict])
- Error codes as string constants: TOKEN_EXPIRED, TOKEN_INVALID_SIGNATURE, TOKEN_INVALID_AUDIENCE, TOKEN_INVALID_ISSUER, TOKEN_MALFORMED, JWKS_FETCH_FAILED, MTLS_INVALID_CERT, MTLS_INVALID_KEY, MTLS_CA_NOT_FOUND
- JWKS fetch: use httpx.AsyncClient or urllib.request.urlopen (httpx preferred for async compatibility)
- Logging: use standard Python logging (logging.getLogger(__name__))

### Testing Strategy
- pytest with pytest-asyncio (for async JWKS fetch tests)
- Generate test RSA keypair using cryptography library in test fixtures
- Create test JWTs using PyJWT with the test keypair
- Mock JWKS endpoint to return test public key
- Test all error paths with specific error_code assertions
- Mock ssl.SSLContext for mTLS tests (do not require real certificates)
- Use tmp_path fixture for testing certificate path validation
- All tests must pass before story is marked done

## Dev Agent Record

### Implementation Plan
<!-- Dev agent fills this during implementation -->

### Debug Log
<!-- Dev agent logs issues here -->

### Completion Notes
<!-- Dev agent summarizes what was done -->

## File List
<!-- Dev agent tracks files here -->

## Change Log
<!-- Dev agent tracks changes here -->

## Status

ready-for-dev
