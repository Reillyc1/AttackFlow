# Security Changelog

This document outlines all security improvements implemented in the AttackFlow application, following OWASP best practices and industry standards.

---

## Version 1.1.0 - Security Hardening Release

### Overview

This release focuses on comprehensive security hardening across the entire application stack, addressing authentication, authorization, input validation, rate limiting, and secure configuration management.

---

## 1. Rate Limiting Implementation

**File:** `middleware/rateLimiter.js`

### Changes

Implemented comprehensive rate limiting to protect against brute-force attacks, denial-of-service attempts, and API abuse.

### Rate Limiters Implemented

| Limiter | Window | Max Requests | Purpose |
|---------|--------|--------------|---------|
| `generalLimiter` | 15 minutes | 100 | Baseline protection for all API routes |
| `authLimiter` | 15 minutes | 5 | Strict limits for login/signup to prevent credential stuffing |
| `uploadLimiter` | 1 hour | 20 | Prevents abuse of file upload functionality |
| `mutationLimiter` | 1 minute | 30 | Limits create/update/delete operations |
| `strictLimiter` | 5 minutes | 3 | For extremely sensitive operations |

### Key Features

- **Combined IP + User Key Generation:** Prevents a single user from exhausting limits across multiple IPs while protecting shared IPs from being blocked due to one bad actor
- **Graceful 429 Responses:** Returns proper HTTP 429 status with `retryAfter` information
- **Static Asset Exclusion:** Static files (CSS, JS, images) bypass rate limiting
- **Configurable via Environment Variables:** All limits can be adjusted without code changes

### OWASP Reference
- API4:2023 - Unrestricted Resource Consumption

---

## 2. Input Validation & Sanitization

**File:** `middleware/validator.js`

### Changes

Implemented schema-based input validation using Joi with strict type checking, length limits, and pattern matching.

### Validation Schemas Implemented

| Schema | Purpose | Key Validations |
|--------|---------|-----------------|
| `login` | User authentication | Username (3-64 chars, alphanumeric), Password (6-128 chars) |
| `signup` | Account creation | Username, Password, Email (valid format), Role (whitelist) |
| `createAnnotation` | New annotations | FileID (positive int), TagID, SelectedText (max 10KB), Notes (max 5KB) |
| `updateAnnotation` | Modify annotations | Same as create with optional fields |
| `generateAttackFlow` | Flow generation | FileID, FlowName (max 255), Description (max 2KB) |
| `approveRejectFlow` | Validation workflow | Feedback (max 5KB) |

### Key Features

- **Schema-Based Validation:** Declarative validation rules with Joi
- **Type Coercion:** Automatic conversion of query strings to appropriate types
- **Length Limits:** Prevents buffer overflow attacks and database issues
- **Pattern Matching:** Username restricted to `[a-zA-Z0-9_-]`
- **Unexpected Field Rejection:** `stripUnknown: true` removes fields not in schema
- **Null Byte Removal:** Sanitization removes null bytes that could cause truncation
- **Content-Type Validation:** Rejects requests with incorrect Content-Type headers

### Validation Middleware Functions

```javascript
validateBody(schema)    // Request body validation
validateParams(schema)  // URL parameter validation
validateQuery(schema)   // Query string validation
validateContentType()   // Content-Type header validation
```

### OWASP References
- API3:2023 - Broken Object Property Level Authorization
- API8:2023 - Security Misconfiguration

---

## 3. Secure Session Configuration

**File:** `app.js`

### Changes

Implemented secure session management following OWASP session management guidelines.

### Security Measures

| Setting | Value | Purpose |
|---------|-------|---------|
| `httpOnly` | `true` | Prevents client-side JavaScript access to session cookie |
| `secure` | Configurable | Requires HTTPS in production |
| `sameSite` | `'lax'` | CSRF protection while allowing normal navigation |
| `name` | `'attackflow.sid'` | Custom cookie name obscures technology stack |
| `saveUninitialized` | `false` | Don't create empty sessions |
| `resave` | `false` | Prevents race conditions |

### Session Regeneration

Session IDs are regenerated on login to prevent session fixation attacks:

```javascript
req.session.regenerate(function(err) {
    // Set session data after regeneration
    req.session.userID = user.userID;
    req.session.role = user.access;
});
```

### OWASP Reference
- Session Management Cheat Sheet

---

## 4. Environment Variable Configuration

**Files:** `app.js`, `.env.example`

### Changes

Moved all sensitive configuration to environment variables with secure defaults.

### Configuration Categories

1. **Server Configuration**
   - `NODE_ENV` - Environment mode (development/production)
   - `PORT` - Server port

2. **Session Security**
   - `SESSION_SECRET` - Cryptographic secret (minimum 32 characters in production)
   - `SESSION_COOKIE_SECURE` - HTTPS-only cookies
   - `SESSION_COOKIE_MAX_AGE` - Session lifetime

3. **Database Configuration**
   - `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
   - `DB_CONNECTION_LIMIT`, `DB_QUEUE_LIMIT`

4. **Rate Limiting**
   - All rate limit windows and max requests configurable

5. **Security Settings**
   - `BCRYPT_SALT_ROUNDS` - Password hashing cost factor
   - `MAX_FILE_SIZE` - Upload size limit
   - `ALLOWED_FILE_EXTENSIONS` - Whitelist of allowed file types

### Production Validation

Application exits on startup in production if:
- `SESSION_SECRET` is set to a default/weak value
- `SESSION_SECRET` is less than 32 characters

---

## 5. HTTP Security Headers

**File:** `app.js`

### Changes

Implemented Helmet.js for comprehensive HTTP security headers.

### Headers Configured

| Header | Configuration | Purpose |
|--------|---------------|---------|
| Content-Security-Policy | Strict directives | Prevents XSS and data injection |
| X-Frame-Options | DENY | Prevents clickjacking |
| X-Content-Type-Options | nosniff | Prevents MIME type sniffing |
| X-XSS-Protection | Enabled | Browser XSS filter |
| X-Powered-By | Removed | Hides technology stack |

### Content Security Policy Directives

```javascript
{
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"]
}
```

---

## 6. SQL Injection Prevention

**File:** `app.js`, `routes/index.js`

### Changes

- All database queries use parameterized queries (prepared statements)
- `multipleStatements: false` in MySQL configuration prevents stacked query attacks
- User inputs are never concatenated directly into SQL queries

### Example

```javascript
// Safe - Parameterized query
pool.query('SELECT * FROM users WHERE username = ?', [username], callback);

// Unsafe - Never used in this codebase
pool.query('SELECT * FROM users WHERE username = "' + username + '"', callback);
```

---

## 7. Password Security

**File:** `routes/index.js`

### Changes

- Passwords hashed using bcrypt with configurable salt rounds (default: 12)
- Timing-safe comparison using bcrypt.compare()
- No plain-text password storage or logging

### Implementation

```javascript
// Password hashing on signup
const hashedPassword = await bcrypt.hash(password, config.bcryptSaltRounds);

// Password verification on login
const match = await bcrypt.compare(password, user.password);
```

---

## 8. File Upload Security

**File:** `routes/index.js`

### Changes

- File type validation by extension whitelist
- File size limits enforced (configurable, default 50MB)
- Rate limiting on upload endpoint
- Files stored outside web root where possible
- Timestamp-prefixed filenames prevent overwrites

---

## 9. Error Handling

**File:** `app.js`

### Changes

- Generic error messages in production (no stack traces)
- Detailed errors only in development mode
- Proper HTTP status codes for all error types
- Centralized error handling middleware

```javascript
const errorResponse = {
    error: 'Internal Server Error',
    message: config.nodeEnv === 'production'
        ? 'An unexpected error occurred'
        : err.message
};
```

---

## 10. Frontend Security

**File:** `public/index.html`

### Changes

- Client-side input validation (defense in depth)
- Proper error message display without exposing technical details
- Rate limit error handling (HTTP 429)
- Form submission protection against double-clicks
- Removed debugging console.log statements
- Proper DOCTYPE and meta tags

---

## Dependencies Added

| Package | Version | Purpose |
|---------|---------|---------|
| `helmet` | ^7.1.0 | HTTP security headers |
| `express-rate-limit` | ^7.1.5 | Rate limiting middleware |
| `joi` | ^17.11.0 | Schema validation |

---

## Files Modified

| File | Changes |
|------|---------|
| `app.js` | Environment config, Helmet, secure sessions, error handling |
| `routes/index.js` | Rate limiting, input validation, parameterized queries |
| `package.json` | New security dependencies |
| `public/index.html` | Secure login form, error handling |

## Files Created

| File | Purpose |
|------|---------|
| `.env.example` | Configuration template |
| `middleware/rateLimiter.js` | Rate limiting middleware |
| `middleware/validator.js` | Input validation middleware |
| `SECURITY_CHANGELOG.md` | This document |

---

## Compliance

These changes align with:

- **OWASP API Security Top 10 (2023)**
  - API1:2023 - Broken Object Level Authorization
  - API2:2023 - Broken Authentication
  - API3:2023 - Broken Object Property Level Authorization
  - API4:2023 - Unrestricted Resource Consumption
  - API5:2023 - Broken Function Level Authorization
  - API8:2023 - Security Misconfiguration

- **OWASP Application Security Verification Standard (ASVS)**
  - V1: Architecture
  - V2: Authentication
  - V3: Session Management
  - V5: Validation, Sanitization and Encoding
  - V14: Configuration

---

## Recommendations for Future Improvements

1. **Implement CSRF Tokens** - Add CSRF protection for state-changing operations
2. **Add Security Logging** - Implement audit logging for security events
3. **Content Security Policy Nonce** - Replace `'unsafe-inline'` with nonces for scripts
4. **Two-Factor Authentication** - Add 2FA for high-privilege accounts
5. **API Key Rotation** - Implement automated key rotation if API keys are added
6. **Security Headers Audit** - Regular review of CSP and other security headers
7. **Dependency Scanning** - Integrate npm audit into CI/CD pipeline
8. **Penetration Testing** - Regular security assessments
