# AttackFlow

A web application for generating and validating attack flows from incident reports using the MITRE ATT&CK framework. AttackFlow enables security analysts to annotate incident reports with ATT&CK techniques and automatically generate standardized Attack Flow JSON files following the MITRE Attack Flow specification.

## Features

- **Document Upload & Management** - Upload incident reports (PDF, DOC, DOCX, TXT) for annotation
- **MITRE ATT&CK Annotation** - Tag document sections with ATT&CK techniques and tactics
- **Attack Flow Generation** - Automatically generate STIX 2.1 compliant Attack Flow JSON
- **Validation Workflow** - Multi-role approval process for attack flow validation
- **Visualization** - Interactive visualization of generated attack flows
- **Role-Based Access Control** - Admin, Client (Validator), and Annotator roles

## Architecture

```
AttackFlow/
├── app.js                    # Express application setup, security middleware
├── bin/www                   # HTTP server entry point
├── routes/
│   ├── index.js              # Main API routes
│   └── users.js              # User management routes
├── middleware/
│   ├── rateLimiter.js        # Rate limiting middleware
│   └── validator.js          # Input validation middleware
├── public/
│   ├── index.html            # Login page
│   ├── home-admin.html       # Admin dashboard
│   ├── home-client.html      # Client/Validator dashboard
│   ├── home-annotator.html   # Annotator dashboard
│   ├── annotate.html         # Document annotation interface
│   └── visualize.html        # Attack flow visualization
├── attackflow.sql            # Database schema
├── .env.example              # Environment configuration template
└── SECURITY_CHANGELOG.md     # Security implementation details
```

## Prerequisites

- **Node.js** >= 16.0.0
- **MySQL** >= 5.7
- **npm** >= 8.0.0

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/attackflow.git
cd attackflow
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment

Copy the example environment file and configure your settings:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Server
NODE_ENV=development
PORT=3000

# Session (IMPORTANT: Change in production)
SESSION_SECRET=your-secure-random-string-minimum-32-characters
SESSION_COOKIE_SECURE=false

# Database
DB_HOST=localhost
DB_PORT=3306
DB_NAME=attackflow
DB_USER=root
DB_PASSWORD=your_password
```

### 4. Initialize Database

```bash
mysql -u root -p < attackflow.sql
```

This creates the `attackflow` database with the following tables:
- `users` - User accounts and roles
- `files` - Uploaded incident reports
- `tags` - MITRE ATT&CK techniques
- `annotations` - Document annotations
- `attack_flows` - Generated attack flows

### 5. Start the Application

```bash
# Development
npm run dev

# Production
NODE_ENV=production npm start
```

Access the application at `http://localhost:3000`

## Default Accounts

The database script creates test accounts for development:

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| validator | validator123 | Client (Validator) |
| annotator | annotator123 | Annotator |

**Note:** Change these credentials in production.

## User Roles

### Admin
- Full access to all features
- Can view and manage all files
- Can delete files and users
- Access to system administration

### Client (Validator)
- Can view all uploaded files
- Approve or reject generated attack flows
- Provide feedback on attack flows
- Cannot create annotations

### Annotator
- Upload incident report documents
- Create and manage annotations
- Generate attack flows from annotations
- Can only access their own files

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | User authentication |
| POST | `/logout` | End user session |
| POST | `/signup` | Create new account |

### Files
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/upload` | Upload incident report |
| GET | `/userfiles` | Get user's files |
| GET | `/allFiles` | Get all files (admin/client) |
| GET | `/file-content/:fileID` | Get file content |
| DELETE | `/delete-file/:fileID` | Delete file (admin) |

### Annotations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/annotations` | Get annotations for file |
| POST | `/annotations` | Create annotation |
| PUT | `/annotations/:annotationID` | Update annotation |
| DELETE | `/annotations/:annotationID` | Delete annotation |

### Attack Flows
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/generate-attack-flow` | Generate attack flow from annotations |
| GET | `/attack-flows/:fileID` | Get attack flows for file |
| POST | `/approve-flow/:flowID` | Approve attack flow |
| POST | `/reject-flow/:flowID` | Reject attack flow |
| GET | `/download-flow/:flowID` | Download attack flow JSON |

### Tags
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/tags` | Get all MITRE ATT&CK tags |

## Security Features

This application implements comprehensive security measures following OWASP best practices:

### Rate Limiting
- **General API:** 100 requests per 15 minutes
- **Authentication:** 5 attempts per 15 minutes (brute-force protection)
- **File Upload:** 20 uploads per hour
- **Mutations:** 30 operations per minute

### Input Validation
- Schema-based validation using Joi
- Type checking and length limits
- Pattern matching for usernames
- Rejection of unexpected fields
- Input sanitization (null byte removal, trimming)

### Session Security
- HttpOnly cookies (prevents XSS access)
- Secure flag in production (HTTPS only)
- SameSite attribute (CSRF protection)
- Session regeneration on login (fixation prevention)

### HTTP Security Headers (Helmet.js)
- Content Security Policy
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection
- X-Powered-By removed

### Database Security
- Parameterized queries (SQL injection prevention)
- Multiple statements disabled
- Connection pooling with limits

### Password Security
- bcrypt hashing (configurable salt rounds)
- Minimum password length enforcement
- No plain-text storage or logging

For detailed security implementation documentation, see [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md).

## Attack Flow Generation

Generated attack flows follow the MITRE Attack Flow specification (STIX 2.1 format):

```json
{
    "type": "bundle",
    "id": "bundle--uuid",
    "objects": [
        {
            "type": "attack-flow",
            "spec_version": "2.1",
            "id": "attack-flow--uuid",
            "name": "Flow Name",
            "description": "Flow Description",
            "scope": "incident",
            "start_refs": ["attack-action--uuid"]
        },
        {
            "type": "identity",
            "id": "identity--uuid",
            "name": "Creator Name"
        },
        {
            "type": "attack-action",
            "id": "attack-action--uuid",
            "name": "Technique Name",
            "technique_id": "T1234",
            "description": "Action description"
        }
    ]
}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | development | Environment mode |
| `PORT` | 3000 | Server port |
| `SESSION_SECRET` | - | Session encryption key (required) |
| `SESSION_COOKIE_SECURE` | false | Require HTTPS for cookies |
| `SESSION_COOKIE_MAX_AGE` | 86400000 | Session lifetime (ms) |
| `DB_HOST` | localhost | MySQL host |
| `DB_PORT` | 3306 | MySQL port |
| `DB_NAME` | attackflow | Database name |
| `DB_USER` | root | Database user |
| `DB_PASSWORD` | - | Database password |
| `BCRYPT_SALT_ROUNDS` | 12 | Password hashing cost |
| `MAX_FILE_SIZE` | 52428800 | Max upload size (50MB) |
| `RATE_LIMIT_MAX_REQUESTS` | 100 | General rate limit |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | 5 | Auth rate limit |

## Development

### Project Structure

```
app.js                  # Application entry, middleware setup
├── Security middleware (Helmet, rate limiting)
├── Session configuration
├── Database connection pool
└── Error handling

routes/index.js         # API route handlers
├── Authentication routes
├── File management routes
├── Annotation CRUD routes
├── Attack flow generation
└── Validation workflow routes

middleware/
├── rateLimiter.js      # Rate limiting configuration
└── validator.js        # Input validation schemas
```

### Adding New Endpoints

1. Define validation schema in `middleware/validator.js`
2. Add route with appropriate rate limiter and validator
3. Implement route handler with parameterized queries
4. Test with various input scenarios

### Database Schema

```sql
-- Users table
CREATE TABLE users (
    userID INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    access ENUM('admin', 'client', 'annotator') DEFAULT 'annotator'
);

-- Files table
CREATE TABLE files (
    fileID INT AUTO_INCREMENT PRIMARY KEY,
    userID INT,
    fileName VARCHAR(255),
    filePath VARCHAR(500),
    uploadDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userID) REFERENCES users(userID)
);

-- Tags table (MITRE ATT&CK techniques)
CREATE TABLE tags (
    tagID INT AUTO_INCREMENT PRIMARY KEY,
    technique_id VARCHAR(20),
    technique_name VARCHAR(255),
    tactic VARCHAR(100)
);

-- Annotations table
CREATE TABLE annotations (
    annotationID INT AUTO_INCREMENT PRIMARY KEY,
    fileID INT,
    userID INT,
    tagID INT,
    selectedText TEXT,
    startOffset INT,
    endOffset INT,
    customTag VARCHAR(255),
    notes TEXT,
    orderIndex INT DEFAULT 0,
    FOREIGN KEY (fileID) REFERENCES files(fileID),
    FOREIGN KEY (userID) REFERENCES users(userID),
    FOREIGN KEY (tagID) REFERENCES tags(tagID)
);

-- Attack Flows table
CREATE TABLE attack_flows (
    flowID INT AUTO_INCREMENT PRIMARY KEY,
    fileID INT,
    userID INT,
    flowName VARCHAR(255),
    flowDescription TEXT,
    flowJSON LONGTEXT,
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    feedback TEXT,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (fileID) REFERENCES files(fileID),
    FOREIGN KEY (userID) REFERENCES users(userID)
);
```

## Production Deployment

### Security Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Generate strong `SESSION_SECRET` (minimum 32 characters)
- [ ] Enable `SESSION_COOKIE_SECURE=true`
- [ ] Configure HTTPS/TLS
- [ ] Set secure database password
- [ ] Review rate limiting settings
- [ ] Configure firewall rules
- [ ] Enable logging and monitoring

### Generate Secure Session Secret

```bash
# Linux/macOS
openssl rand -hex 32

# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/)
- [STIX 2.1 Specification](https://oasis-open.github.io/cti-documentation/stix/intro.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
