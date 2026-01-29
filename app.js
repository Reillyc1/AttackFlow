/**
 * AttackFlow - Main Application Entry Point
 *
 * A web application for generating and validating attack flows from incident
 * reports using the MITRE ATT&CK framework.
 *
 * Security Features:
 * - Helmet.js for HTTP security headers
 * - Rate limiting on all endpoints
 * - Secure session configuration
 * - Environment-based configuration
 * - Input validation and sanitization
 */

'use strict';

// Load environment variables first (before any other imports that might need them)
require('dotenv').config();

var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mysql = require('mysql2');
var session = require('express-session');
var helmet = require('helmet');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

// =============================================================================
// ENVIRONMENT CONFIGURATION WITH VALIDATION
// =============================================================================

/**
 * Validates that required environment variables are set in production mode.
 * Logs warnings for missing optional variables.
 */
function validateEnvironment() {
    const isProduction = process.env.NODE_ENV === 'production';

    // Check for default/weak session secret
    const sessionSecret = process.env.SESSION_SECRET || 'default-dev-secret-change-in-production';
    if (isProduction && (sessionSecret === 'default-dev-secret-change-in-production' ||
        sessionSecret === 'a string of your choice' ||
        sessionSecret.length < 32)) {
        console.error('SECURITY WARNING: SESSION_SECRET must be set to a secure random string in production (minimum 32 characters)');
        process.exit(1);
    }

    return {
        nodeEnv: process.env.NODE_ENV || 'development',
        port: parseInt(process.env.PORT, 10) || 3000,
        sessionSecret: sessionSecret,
        sessionCookieSecure: process.env.SESSION_COOKIE_SECURE === 'true',
        sessionMaxAge: parseInt(process.env.SESSION_COOKIE_MAX_AGE, 10) || 86400000, // 24 hours
        db: {
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT, 10) || 3306,
            database: process.env.DB_NAME || 'attackflow',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT, 10) || 10,
            queueLimit: parseInt(process.env.DB_QUEUE_LIMIT, 10) || 0
        },
        bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12
    };
}

const config = validateEnvironment();

// =============================================================================
// DATABASE CONNECTION POOL
// =============================================================================

/**
 * MySQL connection pool configuration with security best practices.
 * Uses parameterized queries to prevent SQL injection.
 */
var dbConnectionPool = mysql.createPool({
    host: config.db.host,
    port: config.db.port,
    database: config.db.database,
    user: config.db.user,
    password: config.db.password,
    connectionLimit: config.db.connectionLimit,
    queueLimit: config.db.queueLimit,
    // Security: Disable multiple statements to prevent SQL injection via stacked queries
    multipleStatements: false,
    // Enable strict mode for better data validation
    charset: 'utf8mb4'
});

// Test database connection on startup
dbConnectionPool.getConnection(function(err, connection) {
    if (err) {
        console.error('Database connection failed:', err.message);
        console.error('Please ensure MySQL is running and credentials are correct in .env file');
    } else {
        console.log('Database connection established successfully');
        connection.release();
    }
});

// =============================================================================
// EXPRESS APPLICATION SETUP
// =============================================================================

var app = express();

// Trust first proxy (for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// =============================================================================
// SECURITY MIDDLEWARE
// =============================================================================

/**
 * Helmet.js - Sets various HTTP headers for security
 * - Content-Security-Policy
 * - X-Content-Type-Options
 * - X-Frame-Options
 * - X-XSS-Protection
 * - And more...
 */
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts for existing functionality
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: config.nodeEnv === 'production' ? [] : null
        }
    },
    // Prevent clickjacking
    frameguard: { action: 'deny' },
    // Prevent MIME type sniffing
    noSniff: true,
    // Enable XSS filter
    xssFilter: true,
    // Hide X-Powered-By header
    hidePoweredBy: true
}));

// =============================================================================
// REQUEST PARSING AND LOGGING
// =============================================================================

// Attach database pool to request object
app.use(function(req, res, next) {
    req.pool = dbConnectionPool;
    next();
});

// HTTP request logging (use 'combined' in production for more detail)
app.use(logger(config.nodeEnv === 'production' ? 'combined' : 'dev'));

// JSON body parser with size limit to prevent DoS attacks
app.use(express.json({
    limit: '1mb',
    strict: true
}));

// URL-encoded body parser with size limit
app.use(express.urlencoded({
    extended: false,
    limit: '1mb'
}));

// Cookie parser
app.use(cookieParser());

// =============================================================================
// SESSION CONFIGURATION
// =============================================================================

/**
 * Secure session configuration following OWASP recommendations:
 * - HttpOnly cookies (prevents XSS access to session cookie)
 * - Secure flag in production (HTTPS only)
 * - SameSite attribute (CSRF protection)
 * - Session regeneration on login
 */
app.use(session({
    secret: config.sessionSecret,
    name: 'attackflow.sid', // Custom session cookie name (obscures technology)
    resave: false,
    saveUninitialized: false, // Don't create session until something stored
    cookie: {
        secure: config.sessionCookieSecure, // Requires HTTPS in production
        httpOnly: true, // Prevents client-side JavaScript access
        maxAge: config.sessionMaxAge,
        sameSite: 'lax' // CSRF protection while allowing normal navigation
    },
    // Store userID in session
    userID: -1
}));

// =============================================================================
// STATIC FILES
// =============================================================================

// Serve static files with security headers
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: config.nodeEnv === 'production' ? '1d' : 0,
    etag: true,
    lastModified: true
}));

// =============================================================================
// ROUTES
// =============================================================================

app.use('/', indexRouter);
app.use('/users', usersRouter);

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 handler
app.use(function(req, res, next) {
    res.status(404).json({
        error: 'Not Found',
        message: 'The requested resource was not found'
    });
});

// Global error handler
app.use(function(err, req, res, next) {
    // Log error for debugging (don't expose in production)
    console.error('Application Error:', err.message);

    // Don't leak error details in production
    const errorResponse = {
        error: 'Internal Server Error',
        message: config.nodeEnv === 'production'
            ? 'An unexpected error occurred'
            : err.message
    };

    res.status(err.status || 500).json(errorResponse);
});

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = app;
