/**
 * Rate Limiting Middleware
 *
 * Implements comprehensive rate limiting to protect against brute-force attacks,
 * DoS attempts, and API abuse. Uses a combination of IP-based and user-based limiting.
 *
 * Features:
 * - IP-based rate limiting for all requests
 * - User-based rate limiting for authenticated endpoints
 * - Stricter limits for authentication endpoints
 * - Read-only endpoint limits for data retrieval
 * - Graceful 429 responses with retry information and Retry-After header
 * - Configurable via environment variables
 *
 * OWASP References:
 * - API4:2023 - Unrestricted Resource Consumption
 * - API2:2023 - Broken Authentication (rate limiting prevents brute-force)
 *
 * Security Best Practices:
 * - All public endpoints are rate limited
 * - Authentication endpoints have stricter limits
 * - Rate limits are applied per IP + User combination where applicable
 * - Graceful degradation with informative error responses
 */

'use strict';

const rateLimit = require('express-rate-limit');

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Load rate limit configuration from environment variables with sensible defaults.
 * All limits are designed to allow normal usage while preventing abuse.
 *
 * Environment Variables:
 * - RATE_LIMIT_WINDOW_MS: General rate limit window (default: 15 minutes)
 * - RATE_LIMIT_MAX_REQUESTS: Max requests per window (default: 100)
 * - AUTH_RATE_LIMIT_WINDOW_MS: Auth rate limit window (default: 15 minutes)
 * - AUTH_RATE_LIMIT_MAX_REQUESTS: Max auth attempts per window (default: 5)
 * - UPLOAD_RATE_LIMIT_WINDOW_MS: Upload rate limit window (default: 1 hour)
 * - UPLOAD_RATE_LIMIT_MAX_REQUESTS: Max uploads per window (default: 20)
 * - READ_RATE_LIMIT_WINDOW_MS: Read rate limit window (default: 1 minute)
 * - READ_RATE_LIMIT_MAX_REQUESTS: Max read requests per window (default: 60)
 */
const config = {
    // General API limits - baseline protection for all endpoints
    general: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000, // 15 minutes
        max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100 // 100 requests per window
    },
    // Authentication endpoint limits (stricter to prevent brute-force attacks)
    auth: {
        windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000, // 15 minutes
        max: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS, 10) || 5 // 5 attempts per window
    },
    // File upload limits - prevent storage abuse
    upload: {
        windowMs: parseInt(process.env.UPLOAD_RATE_LIMIT_WINDOW_MS, 10) || 60 * 60 * 1000, // 1 hour
        max: parseInt(process.env.UPLOAD_RATE_LIMIT_MAX_REQUESTS, 10) || 20 // 20 uploads per hour
    },
    // API mutation limits (create, update, delete) - prevent rapid modifications
    mutation: {
        windowMs: parseInt(process.env.MUTATION_RATE_LIMIT_WINDOW_MS, 10) || 60 * 1000, // 1 minute
        max: parseInt(process.env.MUTATION_RATE_LIMIT_MAX_REQUESTS, 10) || 30 // 30 mutations per minute
    },
    // Read-only endpoint limits - higher limits for data retrieval
    read: {
        windowMs: parseInt(process.env.READ_RATE_LIMIT_WINDOW_MS, 10) || 60 * 1000, // 1 minute
        max: parseInt(process.env.READ_RATE_LIMIT_MAX_REQUESTS, 10) || 60 // 60 reads per minute
    },
    // Session/status check limits - very frequent but low-cost operations
    session: {
        windowMs: 60 * 1000, // 1 minute
        max: 120 // 120 session checks per minute (supports polling)
    },
    // Download limits - prevent bandwidth abuse
    download: {
        windowMs: parseInt(process.env.DOWNLOAD_RATE_LIMIT_WINDOW_MS, 10) || 60 * 60 * 1000, // 1 hour
        max: parseInt(process.env.DOWNLOAD_RATE_LIMIT_MAX_REQUESTS, 10) || 50 // 50 downloads per hour
    }
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Generates a unique key for rate limiting that combines IP and user ID
 * This prevents a single user from exhausting limits across multiple IPs
 * and protects shared IPs from being blocked due to one bad actor
 *
 * @param {Request} req - Express request object
 * @returns {string} Unique identifier for rate limiting
 */
function generateKey(req) {
    // Get IP address (handles proxy scenarios)
    const ip = req.ip || req.connection.remoteAddress || 'unknown';

    // Include user ID if authenticated for user-specific limiting
    const userId = req.session && req.session.userID ? req.session.userID : 'anonymous';

    return `${ip}-${userId}`;
}

/**
 * Generates a key based only on IP address
 * Used for pre-authentication endpoints
 *
 * @param {Request} req - Express request object
 * @returns {string} IP-based identifier
 */
function generateIpKey(req) {
    return req.ip || req.connection.remoteAddress || 'unknown';
}

/**
 * Standard rate limit exceeded handler
 * Returns a graceful 429 response with retry information
 *
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 */
function standardLimitHandler(req, res) {
    res.status(429).json({
        error: 'Too Many Requests',
        message: 'You have exceeded the rate limit. Please try again later.',
        retryAfter: Math.ceil(config.general.windowMs / 1000)
    });
}

/**
 * Authentication rate limit exceeded handler
 * Provides specific message for login attempts
 *
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 */
function authLimitHandler(req, res) {
    res.status(429).json({
        error: 'Too Many Login Attempts',
        message: 'Too many login attempts from this IP address. Please try again after 15 minutes.',
        retryAfter: Math.ceil(config.auth.windowMs / 1000)
    });
}

/**
 * Upload rate limit exceeded handler
 *
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 */
function uploadLimitHandler(req, res) {
    res.status(429).json({
        error: 'Upload Limit Exceeded',
        message: 'You have exceeded the file upload limit. Please try again later.',
        retryAfter: Math.ceil(config.upload.windowMs / 1000)
    });
}

// =============================================================================
// RATE LIMITERS
// =============================================================================

/**
 * General API Rate Limiter
 * Applied to all routes as a baseline protection
 *
 * Limits: 100 requests per 15 minutes per IP+User combination
 */
const generalLimiter = rateLimit({
    windowMs: config.general.windowMs,
    max: config.general.max,
    message: {
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Please slow down your requests.'
    },
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false, // Disable `X-RateLimit-*` headers
    keyGenerator: generateKey,
    handler: standardLimitHandler,
    skip: function(req) {
        // Skip rate limiting for static assets
        return req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/);
    }
});

/**
 * Authentication Rate Limiter
 * Applied to login, signup, and password-related endpoints
 * Stricter limits to prevent brute-force attacks
 *
 * Limits: 5 attempts per 15 minutes per IP
 */
const authLimiter = rateLimit({
    windowMs: config.auth.windowMs,
    max: config.auth.max,
    message: {
        error: 'Too Many Login Attempts',
        message: 'Too many authentication attempts. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateIpKey, // IP-only for pre-auth endpoints
    handler: authLimitHandler,
    skipSuccessfulRequests: false // Count all requests, not just failures
});

/**
 * File Upload Rate Limiter
 * Prevents abuse of file upload functionality
 *
 * Limits: 20 uploads per hour per user
 */
const uploadLimiter = rateLimit({
    windowMs: config.upload.windowMs,
    max: config.upload.max,
    message: {
        error: 'Upload Limit Exceeded',
        message: 'Too many file uploads. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateKey,
    handler: uploadLimitHandler
});

/**
 * Mutation Rate Limiter
 * Applied to create, update, and delete operations
 * Prevents rapid-fire modifications
 *
 * Limits: 30 mutations per minute
 */
const mutationLimiter = rateLimit({
    windowMs: config.mutation.windowMs,
    max: config.mutation.max,
    message: {
        error: 'Too Many Requests',
        message: 'Too many modification requests. Please slow down.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateKey,
    handler: standardLimitHandler
});

/**
 * Strict Rate Limiter
 * For extremely sensitive operations (password reset, account deletion, etc.)
 *
 * Limits: 3 requests per 5 minutes
 */
const strictLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 3,
    message: {
        error: 'Rate Limited',
        message: 'This action is rate limited. Please wait before trying again.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateKey,
    handler: function(req, res) {
        res.status(429).json({
            error: 'Rate Limited',
            message: 'This sensitive operation is rate limited. Please wait before trying again.',
            retryAfter: 300 // 5 minutes
        });
    }
});

/**
 * Read-Only Endpoint Rate Limiter
 * Applied to GET requests that retrieve data (files, annotations, etc.)
 * Higher limits than mutations since reads are less resource-intensive
 *
 * Limits: 60 requests per minute per IP+User combination
 */
const readLimiter = rateLimit({
    windowMs: config.read.windowMs,
    max: config.read.max,
    message: {
        error: 'Too Many Requests',
        message: 'Too many data requests. Please slow down.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateKey,
    handler: function(req, res) {
        res.status(429).json({
            error: 'Too Many Requests',
            message: 'You have made too many data requests. Please wait before trying again.',
            retryAfter: Math.ceil(config.read.windowMs / 1000)
        });
    },
    skip: function(req) {
        // Skip rate limiting for static assets
        return req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/);
    }
});

/**
 * Session Check Rate Limiter
 * For session status endpoints that may be polled frequently
 * Very permissive limits for low-cost operations
 *
 * Limits: 120 requests per minute
 */
const sessionLimiter = rateLimit({
    windowMs: config.session.windowMs,
    max: config.session.max,
    message: {
        error: 'Too Many Requests',
        message: 'Too many session requests. Please slow down.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateIpKey, // IP-based for session checks
    handler: function(req, res) {
        res.status(429).json({
            error: 'Too Many Requests',
            message: 'Too many session status requests. Please slow down.',
            retryAfter: Math.ceil(config.session.windowMs / 1000)
        });
    }
});

/**
 * Download Rate Limiter
 * For file download endpoints - prevents bandwidth abuse
 *
 * Limits: 50 downloads per hour per user
 */
const downloadLimiter = rateLimit({
    windowMs: config.download.windowMs,
    max: config.download.max,
    message: {
        error: 'Download Limit Exceeded',
        message: 'Too many file downloads. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateKey,
    handler: function(req, res) {
        res.status(429).json({
            error: 'Download Limit Exceeded',
            message: 'You have exceeded the download limit. Please try again later.',
            retryAfter: Math.ceil(config.download.windowMs / 1000)
        });
    }
});

/**
 * Public Endpoint Rate Limiter
 * For public endpoints that don't require authentication (e.g., /tags)
 * Uses IP-only limiting since there's no user context
 *
 * Limits: 30 requests per minute per IP
 */
const publicLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // 30 requests per minute
    message: {
        error: 'Too Many Requests',
        message: 'Too many requests from this IP address. Please slow down.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: generateIpKey,
    handler: function(req, res) {
        res.status(429).json({
            error: 'Too Many Requests',
            message: 'Too many requests from this IP address. Please try again later.',
            retryAfter: 60
        });
    }
});

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    generalLimiter,
    authLimiter,
    uploadLimiter,
    mutationLimiter,
    strictLimiter,
    readLimiter,
    sessionLimiter,
    downloadLimiter,
    publicLimiter,
    generateKey,
    generateIpKey,
    config
};
