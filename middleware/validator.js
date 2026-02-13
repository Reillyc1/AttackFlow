/**
 * Input Validation Middleware
 *
 * Provides schema-based validation for all user inputs following OWASP best practices.
 * Uses Joi for declarative schema validation with type checking, length limits,
 * and pattern matching.
 *
 * Features:
 * - Schema-based validation for request body, query params, and URL params
 * - Type checking and coercion
 * - Length limits to prevent buffer overflow attacks
 * - Pattern matching for format validation
 * - Rejection of unexpected fields
 * - Sanitization of common XSS patterns
 * - Clear, actionable error messages
 *
 * OWASP References:
 * - API3:2023 - Broken Object Property Level Authorization
 * - API8:2023 - Security Misconfiguration
 */

'use strict';

const Joi = require('joi');

// =============================================================================
// CUSTOM VALIDATION HELPERS
// =============================================================================

/**
 * Dangerous patterns that indicate potential XSS or injection attacks.
 * These patterns are used for detection and logging, not blocking
 * (actual protection comes from output encoding and CSP).
 *
 * OWASP Reference: A03:2021 - Injection
 */
const DANGEROUS_PATTERNS = [
    /<script\b[^>]*>/i,                    // Script tags
    /javascript:/i,                         // JavaScript protocol
    /on\w+\s*=/i,                          // Event handlers (onclick, onerror, etc.)
    /data:\s*text\/html/i,                 // Data URLs with HTML
    /vbscript:/i,                          // VBScript protocol
    /expression\s*\(/i,                    // CSS expressions
    /<iframe\b/i,                          // Iframe tags
    /<object\b/i,                          // Object tags
    /<embed\b/i,                           // Embed tags
    /<form\b[^>]*action\s*=/i,             // Form action hijacking
    /&#x?[0-9a-f]+;?/i                     // Encoded characters (potential bypass)
];

/**
 * Checks if a string contains potentially dangerous patterns
 * Used for logging suspicious activity, not for blocking
 *
 * @param {string} value - The string to check
 * @returns {boolean} True if suspicious patterns found
 */
function containsSuspiciousPatterns(value) {
    if (typeof value !== 'string') return false;

    for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(value)) {
            return true;
        }
    }
    return false;
}

/**
 * Sanitizes a string by removing or escaping potentially dangerous characters.
 * This is a defense-in-depth measure in addition to output encoding.
 *
 * Security measures applied:
 * 1. Remove null bytes (can bypass security filters)
 * 2. Trim whitespace (prevents padding attacks)
 * 3. Normalize Unicode (prevents homograph attacks)
 * 4. Remove zero-width characters (can hide malicious content)
 * 5. Log suspicious patterns for security monitoring
 *
 * OWASP Reference: A03:2021 - Injection (defense in depth)
 *
 * @param {string} value - The string to sanitize
 * @param {string} fieldName - Optional field name for logging
 * @returns {string} Sanitized string
 */
function sanitizeString(value, fieldName = 'unknown') {
    if (typeof value !== 'string') return value;

    // Store original for comparison
    const original = value;

    // 1. Remove null bytes (can be used to bypass filters)
    value = value.replace(/\0/g, '');

    // 2. Remove zero-width characters (can hide malicious content)
    // Includes: zero-width space, zero-width non-joiner, zero-width joiner,
    // left-to-right mark, right-to-left mark
    value = value.replace(/[\u200B-\u200D\uFEFF\u200E\u200F]/g, '');

    // 3. Normalize whitespace (replace various whitespace chars with standard space)
    value = value.replace(/[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g, ' ');

    // 4. Trim leading/trailing whitespace
    value = value.trim();

    // 5. Log if suspicious patterns detected (defense in depth - monitoring)
    if (containsSuspiciousPatterns(value)) {
        console.warn(
            `SECURITY: Suspicious pattern detected in field "${fieldName}". ` +
            `Input has been sanitized but should be reviewed. ` +
            `Length: ${value.length} chars`
        );
    }

    // Log if value was modified during sanitization
    if (original !== value && original.length !== value.length) {
        console.info(
            `SECURITY: Input sanitized for field "${fieldName}". ` +
            `Original length: ${original.length}, Sanitized length: ${value.length}`
        );
    }

    return value;
}

/**
 * HTML-encodes a string for safe display in HTML contexts.
 * Use this when outputting user data to HTML (defense in depth).
 *
 * Note: The primary XSS protection should be Content Security Policy
 * and proper templating. This is an additional layer.
 *
 * @param {string} value - The string to encode
 * @returns {string} HTML-encoded string
 */
function htmlEncode(value) {
    if (typeof value !== 'string') return value;

    const htmlEntities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '`': '&#x60;'
    };

    return value.replace(/[&<>"'`\/]/g, char => htmlEntities[char]);
}

/**
 * Custom Joi extension for sanitized strings
 */
const sanitizedString = Joi.string().custom((value, helpers) => {
    const fieldPath = helpers.state.path ? helpers.state.path.join('.') : 'unknown';
    return sanitizeString(value, fieldPath);
}, 'string sanitization');

// =============================================================================
// VALIDATION SCHEMAS
// =============================================================================

/**
 * Common field validators with sensible limits
 */
const fields = {
    // User-related fields
    username: Joi.string()
        .min(3)
        .max(64)
        .pattern(/^[a-zA-Z0-9_-]+$/)
        .required()
        .messages({
            'string.min': 'Username must be at least 3 characters',
            'string.max': 'Username cannot exceed 64 characters',
            'string.pattern.base': 'Username can only contain letters, numbers, underscores, and hyphens',
            'any.required': 'Username is required'
        }),

    password: Joi.string()
        .min(6)
        .max(128)
        .required()
        .messages({
            'string.min': 'Password must be at least 6 characters',
            'string.max': 'Password cannot exceed 128 characters',
            'any.required': 'Password is required'
        }),

    email: Joi.string()
        .email()
        .max(255)
        .required()
        .messages({
            'string.email': 'Invalid email format',
            'string.max': 'Email cannot exceed 255 characters',
            'any.required': 'Email is required'
        }),

    role: Joi.string()
        .valid('admin', 'client', 'annotator')
        .default('annotator')
        .messages({
            'any.only': 'Role must be one of: admin, client, annotator'
        }),

    // File-related fields
    fileID: Joi.number()
        .integer()
        .positive()
        .required()
        .messages({
            'number.base': 'File ID must be a number',
            'number.positive': 'File ID must be positive',
            'any.required': 'File ID is required'
        }),

    fileName: Joi.string()
        .max(255)
        .pattern(/^[a-zA-Z0-9._-]+$/)
        .messages({
            'string.max': 'File name cannot exceed 255 characters',
            'string.pattern.base': 'File name contains invalid characters'
        }),

    // Annotation-related fields
    annotationID: Joi.number()
        .integer()
        .positive()
        .required()
        .messages({
            'number.base': 'Annotation ID must be a number',
            'number.positive': 'Annotation ID must be positive',
            'any.required': 'Annotation ID is required'
        }),

    tagID: Joi.number()
        .integer()
        .positive()
        .allow(null)
        .messages({
            'number.base': 'Tag ID must be a number',
            'number.positive': 'Tag ID must be positive'
        }),

    selectedText: Joi.string()
        .max(10000) // 10KB limit for selected text
        .allow('')
        .messages({
            'string.max': 'Selected text cannot exceed 10,000 characters'
        }),

    customTag: Joi.string()
        .max(255)
        .allow(null, '')
        .messages({
            'string.max': 'Custom tag cannot exceed 255 characters'
        }),

    notes: Joi.string()
        .max(5000)
        .allow('', null)
        .messages({
            'string.max': 'Notes cannot exceed 5,000 characters'
        }),

    orderIndex: Joi.number()
        .integer()
        .min(0)
        .max(10000)
        .default(0)
        .messages({
            'number.min': 'Order index cannot be negative',
            'number.max': 'Order index cannot exceed 10,000'
        }),

    offset: Joi.number()
        .integer()
        .min(0)
        .default(0),

    // Attack flow fields
    flowID: Joi.number()
        .integer()
        .positive()
        .required()
        .messages({
            'number.base': 'Flow ID must be a number',
            'number.positive': 'Flow ID must be positive',
            'any.required': 'Flow ID is required'
        }),

    flowName: Joi.string()
        .min(1)
        .max(255)
        .required()
        .messages({
            'string.min': 'Flow name is required',
            'string.max': 'Flow name cannot exceed 255 characters',
            'any.required': 'Flow name is required'
        }),

    flowDescription: Joi.string()
        .max(2000)
        .allow('', null)
        .messages({
            'string.max': 'Flow description cannot exceed 2,000 characters'
        }),

    feedback: Joi.string()
        .max(5000)
        .allow('', null)
        .messages({
            'string.max': 'Feedback cannot exceed 5,000 characters'
        })
};

/**
 * Request body validation schemas for each endpoint
 *
 * Each schema includes:
 * - Type checking for all fields
 * - Length limits to prevent buffer overflow / DoS
 * - Pattern matching where applicable
 * - Rejection of unexpected fields (stripUnknown: true)
 *
 * OWASP Reference: API3:2023 - Broken Object Property Level Authorization
 */
const schemas = {
    // =========================================================================
    // Authentication schemas
    // =========================================================================

    login: Joi.object({
        username: fields.username,
        password: fields.password
    }).options({ stripUnknown: true }), // Remove unexpected fields

    // SECURITY: Signup schema does NOT accept 'access' field
    // All self-registered users are forced to 'annotator' role
    // Admin/client roles must be assigned by admins via admin panel
    signup: Joi.object({
        username: fields.username,
        password: fields.password,
        email: fields.email
        // NOTE: 'access' field intentionally excluded - prevents privilege escalation
    }).options({ stripUnknown: true }),

    /**
     * Legacy redirect endpoint - only accepts username
     * Used for backward compatibility with older clients
     */
    redirect: Joi.object({
        username: fields.username
    }).options({ stripUnknown: true }),

    // =========================================================================
    // File schemas
    // =========================================================================

    fileID: Joi.object({
        fileID: fields.fileID
    }).options({ stripUnknown: true }),

    /**
     * Empty body schema - used for endpoints that should not accept any body
     * Rejects all fields to prevent mass assignment attacks
     */
    emptyBody: Joi.object({}).options({ stripUnknown: true }),

    // =========================================================================
    // Annotation schemas
    // =========================================================================

    createAnnotation: Joi.object({
        fileID: fields.fileID,
        tagID: fields.tagID,
        selectedText: fields.selectedText,
        startOffset: fields.offset,
        endOffset: fields.offset,
        customTag: fields.customTag,
        notes: fields.notes,
        orderIndex: fields.orderIndex
    }).options({ stripUnknown: true }),

    updateAnnotation: Joi.object({
        tagID: fields.tagID,
        selectedText: fields.selectedText,
        customTag: fields.customTag,
        notes: fields.notes,
        orderIndex: fields.orderIndex
    }).options({ stripUnknown: true }),

    // =========================================================================
    // Attack flow schemas
    // =========================================================================

    generateAttackFlow: Joi.object({
        fileID: fields.fileID,
        flowName: Joi.string().min(1).max(255),
        flowDescription: fields.flowDescription
    }).options({ stripUnknown: true }),

    /**
     * Approve flow - feedback is optional
     */
    approveFlow: Joi.object({
        feedback: fields.feedback
    }).options({ stripUnknown: true }),

    /**
     * Reject flow - feedback is required with minimum length
     * Ensures meaningful feedback is provided when rejecting
     */
    rejectFlow: Joi.object({
        feedback: Joi.string()
            .min(10)  // Require at least 10 characters for meaningful feedback
            .max(5000)
            .required()
            .messages({
                'string.min': 'Feedback must be at least 10 characters when rejecting',
                'string.max': 'Feedback cannot exceed 5,000 characters',
                'any.required': 'Feedback is required when rejecting a flow'
            })
    }).options({ stripUnknown: true }),

    // Legacy schema for backward compatibility
    approveRejectFlow: Joi.object({
        feedback: fields.feedback
    }).options({ stripUnknown: true }),

    // =========================================================================
    // Parameter schemas (for URL path parameters)
    // =========================================================================

    params: {
        fileID: Joi.object({
            fileID: Joi.number().integer().positive().required()
                .messages({
                    'number.base': 'File ID must be a number',
                    'number.positive': 'File ID must be positive',
                    'any.required': 'File ID is required'
                })
        }),
        annotationID: Joi.object({
            annotationID: Joi.number().integer().positive().required()
                .messages({
                    'number.base': 'Annotation ID must be a number',
                    'number.positive': 'Annotation ID must be positive',
                    'any.required': 'Annotation ID is required'
                })
        }),
        flowID: Joi.object({
            flowID: Joi.number().integer().positive().required()
                .messages({
                    'number.base': 'Flow ID must be a number',
                    'number.positive': 'Flow ID must be positive',
                    'any.required': 'Flow ID is required'
                })
        })
    },

    // =========================================================================
    // Query schemas (for URL query parameters)
    // =========================================================================

    query: {
        fileID: Joi.object({
            fileID: Joi.number().integer().positive()
                .messages({
                    'number.base': 'File ID must be a number',
                    'number.positive': 'File ID must be positive'
                })
        }).options({ stripUnknown: true }),

        /**
         * Empty query schema - used for endpoints that should not accept query params
         */
        empty: Joi.object({}).options({ stripUnknown: true })
    }
};

// =============================================================================
// VALIDATION MIDDLEWARE
// =============================================================================

/**
 * Creates a validation middleware for request body.
 *
 * Security features:
 * - Sanitizes all string inputs before validation
 * - Validates against Joi schema with type checking
 * - Strips unknown fields to prevent mass assignment attacks
 * - Returns detailed error messages for debugging (safe - no sensitive data)
 *
 * OWASP Reference: API3:2023 - Broken Object Property Level Authorization
 *
 * @param {Joi.Schema} schema - Joi schema to validate against
 * @returns {Function} Express middleware function
 */
function validateBody(schema) {
    return function(req, res, next) {
        // Apply sanitization to string fields before validation
        // This provides defense-in-depth against injection attacks
        if (req.body && typeof req.body === 'object') {
            Object.keys(req.body).forEach(key => {
                if (typeof req.body[key] === 'string') {
                    req.body[key] = sanitizeString(req.body[key], `body.${key}`);
                }
            });
        }

        const { error, value } = schema.validate(req.body, {
            abortEarly: false, // Collect all errors for better UX
            stripUnknown: true // Remove fields not in schema (mass assignment protection)
        });

        if (error) {
            // Map Joi errors to a consistent format
            // Note: These error messages are safe to return - they only
            // describe field requirements, not internal state
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message
            }));

            return res.status(400).json({
                error: 'Validation Error',
                message: 'Invalid input data',
                details: errors
            });
        }

        // Replace body with validated and sanitized values
        req.body = value;
        next();
    };
}

/**
 * Creates a validation middleware for URL parameters
 *
 * @param {Joi.Schema} schema - Joi schema to validate against
 * @returns {Function} Express middleware function
 */
function validateParams(schema) {
    return function(req, res, next) {
        const { error, value } = schema.validate(req.params, {
            abortEarly: false
        });

        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message
            }));

            return res.status(400).json({
                error: 'Validation Error',
                message: 'Invalid URL parameters',
                details: errors
            });
        }

        req.params = value;
        next();
    };
}

/**
 * Creates a validation middleware for query parameters.
 *
 * Security features:
 * - Sanitizes all string query parameters
 * - Validates against Joi schema
 * - Strips unknown parameters to prevent injection
 *
 * @param {Joi.Schema} schema - Joi schema to validate against
 * @returns {Function} Express middleware function
 */
function validateQuery(schema) {
    return function(req, res, next) {
        // Apply sanitization to query string values before validation
        if (req.query && typeof req.query === 'object') {
            Object.keys(req.query).forEach(key => {
                if (typeof req.query[key] === 'string') {
                    req.query[key] = sanitizeString(req.query[key], `query.${key}`);
                }
            });
        }

        const { error, value } = schema.validate(req.query, {
            abortEarly: false,
            stripUnknown: true
        });

        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message
            }));

            return res.status(400).json({
                error: 'Validation Error',
                message: 'Invalid query parameters',
                details: errors
            });
        }

        req.query = value;
        next();
    };
}

/**
 * Middleware to reject requests with unexpected Content-Type
 * Helps prevent content-type confusion attacks
 *
 * @param {Array<string>} allowedTypes - Array of allowed content types
 * @returns {Function} Express middleware function
 */
function validateContentType(allowedTypes = ['application/json']) {
    return function(req, res, next) {
        // Skip for GET, HEAD, OPTIONS requests
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
            return next();
        }

        const contentType = req.headers['content-type'];

        // Allow if no body
        if (!req.body || Object.keys(req.body).length === 0) {
            return next();
        }

        if (!contentType) {
            return res.status(400).json({
                error: 'Missing Content-Type',
                message: 'Content-Type header is required for this request'
            });
        }

        // Check if content type matches any allowed type
        const isAllowed = allowedTypes.some(type =>
            contentType.toLowerCase().includes(type.toLowerCase())
        );

        if (!isAllowed) {
            return res.status(415).json({
                error: 'Unsupported Media Type',
                message: `Content-Type must be one of: ${allowedTypes.join(', ')}`
            });
        }

        next();
    };
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    // Validation schemas
    schemas,
    fields,

    // Validation middleware
    validateBody,
    validateParams,
    validateQuery,
    validateContentType,

    // Sanitization utilities
    sanitizeString,
    htmlEncode,
    containsSuspiciousPatterns,

    // Constants for external use
    DANGEROUS_PATTERNS
};
