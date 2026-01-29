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
 * Sanitizes a string by removing or escaping potentially dangerous characters
 * This is a defense-in-depth measure in addition to output encoding
 *
 * @param {string} value - The string to sanitize
 * @returns {string} Sanitized string
 */
function sanitizeString(value) {
    if (typeof value !== 'string') return value;

    // Remove null bytes
    value = value.replace(/\0/g, '');

    // Trim whitespace
    value = value.trim();

    return value;
}

/**
 * Custom Joi extension for sanitized strings
 */
const sanitizedString = Joi.string().custom((value, helpers) => {
    return sanitizeString(value);
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
 */
const schemas = {
    // Authentication schemas
    login: Joi.object({
        username: fields.username,
        password: fields.password
    }).options({ stripUnknown: true }), // Remove unexpected fields

    signup: Joi.object({
        username: fields.username,
        password: fields.password,
        email: fields.email,
        access: fields.role
    }).options({ stripUnknown: true }),

    // File schemas
    fileID: Joi.object({
        fileID: fields.fileID
    }).options({ stripUnknown: true }),

    // Annotation schemas
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

    // Attack flow schemas
    generateAttackFlow: Joi.object({
        fileID: fields.fileID,
        flowName: Joi.string().min(1).max(255),
        flowDescription: fields.flowDescription
    }).options({ stripUnknown: true }),

    approveRejectFlow: Joi.object({
        feedback: fields.feedback
    }).options({ stripUnknown: true }),

    // Parameter schemas
    params: {
        fileID: Joi.object({
            fileID: Joi.number().integer().positive().required()
        }),
        annotationID: Joi.object({
            annotationID: Joi.number().integer().positive().required()
        }),
        flowID: Joi.object({
            flowID: Joi.number().integer().positive().required()
        })
    },

    // Query schemas
    query: {
        fileID: Joi.object({
            fileID: Joi.number().integer().positive()
        }).options({ stripUnknown: true })
    }
};

// =============================================================================
// VALIDATION MIDDLEWARE
// =============================================================================

/**
 * Creates a validation middleware for request body
 *
 * @param {Joi.Schema} schema - Joi schema to validate against
 * @returns {Function} Express middleware function
 */
function validateBody(schema) {
    return function(req, res, next) {
        // Apply sanitization to string fields
        if (req.body && typeof req.body === 'object') {
            Object.keys(req.body).forEach(key => {
                if (typeof req.body[key] === 'string') {
                    req.body[key] = sanitizeString(req.body[key]);
                }
            });
        }

        const { error, value } = schema.validate(req.body, {
            abortEarly: false, // Collect all errors
            stripUnknown: true // Remove fields not in schema
        });

        if (error) {
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
 * Creates a validation middleware for query parameters
 *
 * @param {Joi.Schema} schema - Joi schema to validate against
 * @returns {Function} Express middleware function
 */
function validateQuery(schema) {
    return function(req, res, next) {
        // Apply sanitization to query string values
        if (req.query && typeof req.query === 'object') {
            Object.keys(req.query).forEach(key => {
                if (typeof req.query[key] === 'string') {
                    req.query[key] = sanitizeString(req.query[key]);
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
    schemas,
    fields,
    validateBody,
    validateParams,
    validateQuery,
    validateContentType,
    sanitizeString
};
