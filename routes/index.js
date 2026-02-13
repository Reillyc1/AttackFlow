/**
 * AttackFlow API Routes
 *
 * This module defines all API endpoints for the AttackFlow application including:
 * - Authentication (login, logout, signup)
 * - File management (upload, download, delete)
 * - Annotations (CRUD operations)
 * - Attack Flow generation and validation
 *
 * Security Features:
 * - Rate limiting on all endpoints (IP + user based)
 * - Input validation using Joi schemas
 * - Role-based access control
 * - Parameterized SQL queries (SQL injection prevention)
 * - Session-based authentication
 */

'use strict';

var express = require('express');
var router = express.Router();
var path = require('path');
var fs = require('fs');
var bcrypt = require('bcrypt');
var { v4: uuidv4 } = require('uuid');

// Security middleware - Rate limiting (OWASP API4:2023 - Unrestricted Resource Consumption)
var {
    authLimiter,      // For login/signup: 5 attempts per 15 min
    uploadLimiter,    // For file uploads: 20 per hour
    mutationLimiter,  // For create/update/delete: 30 per minute
    generalLimiter,   // General baseline: 100 per 15 min
    readLimiter,      // For GET data endpoints: 60 per minute
    sessionLimiter,   // For session checks: 120 per minute
    downloadLimiter,  // For file downloads: 50 per hour
    publicLimiter     // For public endpoints: 30 per minute (IP-only)
} = require('../middleware/rateLimiter');

// Security middleware - Input validation (OWASP API3:2023 - Broken Object Property Level Authorization)
var { schemas, validateBody, validateParams, validateQuery, validateContentType } = require('../middleware/validator');

// =============================================================================
// FILE UPLOAD CONFIGURATION
// =============================================================================

const multer = require('multer');

/**
 * Multer storage configuration with secure filename generation
 */
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './public/resources');
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        // Sanitize filename: only allow alphanumeric, dots, and hyphens
        const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        cb(null, `${path.basename(safeName, path.extname(safeName))}_${timestamp}${path.extname(safeName)}`);
    }
});

/**
 * Multer configuration with file type validation and size limits
 */
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Validate file extension
        const allowedExtensions = (process.env.ALLOWED_FILE_EXTENSIONS || '.pdf,.doc,.docx,.txt').split(',');
        const ext = path.extname(file.originalname).toLowerCase();

        if (allowedExtensions.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error(`Invalid file type. Allowed types: ${allowedExtensions.join(', ')}`));
        }
    },
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE, 10) || 50 * 1024 * 1024 // 50MB default
    }
});

// =============================================================================
// SECURITY CONFIGURATION
// =============================================================================

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;

// =============================================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================================

/**
 * Middleware to require authentication
 * Checks for valid session with userID
 */
function requireAuth(req, res, next) {
    if (req.session && req.session.userID) {
        next();
    } else {
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Please log in to access this resource'
        });
    }
}

/**
 * Middleware to require specific user roles
 * Must be used after requireAuth
 *
 * @param {Array<string>} roles - Array of allowed roles
 * @returns {Function} Express middleware function
 */
function requireRole(roles) {
    return function(req, res, next) {
        if (!req.session || !req.session.userID) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Please log in to access this resource'
            });
        }

        req.pool.getConnection(function(err, connection) {
            if (err) {
                console.error('Database connection error:', err.message);
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to verify permissions'
                });
            }

            connection.query(
                'SELECT access FROM users WHERE userID = ?',
                [req.session.userID],
                function(err, rows) {
                    connection.release();

                    if (err || rows.length === 0) {
                        return res.status(500).json({
                            error: 'Authorization Error',
                            message: 'Unable to verify user role'
                        });
                    }

                    if (roles.includes(rows[0].access)) {
                        req.userRole = rows[0].access;
                        next();
                    } else {
                        res.status(403).json({
                            error: 'Forbidden',
                            message: 'You do not have permission to perform this action'
                        });
                    }
                }
            );
        });
    };
}

/**
 * Helper function to check if user can access a file
 * Users can access their own files; admins and clients can access all files
 *
 * OWASP Reference: API1:2023 - Broken Object Level Authorization
 *
 * @param {Object} pool - Database connection pool
 * @param {number} fileID - The file ID to check
 * @param {number} userID - The user ID making the request
 * @param {string} userRole - The user's role (admin, client, annotator)
 * @param {Function} callback - Callback with (error, isAuthorized, fileData)
 */
function checkFileAccess(pool, fileID, userID, userRole, callback) {
    // Admins and clients can access all files
    if (userRole === 'admin' || userRole === 'client') {
        pool.getConnection(function(err, connection) {
            if (err) {
                return callback(err, false, null);
            }
            connection.query(
                'SELECT * FROM files WHERE fileID = ?',
                [fileID],
                function(err, rows) {
                    connection.release();
                    if (err) {
                        return callback(err, false, null);
                    }
                    if (rows.length === 0) {
                        return callback(null, false, null);
                    }
                    return callback(null, true, rows[0]);
                }
            );
        });
    } else {
        // Annotators can only access their own files
        pool.getConnection(function(err, connection) {
            if (err) {
                return callback(err, false, null);
            }
            connection.query(
                'SELECT * FROM files WHERE fileID = ? AND userID = ?',
                [fileID, userID],
                function(err, rows) {
                    connection.release();
                    if (err) {
                        return callback(err, false, null);
                    }
                    if (rows.length === 0) {
                        // Check if file exists at all (for better error message)
                        pool.getConnection(function(err2, conn2) {
                            if (err2) {
                                return callback(err2, false, null);
                            }
                            conn2.query(
                                'SELECT fileID FROM files WHERE fileID = ?',
                                [fileID],
                                function(err3, rows2) {
                                    conn2.release();
                                    if (err3 || rows2.length === 0) {
                                        // File doesn't exist
                                        return callback(null, false, null);
                                    }
                                    // File exists but user doesn't have access
                                    return callback('FORBIDDEN', false, null);
                                }
                            );
                        });
                    } else {
                        return callback(null, true, rows[0]);
                    }
                }
            );
        });
    }
}

/**
 * Middleware to verify file ownership before allowing access
 * Extracts fileID from req.params.fileID or req.body.fileID
 *
 * OWASP Reference: API1:2023 - Broken Object Level Authorization
 */
function requireFileAccess(req, res, next) {
    const fileID = parseInt(req.params.fileID || req.body.fileID, 10);

    if (!fileID || isNaN(fileID)) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'File ID is required'
        });
    }

    // Get user's role first
    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to verify access'
            });
        }

        connection.query(
            'SELECT access FROM users WHERE userID = ?',
            [req.session.userID],
            function(err, rows) {
                connection.release();

                if (err || rows.length === 0) {
                    return res.status(500).json({
                        error: 'Authorization Error',
                        message: 'Unable to verify permissions'
                    });
                }

                const userRole = rows[0].access;
                req.userRole = userRole;

                checkFileAccess(
                    req.pool,
                    fileID,
                    req.session.userID,
                    userRole,
                    function(err, isAuthorized, fileData) {
                        if (err === 'FORBIDDEN') {
                            console.warn(
                                `SECURITY: User ${req.session.userID} attempted to access file ${fileID} owned by another user`
                            );
                            return res.status(403).json({
                                error: 'Forbidden',
                                message: 'You do not have permission to access this file'
                            });
                        }
                        if (err) {
                            return res.status(500).json({
                                error: 'Database Error',
                                message: 'Unable to verify file access'
                            });
                        }
                        if (!isAuthorized) {
                            return res.status(404).json({
                                error: 'Not Found',
                                message: 'File not found'
                            });
                        }

                        // Attach file data to request for use in handler
                        req.fileData = fileData;
                        next();
                    }
                );
            }
        );
    });
}

// =============================================================================
// PUBLIC ROUTES
// =============================================================================

/**
 * GET /
 * Serve the login page
 */
router.get('/', function(req, res, next) {
    res.sendFile(path.resolve(__dirname + '/../public/index.html'));
});

/**
 * GET /session_id
 * Get current session information
 *
 * Rate limited: 120 requests per minute (session polling allowed)
 * Security: Returns minimal session info, no sensitive data exposed
 */
router.get('/session_id', sessionLimiter, function(req, res, next) {
    if (req.session && req.session.userID) {
        res.json({
            userID: req.session.userID,
            username: req.session.username,
            role: req.session.role
        });
    } else {
        res.json({ userID: null });
    }
});

/**
 * GET /tags
 * Get all predefined MITRE ATT&CK tags
 * Public endpoint - tags are not sensitive
 *
 * Rate limited: 30 requests per minute per IP (public endpoint, IP-only limiting)
 */
router.get('/tags', publicLimiter, function(req, res) {
    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch tags'
            });
        }

        connection.query('SELECT * FROM tags ORDER BY category, name', function(err, rows) {
            connection.release();
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to fetch tags'
                });
            }
            res.json(rows);
        });
    });
});

// =============================================================================
// AUTHENTICATION ROUTES
// =============================================================================

/**
 * POST /login
 * Authenticate user and create session
 *
 * Rate limited: 5 attempts per 15 minutes per IP
 */
router.post('/login',
    authLimiter,
    validateContentType(),
    validateBody(schemas.login),
    async function(req, res, next) {
        const { username, password } = req.body;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                console.error('Database connection error:', err.message);
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to process login request'
                });
            }

            // Use parameterized query to prevent SQL injection
            connection.query(
                'SELECT userID, username, password, access FROM users WHERE username = ?',
                [username],
                async function(err, rows) {
                    connection.release();

                    if (err) {
                        console.error('Query error:', err.message);
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to process login request'
                        });
                    }

                    if (rows.length === 0) {
                        // Use generic message to prevent username enumeration
                        return res.status(401).json({
                            error: 'Authentication Failed',
                            message: 'Invalid username or password'
                        });
                    }

                    const user = rows[0];

                    try {
                        // Check if password is hashed (bcrypt hashes start with $2b$ or $2a$)
                        let isMatch = false;
                        if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
                            isMatch = await bcrypt.compare(password, user.password);
                        } else {
                            // Legacy plaintext comparison (for migration from old system)
                            // In production, this should trigger a password hash update
                            isMatch = (user.password === password);
                        }

                        if (isMatch) {
                            // Regenerate session to prevent session fixation
                            req.session.regenerate(function(err) {
                                if (err) {
                                    console.error('Session regeneration error:', err);
                                }

                                // Set session data
                                req.session.userID = user.userID;
                                req.session.username = user.username;
                                req.session.role = user.access;

                                // Determine redirect URL based on role
                                let redirectTo = '/home-annotator.html';
                                switch (user.access) {
                                    case 'admin':
                                        redirectTo = '/home-admin.html';
                                        break;
                                    case 'client':
                                        redirectTo = '/home-client.html';
                                        break;
                                    case 'annotator':
                                        redirectTo = '/home-annotator.html';
                                        break;
                                }

                                res.json({
                                    success: true,
                                    redirectTo: redirectTo,
                                    role: user.access
                                });
                            });
                        } else {
                            res.status(401).json({
                                error: 'Authentication Failed',
                                message: 'Invalid username or password'
                            });
                        }
                    } catch (error) {
                        console.error('Password comparison error:', error);
                        res.status(500).json({
                            error: 'Authentication Error',
                            message: 'Unable to process login request'
                        });
                    }
                }
            );
        });
    }
);

/**
 * POST /logout
 * Destroy session and log out user
 *
 * Rate limited: 5 attempts per 15 minutes (uses auth limiter to prevent abuse)
 * Security: Clears session and cookie, prevents session hijacking
 */
router.post('/logout', authLimiter, function(req, res) {
    req.session.destroy(function(err) {
        if (err) {
            return res.status(500).json({
                error: 'Logout Error',
                message: 'Unable to complete logout'
            });
        }
        res.clearCookie('attackflow.sid');
        res.json({ success: true });
    });
});

/**
 * POST /signup
 * Create new user account
 *
 * Rate limited: 5 attempts per 15 minutes per IP
 */
router.post('/signup',
    authLimiter,
    validateContentType(),
    validateBody(schemas.signup),
    async function(req, res, next) {
        const { username, password, email, access } = req.body;

        // Default role is annotator (validated by schema)
        const userRole = access || 'annotator';

        try {
            // Hash password with configured salt rounds
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

            req.pool.getConnection(function(err, connection) {
                if (err) {
                    console.error('Database connection error:', err.message);
                    return res.status(500).json({
                        error: 'Database Error',
                        message: 'Unable to create account'
                    });
                }

                // Check for existing email or username
                connection.query(
                    'SELECT userID FROM users WHERE email = ? OR username = ?',
                    [email, username],
                    function(err, rows) {
                        if (err) {
                            connection.release();
                            console.error('Query error:', err.message);
                            return res.status(500).json({
                                error: 'Database Error',
                                message: 'Unable to create account'
                            });
                        }

                        if (rows.length > 0) {
                            connection.release();
                            return res.status(409).json({
                                error: 'Account Exists',
                                message: 'An account with this email or username already exists'
                            });
                        }

                        // Insert new user
                        connection.query(
                            'INSERT INTO users (username, password, email, access) VALUES (?, ?, ?, ?)',
                            [username, hashedPassword, email, userRole],
                            function(err, result) {
                                connection.release();
                                if (err) {
                                    console.error('Insert error:', err.message);
                                    return res.status(500).json({
                                        error: 'Database Error',
                                        message: 'Unable to create account'
                                    });
                                }

                                res.status(201).json({
                                    success: true,
                                    message: 'Account created successfully'
                                });
                            }
                        );
                    }
                );
            });
        } catch (error) {
            console.error('Signup error:', error);
            res.status(500).json({
                error: 'Server Error',
                message: 'Unable to create account'
            });
        }
    }
);

/**
 * POST /redirect
 * Legacy redirect endpoint for backward compatibility
 *
 * Rate limited: 5 attempts per 15 minutes (auth limiter)
 * Security: Validates username format, uses parameterized queries
 *
 * NOTE: This endpoint should be deprecated in favor of using the
 * role information returned by /login endpoint
 */
router.post('/redirect',
    authLimiter,
    validateContentType(),
    validateBody(schemas.redirect),
    function(req, res) {
        const { username } = req.body;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to process request'
                });
            }

            connection.query(
                'SELECT access FROM users WHERE username = ?',
                [username],
                function(err, rows) {
                    connection.release();

                    // Return generic error to prevent username enumeration
                    if (err || rows.length === 0) {
                        return res.status(404).json({
                            error: 'Not Found',
                            message: 'Unable to determine redirect location'
                        });
                    }

                    let redirectTo = '/home-annotator.html';
                    switch (rows[0].access) {
                        case 'admin':
                            redirectTo = '/home-admin.html';
                            break;
                        case 'client':
                            redirectTo = '/home-client.html';
                            break;
                        case 'annotator':
                            redirectTo = '/home-annotator.html';
                            break;
                    }
                    res.json({ redirectTo: redirectTo });
                }
            );
        });
    }
);

// =============================================================================
// USER ROUTES
// =============================================================================

/**
 * GET /current-user
 * Get current authenticated user's information
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Only returns user's own data, requires authentication
 */
router.get('/current-user', requireAuth, readLimiter, function(req, res) {
    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch user information'
            });
        }

        connection.query(
            'SELECT userID, username, email, access FROM users WHERE userID = ?',
            [req.session.userID],
            function(err, rows) {
                connection.release();
                if (err || rows.length === 0) {
                    return res.status(500).json({
                        error: 'Database Error',
                        message: 'Unable to fetch user information'
                    });
                }
                res.json(rows[0]);
            }
        );
    });
});

// =============================================================================
// FILE ROUTES
// =============================================================================

/**
 * POST /upload
 * Upload a new file
 *
 * Rate limited: 20 uploads per hour per user
 */
router.post('/upload',
    requireAuth,
    uploadLimiter,
    upload.single('file'),
    (req, res) => {
        if (!req.file) {
            return res.status(400).json({
                error: 'Upload Error',
                message: 'No file was uploaded'
            });
        }

        const uploadedFile = req.file;
        const userID = req.session.userID;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to save file information'
                });
            }

            connection.query(
                'INSERT INTO files (fileName, userID, status) VALUES (?, ?, ?)',
                [uploadedFile.filename, userID, 'Unvalidated'],
                function(err, result) {
                    connection.release();
                    if (err) {
                        console.error('Query error:', err.message);
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to save file information'
                        });
                    }
                    res.status(201).json({
                        success: true,
                        fileID: result.insertId,
                        fileName: uploadedFile.filename
                    });
                }
            );
        });
    }
);

/**
 * GET /userfiles
 * Get files belonging to the current user
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Only returns files owned by authenticated user (enforced via session.userID)
 */
router.get('/userfiles', requireAuth, readLimiter, function(req, res) {
    const userID = req.session.userID;

    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch files'
            });
        }

        connection.query(
            `SELECT f.*,
                (SELECT COUNT(*) FROM annotations WHERE fileID = f.fileID) as annotationCount
             FROM files f WHERE f.userID = ? ORDER BY f.fileID DESC`,
            [userID],
            function(err, rows) {
                connection.release();
                if (err) {
                    return res.status(500).json({
                        error: 'Database Error',
                        message: 'Unable to fetch files'
                    });
                }
                res.json(rows);
            }
        );
    });
});

/**
 * POST /userfiles
 * Legacy endpoint for backward compatibility
 *
 * SECURITY FIX: This endpoint previously accepted userID from request body,
 * allowing unauthorized access to any user's files (IDOR vulnerability).
 * Now requires authentication and only returns the authenticated user's files.
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires authentication, ignores userID from body (uses session only)
 *
 * OWASP Reference: API1:2023 - Broken Object Level Authorization
 */
router.post('/userfiles',
    requireAuth,
    readLimiter,
    validateContentType(),
    function(req, res) {
        // SECURITY: Always use session userID, never trust client-provided userID
        // This prevents IDOR attacks where attackers could view other users' files
        const userID = req.session.userID;

        // Log if someone attempts to pass a different userID (potential attack)
        if (req.body.userID && req.body.userID !== userID) {
            console.warn(
                `SECURITY: User ${userID} attempted to access files for user ${req.body.userID} - request denied`
            );
        }

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to fetch files'
                });
            }

            connection.query(
                'SELECT * FROM files WHERE userID = ? ORDER BY fileID DESC',
                [userID],
                function(err, rows) {
                    connection.release();
                    if (err) {
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to fetch files'
                        });
                    }
                    res.json(rows);
                }
            );
        });
    }
);

/**
 * GET /allFiles
 * Get all files (admin and client only)
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires admin or client role, enforced via requireRole middleware
 */
router.get('/allFiles', requireRole(['admin', 'client']), readLimiter, function(req, res) {
    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch files'
            });
        }

        connection.query(
            `SELECT u.username, u.email, f.*,
                (SELECT COUNT(*) FROM annotations WHERE fileID = f.fileID) as annotationCount,
                (SELECT COUNT(*) FROM attack_flows WHERE fileID = f.fileID) as flowCount
             FROM users u
             INNER JOIN files f ON u.userID = f.userID
             ORDER BY f.fileID DESC`,
            function(err, rows) {
                connection.release();
                if (err) {
                    return res.status(500).json({
                        error: 'Database Error',
                        message: 'Unable to fetch files'
                    });
                }
                res.json(rows);
            }
        );
    });
});

/**
 * POST /download
 * Get file path for download
 *
 * Rate limited: 50 downloads per hour (prevents bandwidth abuse)
 * Security: Requires authentication, validates fileID, checks file ownership
 *
 * Authorization: Users can only download their own files unless admin/client
 * OWASP Reference: API1:2023 - Broken Object Level Authorization
 */
router.post('/download',
    requireAuth,
    downloadLimiter,
    validateContentType(),
    validateBody(schemas.fileID),
    requireFileAccess,  // Verify user has access to this file
    function(req, res) {
        // File data already verified and attached by requireFileAccess
        const fileName = req.fileData.fileName;
        const filePath = path.join('resources', fileName);
        res.json({ filePath: filePath, fileName: fileName });
    }
);

/**
 * POST /delete
 * Delete a file (admin only)
 */
router.post('/delete',
    requireRole(['admin']),
    validateContentType(),
    validateBody(schemas.fileID),
    mutationLimiter,
    function(req, res) {
        const fileID = req.body.fileID;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to delete file'
                });
            }

            // First get the filename to delete the physical file
            connection.query(
                'SELECT fileName FROM files WHERE fileID = ?',
                [fileID],
                function(err, rows) {
                    if (err || rows.length === 0) {
                        connection.release();
                        return res.status(404).json({
                            error: 'Not Found',
                            message: 'File not found'
                        });
                    }

                    const fileName = rows[0].fileName;

                    // Delete from database (cascades to annotations and attack_flows)
                    connection.query(
                        'DELETE FROM files WHERE fileID = ?',
                        [fileID],
                        function(err) {
                            connection.release();
                            if (err) {
                                return res.status(500).json({
                                    error: 'Database Error',
                                    message: 'Unable to delete file'
                                });
                            }

                            // Attempt to delete the physical file
                            const filePath = path.join(__dirname, '..', 'public', 'resources', fileName);
                            fs.unlink(filePath, (err) => {
                                if (err) {
                                    console.error('Failed to delete physical file:', err.message);
                                }
                            });

                            res.json({ success: true });
                        }
                    );
                }
            );
        });
    }
);

// =============================================================================
// ANNOTATION ROUTES
// =============================================================================

/**
 * GET /annotations/:fileID?
 * Get annotations for a file
 * Supports both path param and query param
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires authentication, validates fileID, checks file ownership
 *
 * Authorization: Users can only view annotations for their own files unless admin/client
 * OWASP Reference: API1:2023 - Broken Object Level Authorization
 */
router.get('/annotations/:fileID?', requireAuth, readLimiter, function(req, res) {
    const fileID = req.params.fileID || req.query.fileID;

    if (!fileID) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'File ID is required'
        });
    }

    // Validate fileID is a number
    const parsedFileID = parseInt(fileID, 10);
    if (isNaN(parsedFileID) || parsedFileID <= 0) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'File ID must be a positive integer'
        });
    }

    // Get user's role to check authorization
    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch annotations'
            });
        }

        // First, get user's role
        connection.query(
            'SELECT access FROM users WHERE userID = ?',
            [req.session.userID],
            function(err, userRows) {
                if (err || userRows.length === 0) {
                    connection.release();
                    return res.status(500).json({
                        error: 'Authorization Error',
                        message: 'Unable to verify permissions'
                    });
                }

                const userRole = userRows[0].access;

                // Check file access based on role
                let fileQuery, fileParams;
                if (userRole === 'admin' || userRole === 'client') {
                    // Admins and clients can access any file
                    fileQuery = 'SELECT fileID FROM files WHERE fileID = ?';
                    fileParams = [parsedFileID];
                } else {
                    // Annotators can only access their own files
                    fileQuery = 'SELECT fileID FROM files WHERE fileID = ? AND userID = ?';
                    fileParams = [parsedFileID, req.session.userID];
                }

                connection.query(fileQuery, fileParams, function(err, fileRows) {
                    if (err) {
                        connection.release();
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to verify file access'
                        });
                    }

                    if (fileRows.length === 0) {
                        // Check if file exists at all for proper error message
                        connection.query(
                            'SELECT fileID FROM files WHERE fileID = ?',
                            [parsedFileID],
                            function(err, existsRows) {
                                if (existsRows && existsRows.length > 0) {
                                    connection.release();
                                    console.warn(
                                        `SECURITY: User ${req.session.userID} attempted to access annotations for file ${parsedFileID}`
                                    );
                                    return res.status(403).json({
                                        error: 'Forbidden',
                                        message: 'You do not have permission to access this file'
                                    });
                                }
                                connection.release();
                                return res.status(404).json({
                                    error: 'Not Found',
                                    message: 'File not found'
                                });
                            }
                        );
                        return;
                    }

                    // User has access, fetch annotations
                    connection.query(
                        `SELECT a.*, t.name as tagName, t.techniqueID, t.category, t.description as tagDescription,
                            u.username as createdByUsername
                         FROM annotations a
                         LEFT JOIN tags t ON a.tagID = t.tagID
                         LEFT JOIN users u ON a.createdBy = u.userID
                         WHERE a.fileID = ?
                         ORDER BY a.orderIndex, a.annotationID`,
                        [parsedFileID],
                        function(err, rows) {
                            connection.release();
                            if (err) {
                                return res.status(500).json({
                                    error: 'Database Error',
                                    message: 'Unable to fetch annotations'
                                });
                            }
                            res.json(rows);
                        }
                    );
                });
            }
        );
    });
});

/**
 * POST /annotations
 * Create a new annotation
 */
router.post('/annotations',
    requireAuth,
    validateContentType(),
    validateBody(schemas.createAnnotation),
    mutationLimiter,
    function(req, res) {
        const { fileID, tagID, selectedText, startOffset, endOffset, customTag, notes, orderIndex } = req.body;
        const userID = req.session.userID;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to create annotation'
                });
            }

            connection.query(
                `INSERT INTO annotations (fileID, tagID, selectedText, startOffset, endOffset, customTag, notes, orderIndex, createdBy, createdAt)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
                [fileID, tagID || null, selectedText || '', startOffset || 0, endOffset || 0, customTag || null, notes || '', orderIndex || 0, userID],
                function(err, result) {
                    connection.release();
                    if (err) {
                        console.error('Insert annotation error:', err.message);
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to create annotation'
                        });
                    }
                    res.status(201).json({
                        success: true,
                        annotationID: result.insertId
                    });
                }
            );
        });
    }
);

/**
 * PUT /annotations/:annotationID
 * Update an existing annotation
 */
router.put('/annotations/:annotationID',
    requireAuth,
    validateContentType(),
    validateBody(schemas.updateAnnotation),
    mutationLimiter,
    function(req, res) {
        const annotationID = parseInt(req.params.annotationID, 10);

        if (isNaN(annotationID) || annotationID <= 0) {
            return res.status(400).json({
                error: 'Validation Error',
                message: 'Annotation ID must be a positive integer'
            });
        }

        const { tagID, selectedText, customTag, notes, orderIndex } = req.body;
        const userID = req.session.userID;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to update annotation'
                });
            }

            connection.query(
                `UPDATE annotations SET tagID = ?, selectedText = ?, customTag = ?, notes = ?, orderIndex = ?, updatedBy = ?, updatedAt = NOW()
                 WHERE annotationID = ?`,
                [tagID || null, selectedText, customTag || null, notes || '', orderIndex || 0, userID, annotationID],
                function(err) {
                    connection.release();
                    if (err) {
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to update annotation'
                        });
                    }
                    res.json({ success: true });
                }
            );
        });
    }
);

/**
 * DELETE /annotations/:annotationID
 * Delete an annotation
 */
router.delete('/annotations/:annotationID',
    requireAuth,
    mutationLimiter,
    function(req, res) {
        const annotationID = parseInt(req.params.annotationID, 10);

        if (isNaN(annotationID) || annotationID <= 0) {
            return res.status(400).json({
                error: 'Validation Error',
                message: 'Annotation ID must be a positive integer'
            });
        }

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to delete annotation'
                });
            }

            connection.query(
                'DELETE FROM annotations WHERE annotationID = ?',
                [annotationID],
                function(err) {
                    connection.release();
                    if (err) {
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to delete annotation'
                        });
                    }
                    res.json({ success: true });
                }
            );
        });
    }
);

// =============================================================================
// ATTACK FLOW ROUTES
// =============================================================================

/**
 * POST /generate-attack-flow
 * Generate an Attack Flow JSON from annotations
 */
router.post('/generate-attack-flow',
    requireAuth,
    validateContentType(),
    validateBody(schemas.generateAttackFlow),
    mutationLimiter,
    function(req, res) {
        const { fileID, flowName, flowDescription } = req.body;
        const userID = req.session.userID;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to generate attack flow'
                });
            }

            // Get file info and annotations
            connection.query(
                `SELECT f.fileName, f.userID, u.username
                 FROM files f
                 JOIN users u ON f.userID = u.userID
                 WHERE f.fileID = ?`,
                [fileID],
                function(err, fileRows) {
                    if (err || fileRows.length === 0) {
                        connection.release();
                        return res.status(404).json({
                            error: 'Not Found',
                            message: 'File not found'
                        });
                    }

                    const fileInfo = fileRows[0];

                    // Get annotations with tags
                    connection.query(
                        `SELECT a.*, t.name as tagName, t.techniqueID, t.category, t.description as tagDescription
                         FROM annotations a
                         LEFT JOIN tags t ON a.tagID = t.tagID
                         WHERE a.fileID = ?
                         ORDER BY a.orderIndex, a.annotationID`,
                        [fileID],
                        function(err, annotations) {
                            if (err) {
                                connection.release();
                                return res.status(500).json({
                                    error: 'Database Error',
                                    message: 'Unable to fetch annotations'
                                });
                            }

                            // Generate Attack Flow JSON based on MITRE schema
                            const flowID = uuidv4();
                            const attackFlow = generateAttackFlowJSON(
                                flowID,
                                flowName || fileInfo.fileName,
                                flowDescription || '',
                                fileInfo,
                                annotations
                            );

                            // Save the attack flow to database
                            connection.query(
                                `INSERT INTO attack_flows (fileID, flowName, flowJSON, status, createdBy, createdAt)
                                 VALUES (?, ?, ?, 'Pending', ?, NOW())`,
                                [fileID, flowName || fileInfo.fileName, JSON.stringify(attackFlow), userID],
                                function(err, result) {
                                    connection.release();
                                    if (err) {
                                        console.error('Save attack flow error:', err.message);
                                        return res.status(500).json({
                                            error: 'Database Error',
                                            message: 'Unable to save attack flow'
                                        });
                                    }

                                    res.status(201).json({
                                        success: true,
                                        flowID: result.insertId,
                                        attackFlow: attackFlow
                                    });
                                }
                            );
                        }
                    );
                }
            );
        });
    }
);

/**
 * GET /attack-flows/:fileID
 * Get attack flows for a specific file
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires authentication, validates fileID parameter
 */
router.get('/attack-flows/:fileID', requireAuth, readLimiter, function(req, res) {
    const fileID = parseInt(req.params.fileID, 10);

    if (isNaN(fileID) || fileID <= 0) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'File ID must be a positive integer'
        });
    }

    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch attack flows'
            });
        }

        connection.query(
            `SELECT af.*, u.username as createdByUsername
             FROM attack_flows af
             LEFT JOIN users u ON af.createdBy = u.userID
             WHERE af.fileID = ?
             ORDER BY af.createdAt DESC`,
            [fileID],
            function(err, rows) {
                connection.release();
                if (err) {
                    return res.status(500).json({
                        error: 'Database Error',
                        message: 'Unable to fetch attack flows'
                    });
                }
                res.json(rows);
            }
        );
    });
});

/**
 * GET /all-attack-flows
 * Get all attack flows (admin and client only)
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires admin or client role
 */
router.get('/all-attack-flows', requireRole(['admin', 'client']), readLimiter, function(req, res) {
    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch attack flows'
            });
        }

        connection.query(
            `SELECT af.*, f.fileName, u.username as createdByUsername
             FROM attack_flows af
             JOIN files f ON af.fileID = f.fileID
             LEFT JOIN users u ON af.createdBy = u.userID
             ORDER BY af.createdAt DESC`,
            function(err, rows) {
                connection.release();
                if (err) {
                    return res.status(500).json({
                        error: 'Database Error',
                        message: 'Unable to fetch attack flows'
                    });
                }
                res.json(rows);
            }
        );
    });
});

/**
 * GET /attack-flow/:flowID
 * Get a single attack flow by ID
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires authentication, validates flowID parameter
 */
router.get('/attack-flow/:flowID', requireAuth, readLimiter, function(req, res) {
    const flowID = parseInt(req.params.flowID, 10);

    if (isNaN(flowID) || flowID <= 0) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Flow ID must be a positive integer'
        });
    }

    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch attack flow'
            });
        }

        connection.query(
            `SELECT af.*, f.fileName, u.username as createdByUsername
             FROM attack_flows af
             JOIN files f ON af.fileID = f.fileID
             LEFT JOIN users u ON af.createdBy = u.userID
             WHERE af.flowID = ?`,
            [flowID],
            function(err, rows) {
                connection.release();
                if (err || rows.length === 0) {
                    return res.status(404).json({
                        error: 'Not Found',
                        message: 'Attack flow not found'
                    });
                }

                const flow = rows[0];
                try {
                    flow.flowJSON = JSON.parse(flow.flowJSON);
                } catch (e) {
                    console.error('Error parsing flowJSON:', e.message);
                }
                res.json(flow);
            }
        );
    });
});

/**
 * POST /approve-flow/:flowID
 * Approve an attack flow (client and admin only)
 *
 * Rate limited: 30 mutations per minute
 * Security: Requires admin or client role, validates flowID parameter
 */
router.post('/approve-flow/:flowID',
    requireRole(['admin', 'client']),
    validateContentType(),
    validateParams(schemas.params.flowID),
    validateBody(schemas.approveFlow),
    mutationLimiter,
    function(req, res) {
        const flowID = req.params.flowID; // Already validated by validateParams
        const { feedback } = req.body;
        const userID = req.session.userID;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to approve flow'
                });
            }

            connection.query(
                `UPDATE attack_flows SET status = 'Approved', validatedBy = ?, validatedAt = NOW(), feedback = ?
                 WHERE flowID = ?`,
                [userID, feedback || '', flowID],
                function(err) {
                    if (err) {
                        connection.release();
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to approve flow'
                        });
                    }

                    // Also update the file status
                    connection.query(
                        `UPDATE files f
                         JOIN attack_flows af ON f.fileID = af.fileID
                         SET f.status = 'Approved'
                         WHERE af.flowID = ?`,
                        [flowID],
                        function(err) {
                            connection.release();
                            if (err) {
                                console.error('Failed to update file status:', err.message);
                            }
                            res.json({ success: true });
                        }
                    );
                }
            );
        });
    }
);

/**
 * POST /reject-flow/:flowID
 * Reject an attack flow (client and admin only)
 *
 * Rate limited: 30 mutations per minute
 * Security: Requires admin or client role, validates flowID and feedback
 * Note: Feedback is required and must be at least 10 characters
 */
router.post('/reject-flow/:flowID',
    requireRole(['admin', 'client']),
    validateContentType(),
    validateParams(schemas.params.flowID),
    validateBody(schemas.rejectFlow),
    mutationLimiter,
    function(req, res) {
        const flowID = req.params.flowID; // Already validated by validateParams
        const { feedback } = req.body;    // Already validated by validateBody (min 10 chars)
        const userID = req.session.userID;

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to reject flow'
                });
            }

            connection.query(
                `UPDATE attack_flows SET status = 'Rejected', validatedBy = ?, validatedAt = NOW(), feedback = ?
                 WHERE flowID = ?`,
                [userID, feedback, flowID],
                function(err, result) {
                    connection.release();
                    if (err) {
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to reject flow'
                        });
                    }

                    // Check if the flow existed
                    if (result.affectedRows === 0) {
                        return res.status(404).json({
                            error: 'Not Found',
                            message: 'Attack flow not found'
                        });
                    }

                    res.json({ success: true });
                }
            );
        });
    }
);

/**
 * GET /download-flow/:flowID
 * Download an attack flow as JSON
 *
 * Rate limited: 50 downloads per hour (prevents bandwidth abuse)
 * Security: Requires authentication, validates flowID parameter
 */
router.get('/download-flow/:flowID', requireAuth, downloadLimiter, function(req, res) {
    const flowID = parseInt(req.params.flowID, 10);

    if (isNaN(flowID) || flowID <= 0) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'Flow ID must be a positive integer'
        });
    }

    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to download flow'
            });
        }

        connection.query(
            'SELECT flowName, flowJSON FROM attack_flows WHERE flowID = ?',
            [flowID],
            function(err, rows) {
                connection.release();
                if (err || rows.length === 0) {
                    return res.status(404).json({
                        error: 'Not Found',
                        message: 'Attack flow not found'
                    });
                }

                const flow = rows[0];
                const fileName = `${flow.flowName.replace(/[^a-zA-Z0-9]/g, '_')}_attack_flow.json`;

                res.setHeader('Content-Type', 'application/json');
                res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
                res.send(flow.flowJSON);
            }
        );
    });
});

// =============================================================================
// DOCUMENT ROUTES
// =============================================================================

/**
 * GET /annotate/:fileID
 * Serve the annotation editor page
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires authentication
 */
router.get('/annotate/:fileID', requireAuth, readLimiter, function(req, res) {
    res.sendFile(path.resolve(__dirname + '/../public/annotate.html'));
});

/**
 * GET /file-info/:fileID
 * Get file information for annotation
 *
 * Rate limited: 60 requests per minute (read endpoint)
 * Security: Requires authentication, validates fileID, checks file ownership
 *
 * Authorization: Users can only view info for their own files unless admin/client
 * OWASP Reference: API1:2023 - Broken Object Level Authorization
 */
router.get('/file-info/:fileID', requireAuth, readLimiter, function(req, res) {
    const fileID = parseInt(req.params.fileID, 10);

    if (isNaN(fileID) || fileID <= 0) {
        return res.status(400).json({
            error: 'Validation Error',
            message: 'File ID must be a positive integer'
        });
    }

    req.pool.getConnection(function(err, connection) {
        if (err) {
            return res.status(500).json({
                error: 'Database Error',
                message: 'Unable to fetch file information'
            });
        }

        // First, get user's role
        connection.query(
            'SELECT access FROM users WHERE userID = ?',
            [req.session.userID],
            function(err, userRows) {
                if (err || userRows.length === 0) {
                    connection.release();
                    return res.status(500).json({
                        error: 'Authorization Error',
                        message: 'Unable to verify permissions'
                    });
                }

                const userRole = userRows[0].access;

                // Build query based on role
                let query, params;
                if (userRole === 'admin' || userRole === 'client') {
                    // Admins and clients can access any file
                    query = `SELECT f.*, u.username
                             FROM files f
                             JOIN users u ON f.userID = u.userID
                             WHERE f.fileID = ?`;
                    params = [fileID];
                } else {
                    // Annotators can only access their own files
                    query = `SELECT f.*, u.username
                             FROM files f
                             JOIN users u ON f.userID = u.userID
                             WHERE f.fileID = ? AND f.userID = ?`;
                    params = [fileID, req.session.userID];
                }

                connection.query(query, params, function(err, rows) {
                    if (err) {
                        connection.release();
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to fetch file information'
                        });
                    }

                    if (rows.length === 0) {
                        // Check if file exists for proper error
                        connection.query(
                            'SELECT fileID FROM files WHERE fileID = ?',
                            [fileID],
                            function(err, existsRows) {
                                connection.release();
                                if (existsRows && existsRows.length > 0) {
                                    console.warn(
                                        `SECURITY: User ${req.session.userID} attempted to access file info for file ${fileID}`
                                    );
                                    return res.status(403).json({
                                        error: 'Forbidden',
                                        message: 'You do not have permission to access this file'
                                    });
                                }
                                return res.status(404).json({
                                    error: 'Not Found',
                                    message: 'File not found'
                                });
                            }
                        );
                        return;
                    }

                    connection.release();
                    res.json(rows[0]);
                });
            }
        );
    });
});

/**
 * POST /submit-for-validation/:fileID
 * Submit a file for validation
 *
 * Rate limited: 30 mutations per minute (mutation endpoint)
 * Security: Requires authentication, validates fileID parameter
 */
router.post('/submit-for-validation/:fileID',
    requireAuth,
    mutationLimiter,
    validateContentType(),
    function(req, res) {
        const fileID = parseInt(req.params.fileID, 10);

        if (isNaN(fileID) || fileID <= 0) {
            return res.status(400).json({
                error: 'Validation Error',
                message: 'File ID must be a positive integer'
            });
        }

        req.pool.getConnection(function(err, connection) {
            if (err) {
                return res.status(500).json({
                    error: 'Database Error',
                    message: 'Unable to submit for validation'
                });
            }

            connection.query(
                `UPDATE files SET status = 'Pending' WHERE fileID = ?`,
                [fileID],
                function(err) {
                    connection.release();
                    if (err) {
                        return res.status(500).json({
                            error: 'Database Error',
                            message: 'Unable to submit for validation'
                        });
                    }
                    res.json({ success: true });
                }
            );
        });
    }
);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Generate Attack Flow JSON based on MITRE Attack Flow schema (STIX 2.1)
 *
 * @param {string} flowID - Unique identifier for the flow
 * @param {string} name - Name of the attack flow
 * @param {string} description - Description of the attack flow
 * @param {Object} fileInfo - Information about the source file
 * @param {Array} annotations - Array of annotations to convert to attack actions
 * @returns {Object} STIX 2.1 compliant Attack Flow bundle
 */
function generateAttackFlowJSON(flowID, name, description, fileInfo, annotations) {
    const now = new Date().toISOString();

    // Create the base Attack Flow bundle structure
    const attackFlow = {
        type: "bundle",
        id: `bundle--${flowID}`,
        spec_version: "2.1",
        created: now,
        modified: now,
        objects: []
    };

    // Add the attack-flow object
    const identityId = `identity--${uuidv4()}`;
    const flowObject = {
        type: "attack-flow",
        id: `attack-flow--${flowID}`,
        spec_version: "2.1",
        created: now,
        modified: now,
        name: name,
        description: description || `Attack flow generated from ${fileInfo.fileName}`,
        scope: "incident",
        start_refs: [],
        created_by_ref: identityId
    };
    attackFlow.objects.push(flowObject);

    // Add identity for the creator
    const identity = {
        type: "identity",
        id: identityId,
        spec_version: "2.1",
        created: now,
        modified: now,
        name: fileInfo.username,
        identity_class: "individual"
    };
    attackFlow.objects.push(identity);

    // Convert annotations to attack-action objects
    let previousActionId = null;
    annotations.forEach((annotation, index) => {
        const actionId = `attack-action--${uuidv4()}`;

        const action = {
            type: "attack-action",
            id: actionId,
            spec_version: "2.1",
            created: now,
            modified: now,
            name: annotation.tagName || annotation.customTag || `Action ${index + 1}`,
            description: annotation.selectedText || annotation.notes || '',
            technique_id: annotation.techniqueID || null,
            technique_ref: annotation.techniqueID ? `attack-pattern--${annotation.techniqueID}` : null
        };

        // Add tactic/category information if available
        if (annotation.category) {
            action.tactic_id = annotation.category;
        }

        attackFlow.objects.push(action);

        // Set as start ref if first action
        if (index === 0) {
            flowObject.start_refs.push(actionId);
        }

        // Create relationship to previous action (sequential flow)
        if (previousActionId) {
            const relationship = {
                type: "relationship",
                id: `relationship--${uuidv4()}`,
                spec_version: "2.1",
                created: now,
                modified: now,
                relationship_type: "effect-of",
                source_ref: actionId,
                target_ref: previousActionId
            };
            attackFlow.objects.push(relationship);
        }

        previousActionId = actionId;
    });

    return attackFlow;
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = router;
