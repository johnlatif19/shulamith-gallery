require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session'); // 👈 جديد
const admin = require('firebase-admin');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const csrf = require('csrf'); // 👈 جديد

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', true);

// ============================================
// ===== TIMEOUT =====
// ============================================
const timeoutMiddleware = (req, res, next) => {
    req.setTimeout(30000, () => {
        res.status(504).json({ error: 'Request timeout' });
    });
    next();
};

// ============================================
// ===== HELMET =====
// ============================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com", "https://i.postimg.cc"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", "https://firestore.googleapis.com", "https://api.cloudinary.com"],
            baseUri: ["'self'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true
}));

// ============================================
// ===== SESSION (للـ CSRF) =====
// ============================================
app.use(session({
    secret: process.env.SESSION_SECRET || 'default-session-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 ساعة
    },
    name: 'shulamith.sid'
}));

// ============================================
// ===== CSRF TOKENS =====
// ============================================
const csrfTokens = new csrf();

// Middleware لتوليد CSRF Token
const generateCsrfToken = (req, res, next) => {
    if (!req.session.csrfSecret) {
        req.session.csrfSecret = csrfTokens.secretSync();
    }
    req.csrfToken = csrfTokens.create(req.session.csrfSecret);
    next();
};

// Middleware للتحقق من CSRF Token
const verifyCsrf = (req, res, next) => {
    //跳过 GET, HEAD, OPTIONS
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    const token = req.headers['x-csrf-token'] || req.body._csrf || req.query._csrf;
    
    if (!token) {
        return res.status(403).json({ 
            error: 'CSRF token missing. Please refresh the page.' 
        });
    }

    if (!req.session.csrfSecret) {
        return res.status(403).json({ 
            error: 'CSRF session expired. Please refresh the page.' 
        });
    }

    try {
        const isValid = csrfTokens.verify(req.session.csrfSecret, token);
        if (!isValid) {
            return res.status(403).json({ 
                error: 'Invalid CSRF token. Please refresh the page.' 
            });
        }
        next();
    } catch (error) {
        console.error('CSRF verification error:', error);
        return res.status(403).json({ 
            error: 'CSRF verification failed.' 
        });
    }
};

// API لتوليد CSRF Token للـ Frontend
app.get('/api/csrf-token', generateCsrfToken, (req, res) => {
    res.json({ 
        token: req.csrfToken,
        expiresIn: 300 // ساعة
    });
});

// ============================================
// ===== CORS =====
// ============================================
const allowedOrigins = [
    'https://shulamith-gallery.vercel.app',
    'https://shulamith-gallery.com',
    'http://localhost:3000',
    'http://localhost:5500'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            console.warn('CORS blocked: ' + origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

app.use(timeoutMiddleware);

// ============================================
// ===== RATE LIMITING =====
// ============================================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    }
});

const contactLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: 'Too many messages sent. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    }
});

// ===== RATE LIMITER للتقييمات (جديد) =====
const rateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // ساعة واحدة
    max: 5, // 5 تقييمات بس في الساعة
    message: { 
        error: 'تم إرسال عدد كبير من التقييمات. الرجاء الانتظار ساعة قبل المحاولة مرة أخرى.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    },
    skipSuccessfulRequests: false // يحسب حتى الطلبات الناجحة
});

// تطبيق الـ Rate Limiters
app.use('/api/login', authLimiter);
app.use('/api/contact', contactLimiter);
app.use('/api/upload', limiter);
app.use('/api/stats', limiter);
app.use('/api/send-email', limiter);

// ============================================
// ===== FIREBASE =====
// ============================================
const revokedTokens = new Set();

let firebaseConfig;
try {
    firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
} catch (e) {
    console.error('Error parsing FIREBASE_CONFIG:', e.message);
    process.exit(1);
}

if (!admin.apps.length) {
    try {
        admin.initializeApp({
            credential: admin.credential.cert(firebaseConfig)
        });
        console.log('Firebase initialized successfully');
    } catch (error) {
        console.error('Firebase initialization failed:', error.message);
        process.exit(1);
    }
} else {
    console.log('Firebase app already exists, reusing...');
}

const db = admin.firestore();

// ============================================
// ===== CLOUDINARY =====
// ============================================
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// ============================================
// ===== EMAIL =====
// ============================================
let transporter = null;
let emailConfigured = false;
let initializationPromise = null;

const initializeTransporter = async () => {
    if (initializationPromise) {
        console.log('SMTP initialization already in progress, waiting...');
        return initializationPromise;
    }

    initializationPromise = (async () => {
        try {
            if (!nodemailer || typeof nodemailer.createTransport !== 'function') {
                console.warn('Nodemailer not available or invalid');
                return false;
            }

            const requiredEnv = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM_EMAIL'];
            const missing = requiredEnv.filter(key => !process.env[key]);
            if (missing.length > 0) {
                console.warn('Missing SMTP env variables: ' + missing.join(', '));
                return false;
            }

            console.log('Connecting to SMTP: ' + process.env.SMTP_HOST + ':' + process.env.SMTP_PORT);

            const newTransporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: parseInt(process.env.SMTP_PORT),
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASSWORD
                },
                connectionTimeout: 30000,
                greetingTimeout: 30000,
                socketTimeout: 30000,
                tls: {
                    rejectUnauthorized: true
                }
            });

            await Promise.race([
                newTransporter.verify(),
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('SMTP verification timeout')), 20000)
                )
            ]);

            transporter = newTransporter;
            emailConfigured = true;
            console.log('SMTP configured and verified successfully');
            return true;
            
        } catch (error) {
            console.error('SMTP initialization FAILED:', error.message);
            
            if (error.message.includes('535-5.7.8')) {
                console.error('GMAIL AUTH ERROR: Use App Password, not regular password');
                console.error('Get one at: https://myaccount.google.com/apppasswords');
            } else if (error.message.includes('timeout')) {
                console.error('TIMEOUT: Vercel might be blocking the connection');
                console.error('Try changing SMTP_PORT to 587 and SMTP_SECURE to false');
            }
            
            transporter = null;
            emailConfigured = false;
            return false;
        } finally {
            initializationPromise = null;
        }
    })();

    return initializationPromise;
};

initializeTransporter().catch(console.error);

async function getTransporter() {
    if (transporter && emailConfigured) {
        return transporter;
    }
    
    if (!initializationPromise) {
        await initializeTransporter();
    } else {
        await initializationPromise;
    }
    
    return transporter;
}

function isEmailConfigured() {
    return transporter !== null && emailConfigured === true;
}

// ============================================
// ===== JWT =====
// ============================================
const generateToken = (username) => {
    return jwt.sign(
        { 
            username, 
            role: 'admin',
            iat: Math.floor(Date.now() / 1000),
            jti: crypto.randomBytes(16).toString('hex')
        },
        process.env.JWT_SECRET,
        { 
            expiresIn: '1h',
            algorithm: 'HS256'
        }
    );
};

const verifyToken = (token) => {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (revokedTokens.has(decoded.jti)) {
            return null;
        }
        return decoded;
    } catch (error) {
        return null;
    }
};

const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.user = decoded;
    next();
};

// ============================================
// ===== VALIDATION =====
// ============================================
const validateEmail = (email) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

const validatePhone = (phone) => {
    return /^[\d+\s-()]{8,20}$/.test(phone);
};

function sanitizeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
        .replace(/\n/g, '<br>');
}

function validateFirestoreId(id) {
    return id && typeof id === 'string' && /^[a-zA-Z0-9_-]+$/.test(id);
}

function sanitizeInput(text) {
    if (!text) return '';
    return text
        .replace(/<script/g, '&lt;script')
        .replace(/<\/script>/g, '&lt;/script&gt;')
        .replace(/onerror=/g, 'onerror=')
        .replace(/onload=/g, 'onload=')
        .replace(/javascript:/g, 'javascript:')
        .trim();
}

// ===== إخفاء الإيميل (جديد) =====
function maskEmail(email) {
    if (!email) return '';
    const [local, domain] = email.split('@');
    if (!domain) return email;
    
    // لو الإيميل قصير جداً
    if (local.length <= 3) {
        return '***@' + domain;
    }
    
    // خفي أول 3 حروف بس
    return local.slice(0, 3) + '***@' + domain;
}

// ============================================
// ===== API ROUTES =====
// ============================================

// ===== CSRF TOKEN =====
app.get('/api/csrf-token', generateCsrfToken, (req, res) => {
    res.json({ 
        token: req.csrfToken,
        expiresIn: 3600
    });
});

// ===== LOGIN =====
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const adminUsername = process.env.ADMIN_USERNAME;
        const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

        if (username !== adminUsername) {
            await new Promise(resolve => setTimeout(resolve, 100));
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValid = await bcrypt.compare(password, adminPasswordHash);
        if (!isValid) {
            await new Promise(resolve => setTimeout(resolve, 100));
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = generateToken(username);
        res.json({
            token,
            user: { username },
            expiresIn: 3600
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ===== LOGOUT =====
app.post('/api/logout', requireAuth, (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        const decoded = jwt.decode(token);
        if (decoded && decoded.jti) {
            revokedTokens.add(decoded.jti);
        }
    } catch (e) {}
    res.json({ success: true });
});

// ===== VERIFY =====
app.post('/api/verify', requireAuth, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ===== GALLERIES =====
app.get('/api/galleries', async (req, res) => {
    try {
        const snapshot = await db.collection('galleries').limit(100).get();

        const galleries = [];
        snapshot.forEach(doc => {
            galleries.push({ id: doc.id, ...doc.data() });
        });

        galleries.sort((a, b) => (a.order || 0) - (b.order || 0));

        res.json(galleries);
    } catch (error) {
        console.error('Error fetching galleries:', error);
        res.status(500).json({ error: 'Failed to fetch galleries' });
    }
});

app.post('/api/galleries', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { name, description, coverImage, visible, order } = req.body;

        if (!name || typeof name !== 'string' || name.trim().length === 0) {
            return res.status(400).json({ error: 'Gallery name is required' });
        }

        const galleryData = {
            name: sanitizeInput(name.trim()),
            description: sanitizeInput(description || ''),
            coverImage: coverImage || '',
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('galleries').add(galleryData);
        res.status(201).json({ id: docRef.id, ...galleryData });
    } catch (error) {
        console.error('Error creating gallery:', error);
        res.status(500).json({ error: 'Failed to create gallery' });
    }
});

app.put('/api/galleries/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, coverImage, visible, order } = req.body;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid gallery ID' });
        }

        if (!name || typeof name !== 'string' || name.trim().length === 0) {
            return res.status(400).json({ error: 'Gallery name is required' });
        }

        const docRef = db.collection('galleries').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Gallery not found' });
        }

        const updateData = {
            name: sanitizeInput(name.trim()),
            description: sanitizeInput(description || ''),
            coverImage: coverImage || '',
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await docRef.update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating gallery:', error);
        res.status(500).json({ error: 'Failed to update gallery' });
    }
});

app.delete('/api/galleries/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid gallery ID' });
        }

        const docRef = db.collection('galleries').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Gallery not found' });
        }

        const artworksSnapshot = await db.collection('artworks')
            .where('galleryId', '==', id)
            .limit(1)
            .get();

        if (!artworksSnapshot.empty) {
            return res.status(400).json({
                error: 'Cannot delete gallery with existing artworks. Please delete or move artworks first.'
            });
        }

        await docRef.delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting gallery:', error);
        res.status(500).json({ error: 'Failed to delete gallery' });
    }
});

// ===== ARTWORKS =====
app.get('/api/artworks', async (req, res) => {
    try {
        const { galleryId, featured } = req.query;
        
        if (galleryId && !validateFirestoreId(galleryId)) {
            return res.status(400).json({ error: 'Invalid galleryId' });
        }
        
        if (featured && featured !== 'true' && featured !== 'false') {
            return res.status(400).json({ error: 'Invalid featured value' });
        }

        let query = db.collection('artworks').limit(100);

        if (galleryId) {
            query = query.where('galleryId', '==', galleryId);
        }

        if (featured === 'true') {
            query = query.where('featured', '==', true);
        }

        const snapshot = await query.get();
        const artworks = [];
        snapshot.forEach(doc => {
            artworks.push({ id: doc.id, ...doc.data() });
        });

        artworks.sort((a, b) => (a.order || 0) - (b.order || 0));

        res.json(artworks);
    } catch (error) {
        console.error('Error fetching artworks:', error);
        res.status(500).json({ error: 'Failed to fetch artworks' });
    }
});

app.post('/api/artworks', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const {
            galleryId, title, description, imageUrl, cloudinaryPublicId,
            material, dimensions, price, featured, visible, order
        } = req.body;

        if (!galleryId || !validateFirestoreId(galleryId)) {
            return res.status(400).json({ error: 'Valid Gallery ID is required' });
        }

        if (!title || typeof title !== 'string' || title.trim().length === 0) {
            return res.status(400).json({ error: 'Artwork title is required' });
        }

        if (!imageUrl || typeof imageUrl !== 'string') {
            return res.status(400).json({ error: 'Image URL is required' });
        }

        const artworkData = {
            galleryId,
            title: sanitizeInput(title.trim()),
            description: sanitizeInput(description || ''),
            imageUrl,
            cloudinaryPublicId: cloudinaryPublicId || '',
            material: sanitizeInput(material || ''),
            dimensions: sanitizeInput(dimensions || ''),
            price: price || 0,
            featured: featured || false,
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('artworks').add(artworkData);
        res.status(201).json({ id: docRef.id, ...artworkData });
    } catch (error) {
        console.error('Error creating artwork:', error);
        res.status(500).json({ error: 'Failed to create artwork' });
    }
});

app.put('/api/artworks/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            galleryId, title, description, imageUrl, cloudinaryPublicId,
            material, dimensions, price, featured, visible, order
        } = req.body;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid artwork ID' });
        }

        if (!galleryId || !validateFirestoreId(galleryId)) {
            return res.status(400).json({ error: 'Valid Gallery ID is required' });
        }

        if (!title || typeof title !== 'string' || title.trim().length === 0) {
            return res.status(400).json({ error: 'Artwork title is required' });
        }

        if (!imageUrl || typeof imageUrl !== 'string') {
            return res.status(400).json({ error: 'Image URL is required' });
        }

        const docRef = db.collection('artworks').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Artwork not found' });
        }

        const updateData = {
            galleryId,
            title: sanitizeInput(title.trim()),
            description: sanitizeInput(description || ''),
            imageUrl,
            cloudinaryPublicId: cloudinaryPublicId || '',
            material: sanitizeInput(material || ''),
            dimensions: sanitizeInput(dimensions || ''),
            price: price || 0,
            featured: featured || false,
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await docRef.update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating artwork:', error);
        res.status(500).json({ error: 'Failed to update artwork' });
    }
});

app.delete('/api/artworks/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid artwork ID' });
        }

        const docRef = db.collection('artworks').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Artwork not found' });
        }

        const data = doc.data();
        if (data.cloudinaryPublicId) {
            try {
                await cloudinary.uploader.destroy(data.cloudinaryPublicId);
            } catch (error) {
                console.error('Error deleting from Cloudinary:', error);
            }
        }

        await docRef.delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting artwork:', error);
        res.status(500).json({ error: 'Failed to delete artwork' });
    }
});

// ===== UPLOAD =====
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images are allowed.'));
        }
    }
});

app.post('/api/upload', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }

        const b64 = Buffer.from(req.file.buffer).toString('base64');
        const dataURI = 'data:' + req.file.mimetype + ';base64,' + b64;

        const result = await Promise.race([
            cloudinary.uploader.upload(dataURI, {
                folder: 'shulamith-gallery/orders',
                resource_type: 'auto'
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Upload timeout')), 30000))
        ]);

        res.json({
            url: result.secure_url,
            publicId: result.public_id,
            width: result.width,
            height: result.height,
            format: result.format,
            bytes: result.bytes
        });
    } catch (error) {
        console.error('Upload error:', error);
        if (error.message === 'Upload timeout') {
            res.status(504).json({ error: 'Upload timeout, please try again' });
        } else {
            res.status(500).json({ error: 'Failed to upload image' });
        }
    }
});

// ===== CONTACT =====
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, message } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({ error: 'الاسم والبريد الإلكتروني والرسالة مطلوبة' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });
        }

        if (phone && !validatePhone(phone)) {
            return res.status(400).json({ error: 'رقم هاتف غير صالح' });
        }

        const messageData = {
            name: sanitizeInput(name.trim()),
            email: email.trim(),
            phone: phone ? sanitizeInput(phone.trim()) : '',
            message: sanitizeInput(message.trim()),
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('messages').add(messageData);

        if (email && transporter && emailConfigured) {
            setImmediate(async () => {
                try {
                    await transporter.sendMail({
                        from: '"' + (process.env.SMTP_FROM_NAME || 'Shulamith Gallery') + '" <' + process.env.SMTP_FROM_EMAIL + '>',
                        to: email,
                        subject: 'شكراً لتواصلك مع Shulamith Gallery',
                        html: `
                            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #1a1a1a; color: #e8e0d4; border-radius: 12px;">
                                <div style="text-align: center; margin-bottom: 30px;">
                                    <img src="https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg" alt="Shulamith Gallery" style="max-width: 150px; height: auto; border-radius: 8px;">
                                </div>
                                <h2 style="color: #d4b892; margin-bottom: 20px;">مرحباً ${sanitizeHtml(name)}،</h2>
                                <p style="line-height: 1.8; color: #d4c8b8;">تم استلام رسالتك وسيتم الرد في أقرب وقت.</p>
                                <p style="line-height: 1.8; color: #d4c8b8;">شكراً لتواصلك مع <strong style="color: #d4b892;">Shulamith Gallery</strong>.</p>
                                <div style="margin: 30px 0; padding: 20px; background: #252525; border-radius: 8px; border-right: 3px solid #d4b892;">
                                    <p style="margin: 5px 0; color: #d4c8b8;"><strong style="color: #d4b892;">رسالتك:</strong></p>
                                    <p style="margin: 10px 0 0 0; color: #e8e0d4; font-style: italic;">${sanitizeHtml(message)}</p>
                                </div>
                                <hr style="border: none; border-top: 1px solid #333; margin: 30px 0;">
                                <p style="color: #999; font-size: 14px; text-align: center;">
                                    © 2026 Shulamith Gallery. جميع الحقوق محفوظة
                                </p>
                            </div>
                        `
                    });
                    console.log('Confirmation email sent to:', email);
                } catch (error) {
                    console.error('Error sending confirmation email:', error.message);
                }
            });
        } else {
            console.log('Email service not configured, skipping confirmation email');
        }

        res.status(201).json({
            success: true,
            message: 'Message sent successfully',
            id: docRef.id
        });
    } catch (error) {
        console.error('Contact error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// ===== MESSAGES =====
app.get('/api/messages', requireAuth, async (req, res) => {
    try {
        const { unread } = req.query;
        let query = db.collection('messages').limit(100);

        if (unread === 'true') {
            query = query.where('read', '==', false);
        }

        const snapshot = await query.get();
        const messages = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            messages.push({
                id: doc.id,
                ...data,
                createdAt: data.createdAt?.toDate?.()?.toISOString() || null
            });
        });

        messages.sort((a, b) => {
            if (!a.createdAt) return 1;
            if (!b.createdAt) return -1;
            return new Date(b.createdAt) - new Date(a.createdAt);
        });

        res.json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

app.put('/api/messages/:id/read', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;
        const { read } = req.body;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid message ID' });
        }

        const docRef = db.collection('messages').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Message not found' });
        }

        await docRef.update({
            read: read !== undefined ? read : true,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating message:', error);
        res.status(500).json({ error: 'Failed to update message' });
    }
});

app.delete('/api/messages/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid message ID' });
        }

        const docRef = db.collection('messages').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Message not found' });
        }

        await docRef.delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// ============================================
// ===== RATES (مع التعديلات) =====
// ============================================

// POST - مع Rate Limiting و CSRF
app.post('/api/rates', rateLimiter, verifyCsrf, async (req, res) => {
    try {
        const { name, email, rating, opinion } = req.body;

        if (!name || !email || !rating || !opinion) {
            return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });
        }

        if (rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'التقييم يجب أن يكون بين 1 و 5' });
        }

        const rateData = {
            name: sanitizeInput(name.trim()),
            email: email.trim(),
            rating: parseInt(rating),
            opinion: sanitizeInput(opinion.trim()),
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('rates').add(rateData);
        
        // Log security event
        console.log(`✅ New rating submitted: ${name} (${email}) - Rating: ${rating}`);
        
        res.status(201).json({ 
            id: docRef.id, 
            ...rateData,
            email: maskEmail(email) // إخفاء الإيميل في الرد
        });
    } catch (error) {
        console.error('Error creating rate:', error);
        res.status(500).json({ error: 'Failed to submit rate' });
    }
});

// GET - مع إخفاء الإيميلات
app.get('/api/rates', async (req, res) => {
    try {
        const { rating } = req.query;
        let query = db.collection('rates').limit(100);

        if (rating) {
            const parsedRating = parseInt(rating);
            if (parsedRating >= 1 && parsedRating <= 5) {
                query = query.where('rating', '==', parsedRating);
            }
        }

        const snapshot = await query.get();
        const rates = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            rates.push({
                id: doc.id,
                ...data,
                // إخفاء الإيميل 🔒
                email: maskEmail(data.email),
                createdAt: data.createdAt?.toDate?.()?.toISOString() || null
            });
        });

        rates.sort((a, b) => {
            if (!a.createdAt) return 1;
            if (!b.createdAt) return -1;
            return new Date(b.createdAt) - new Date(a.createdAt);
        });

        res.json(rates);
    } catch (error) {
        console.error('Error fetching rates:', error);
        res.status(500).json({ error: 'Failed to fetch rates' });
    }
});

// PUT - مع CSRF
app.put('/api/rates/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, rating, opinion } = req.body;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid rate ID' });
        }

        if (!name || !email || !rating || !opinion) {
            return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });
        }

        if (rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'التقييم يجب أن يكون بين 1 و 5' });
        }

        const docRef = db.collection('rates').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Rate not found' });
        }

        const updateData = {
            name: sanitizeInput(name.trim()),
            email: email.trim(),
            rating: parseInt(rating),
            opinion: sanitizeInput(opinion.trim()),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await docRef.update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating rate:', error);
        res.status(500).json({ error: 'Failed to update rate' });
    }
});

// DELETE - مع CSRF
app.delete('/api/rates/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid rate ID' });
        }

        const docRef = db.collection('rates').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Rate not found' });
        }

        await docRef.delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting rate:', error);
        res.status(500).json({ error: 'Failed to delete rate' });
    }
});

// ============================================
// ===== ORDERS =====
// ============================================
app.post('/api/orders', async (req, res) => {
    try {
        const { name, phone, email, orderText, imageUrl } = req.body;

        if (!name || !phone || !email || !orderText) {
            return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });
        }

        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'رقم هاتف غير صالح' });
        }

        const orderData = {
            name: sanitizeInput(name.trim()),
            phone: sanitizeInput(phone.trim()),
            email: email.trim(),
            orderText: sanitizeInput(orderText.trim()),
            status: 'pending',
            imageUrl: imageUrl || '',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('orders').add(orderData);
        res.status(201).json({ id: docRef.id, ...orderData });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Failed to submit order' });
    }
});

app.get('/api/orders', requireAuth, async (req, res) => {
    try {
        const { status } = req.query;
        let query = db.collection('orders').limit(100);

        if (status && status !== 'all') {
            const validStatuses = ['pending', 'processing', 'completed', 'cancelled'];
            if (validStatuses.includes(status)) {
                query = query.where('status', '==', status);
            }
        }

        const snapshot = await query.get();
        const orders = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            orders.push({
                id: doc.id,
                ...data,
                createdAt: data.createdAt?.toDate?.()?.toISOString() || null
            });
        });

        orders.sort((a, b) => {
            if (!a.createdAt) return 1;
            if (!b.createdAt) return -1;
            return new Date(b.createdAt) - new Date(a.createdAt);
        });

        res.json(orders);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.put('/api/orders/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, phone, email, orderText, status, imageUrl } = req.body;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid order ID' });
        }

        if (!name || !phone || !email || !orderText) {
            return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });
        }

        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'رقم هاتف غير صالح' });
        }

        const validStatuses = ['pending', 'processing', 'completed', 'cancelled'];
        if (status && !validStatuses.includes(status)) {
            return res.status(400).json({ error: 'حالة غير صالحة' });
        }

        const docRef = db.collection('orders').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const updateData = {
            name: sanitizeInput(name.trim()),
            phone: sanitizeInput(phone.trim()),
            email: email.trim(),
            orderText: sanitizeInput(orderText.trim()),
            status: status || 'pending',
            imageUrl: imageUrl || '',
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await docRef.update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating order:', error);
        res.status(500).json({ error: 'Failed to update order' });
    }
});

app.put('/api/orders/:id/status', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid order ID' });
        }

        const validStatuses = ['pending', 'processing', 'completed', 'cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'حالة غير صالحة' });
        }

        const docRef = db.collection('orders').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Order not found' });
        }

        await docRef.update({
            status,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        try {
            const order = doc.data();
            const statusMap = {
                pending: 'قيد الانتظار',
                processing: 'قيد التنفيذ',
                completed: 'مكتمل',
                cancelled: 'ملغي'
            };
            
            const transporterInstance = await getTransporter();
            if (transporterInstance && order.email) {
                await transporterInstance.sendMail({
                    from: '"Shulamith Gallery" <' + process.env.SMTP_FROM_EMAIL + '>',
                    to: order.email,
                    subject: 'تحديث حالة الطلب #' + id.substring(0, 8),
                    html: `
                        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #1a1a1a; color: #e8e0d4; border-radius: 12px; border: 1px solid #333;">
                            <div style="text-align: center; margin-bottom: 30px;">
                                <img src="https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg" alt="Shulamith Gallery" style="max-width: 150px; height: auto; border-radius: 8px;">
                            </div>
                            <h2 style="color: #d4b892; margin-bottom: 20px;">مرحباً ${sanitizeHtml(order.name)}،</h2>
                            <p style="line-height: 1.8; color: #d4c8b8;">تم تحديث حالة طلبك إلى: <strong style="color: #d4b892;">${statusMap[status] || status}</strong></p>
                            <div style="margin: 20px 0; padding: 20px; background: #252525; border-radius: 8px; border-right: 3px solid #d4b892;">
                                <p style="margin: 5px 0; color: #d4c8b8;"><strong style="color: #d4b892;">تفاصيل الطلب:</strong></p>
                                <p style="margin: 10px 0 0 0; color: #e8e0d4;">${sanitizeHtml(order.orderText)}</p>
                            </div>
                            <hr style="border: none; border-top: 1px solid #333; margin: 30px 0;">
                            <p style="color: #999; font-size: 14px; text-align: center;">
                                © 2026 Shulamith Gallery. جميع الحقوق محفوظة
                            </p>
                        </div>
                    `
                });
                console.log('Status update email sent to:', order.email);
            }
        } catch (emailError) {
            console.error('Error sending status email:', emailError.message);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).json({ error: 'Failed to update order status' });
    }
});

app.delete('/api/orders/:id', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { id } = req.params;

        if (!validateFirestoreId(id)) {
            return res.status(400).json({ error: 'Invalid order ID' });
        }

        const docRef = db.collection('orders').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Order not found' });
        }

        await docRef.delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting order:', error);
        res.status(500).json({ error: 'Failed to delete order' });
    }
});

// ============================================
// ===== SETTINGS =====
// ============================================
app.get('/api/settings', async (req, res) => {
    try {
        const doc = await db.collection('settings').doc('site').get();
        if (doc.exists) {
            res.json({ id: doc.id, ...doc.data() });
        } else {
            res.json({
                siteName: 'Shulamith Gallery',
                logo: 'https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg',
                aboutText: 'خريجة فنون جميلة، أقدم أعمال فنية ولوحات وديكور مع إمكانية تنفيذ أي تابلوه بخامة وحجم مناسبين.',
                phone: '012 76961450',
                email: 'mrmrtharwat43@gmail.com',
                address: 'سوهاج، مصر',
                instagram: '',
                facebook: 'shulamithgallery.7559699',
                whatsapp: '201276961450',
                heroText: 'شولميث جاليري - حيث يلتقي الفن بالجمال',
                footerText: '© 2026 Shulamith Gallery. جميع الحقوق محفوظة'
            });
        }
    } catch (error) {
        console.error('Error fetching settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.put('/api/settings', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const settings = req.body;

        const requiredFields = ['siteName', 'logo'];
        for (const field of requiredFields) {
            if (!settings[field]) {
                return res.status(400).json({ error: field + ' is required' });
            }
        }

        settings.updatedAt = admin.firestore.FieldValue.serverTimestamp();

        await db.collection('settings').doc('site').set(settings, { merge: true });
        res.json({ success: true, settings });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// ============================================
// ===== STATS =====
// ============================================
app.get('/api/stats', requireAuth, async (req, res) => {
    try {
        const statsPromise = Promise.all([
            db.collection('galleries').get(),
            db.collection('artworks').get(),
            db.collection('messages').get(),
            db.collection('artworks').where('featured', '==', true).get(),
            db.collection('messages').where('read', '==', false).get(),
            db.collection('rates').get(),
            db.collection('orders').get()
        ]);

        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Stats request timeout')), 10000);
        });

        const [galleriesSnapshot, artworksSnapshot, messagesSnapshot, featuredSnapshot, unreadSnapshot, ratesSnapshot, ordersSnapshot] =
            await Promise.race([statsPromise, timeoutPromise]);

        res.json({
            galleries: galleriesSnapshot.size,
            artworks: artworksSnapshot.size,
            messages: messagesSnapshot.size,
            featured: featuredSnapshot.size,
            unreadMessages: unreadSnapshot.size,
            rates: ratesSnapshot.size,
            orders: ordersSnapshot.size
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        if (error.message === 'Stats request timeout') {
            res.status(504).json({ error: 'Request timeout, please try again' });
        } else {
            res.status(500).json({ error: 'Failed to fetch stats' });
        }
    }
});

// ============================================
// ===== SEND EMAIL =====
// ============================================
app.post('/api/send-email', requireAuth, verifyCsrf, async (req, res) => {
    try {
        const { name, email, message } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({ error: 'الاسم والبريد الإلكتروني والرسالة مطلوبة' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });
        }

        const smtpTransporter = await getTransporter();
        
        if (!smtpTransporter) {
            console.error('Email service not available');
            return res.status(503).json({
                error: 'خدمة البريد الإلكتروني غير متاحة. الرجاء المحاولة لاحقاً.'
            });
        }

        const mailOptions = {
            from: '"Shulamith Gallery" <' + process.env.SMTP_FROM_EMAIL + '>',
            to: email,
            subject: 'رسالة من Shulamith Gallery',
            html: `
                <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #1a1a1a; color: #e8e0d4; border-radius: 12px; border: 1px solid #333;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg" alt="Shulamith Gallery" style="max-width: 150px; height: auto; border-radius: 8px;">
                    </div>
                    <div style="border-bottom: 1px solid #333; padding-bottom: 20px; margin-bottom: 20px;">
                        <h2 style="color: #d4b892; margin: 0; font-weight: 300;">Shulamith Gallery</h2>
                        <p style="color: #b0a89a; margin: 5px 0 0 0;">${new Date().toLocaleDateString('ar-EG')}</p>
                    </div>
                    <div style="background: #252525; padding: 20px; border-radius: 8px; border-right: 3px solid #d4b892;">
                        <p style="color: #d4c8b8; margin: 0 0 10px 0;"><strong style="color: #d4b892;">رسالة إلى:</strong> ${sanitizeHtml(name)}</p>
                        <p style="color: #d4c8b8; margin: 0 0 10px 0;"><strong style="color: #d4b892;">البريد:</strong> ${email}</p>
                        <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #333;">
                            <p style="color: #d4c8b8; margin: 0 0 8px 0;"><strong style="color: #d4b892;">الرسالة:</strong></p>
                            <p style="color: #e8e0d4; margin: 0; line-height: 1.8; background: #1a1a1a; padding: 12px; border-radius: 6px;">${sanitizeHtml(message)}</p>
                        </div>
                    </div>
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #333; text-align: center;">
                        <p style="color: #999; font-size: 14px; margin: 0;">
                            © 2026 <strong style="color: #d4b892;">Shulamith Gallery</strong>. جميع الحقوق محفوظة
                        </p>
                        <p style="color: #666; font-size: 12px; margin: 5px 0 0 0;">
                            شولميث جاليري — حيث يلتقي الفن بالجمال
                        </p>
                    </div>
                </div>
            `
        };

        await smtpTransporter.sendMail(mailOptions);
        console.log('Email sent to:', email);

        res.json({ success: true, message: 'Email sent successfully' });
    } catch (error) {
        console.error('Send email error:', error);
        res.status(500).json({ error: 'Failed to send email: ' + error.message });
    }
});

// ============================================
// ===== HEALTH =====
// ============================================
app.get('/api/health', requireAuth, (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString()
    });
});

// ============================================
// ===== ERROR HANDLING =====
// ============================================
app.use((err, req, res, next) => {
    console.error('Server error:', err);

    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'الملف كبير جداً. الحد الأقصى 5 ميجابايت.' });
        }
        if (err.code === 'FILE_TYPE') {
            return res.status(400).json({ error: err.message });
        }
        return res.status(400).json({ error: err.message });
    }

    if (err.message === 'Invalid file type. Only images are allowed.') {
        return res.status(400).json({ error: 'نوع الملف غير مدعوم. الصور فقط مسموحة.' });
    }

    res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// ===== START SERVER =====
// ============================================
if (require.main === module) {
    app.listen(PORT, () => {
        console.log('🚀 Shulamith Gallery Server running on port ' + PORT);
        console.log('📊 Dashboard available at http://localhost:' + PORT + '/dashboard.html');
        console.log('🔑 Login at http://localhost:' + PORT + '/login.html');
        console.log('❤️ Health check at http://localhost:' + PORT + '/api/health (admin only)');
        console.log('🛡️ CSRF Protection: ✅ ENABLED');
        console.log('🔒 Rate Limiting: ✅ ENABLED');
        console.log('📧 Email Privacy: ✅ ENABLED (email masking)');
    });
}

module.exports = app;
