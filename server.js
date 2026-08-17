require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ ✅ مهم جداً لـ Vercel ============
app.set('trust proxy', true);

// ============ Timeout Middleware ============
const timeoutMiddleware = (req, res, next) => {
    req.setTimeout(30000, () => {
        res.status(504).json({ error: 'Request timeout' });
    });
    next();
};

// ============ 🔥 CORS - إصلاح الأمان ============
const allowedOrigins = (process.env.CORS_ORIGIN || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(origin => origin.length > 0);

const corsOptions = {
    origin: function (origin, callback) {
        // السماح للطلبات بدون origin (مثل Postman)
        if (!origin) return callback(null, true);
        
        // في بيئة التطوير، السماح بأي origin
        if (process.env.NODE_ENV === 'development') {
            return callback(null, true);
        }
        
        // في الإنتاج، السماح فقط بالأصول المسموح بها
        if (allowedOrigins.length === 0) {
            return callback(new Error('CORS_ORIGIN not configured'), false);
        }
        
        if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'), false);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));

// ============ 🔥 Helmet - إصلاح الأمان ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com", "https://i.postimg.cc", "https://via.placeholder.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", "https://firestore.googleapis.com", "https://api.cloudinary.com"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
    noSniff: true,
    hidePoweredBy: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

app.use(timeoutMiddleware);

// ============ 🔥 Rate Limiting - إصلاح ============
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

const orderLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Too many orders placed. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    }
});

const rateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    }
});

app.use('/api/login', authLimiter);
app.use('/api/contact', contactLimiter);
app.use('/api/upload', limiter);
app.use('/api/stats', limiter);
app.use('/api/send-email', limiter);
app.use('/api/orders', orderLimiter);

// ============ Firebase Admin ============
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
        console.log('✅ Firebase initialized successfully');
    } catch (error) {
        console.error('❌ Firebase initialization failed:', error.message);
        process.exit(1);
    }
} else {
    console.log('✅ Firebase app already exists, reusing...');
}

const db = admin.firestore();

// ============ Cloudinary ============
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// ============ Email Transporter ============
let transporter = null;
let emailConfigured = false;
let initializationPromise = null;

const initializeTransporter = async () => {
    if (initializationPromise) {
        console.log('⏳ SMTP initialization already in progress, waiting...');
        return initializationPromise;
    }

    initializationPromise = (async () => {
        try {
            if (!nodemailer || typeof nodemailer.createTransport !== 'function') {
                console.warn('⚠️ Nodemailer not available or invalid');
                return false;
            }

            const requiredEnv = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM_EMAIL'];
            const missing = requiredEnv.filter(key => !process.env[key]);
            if (missing.length > 0) {
                console.warn(`⚠️ Missing SMTP env variables: ${missing.join(', ')}`);
                return false;
            }

            console.log(`📧 Connecting to SMTP: ${process.env.SMTP_HOST}:${process.env.SMTP_PORT}`);

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
                    ciphers: 'SSLv3',
                    rejectUnauthorized: false
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
            console.log('✅ SMTP configured and verified successfully');
            return true;
            
        } catch (error) {
            console.error('❌ SMTP initialization FAILED:', error.message);
            
            if (error.message.includes('535-5.7.8')) {
                console.error('🔴 GMAIL AUTH ERROR: Use App Password, not regular password');
                console.error('🔴 Get one at: https://myaccount.google.com/apppasswords');
            } else if (error.message.includes('timeout')) {
                console.error('🔴 TIMEOUT: Vercel might be blocking the connection');
                console.error('🔴 Try changing SMTP_PORT to 587 and SMTP_SECURE to false');
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

// ============ JWT Helpers ============
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('⚠️ JWT_SECRET is too short or not set! Please set a strong secret.');
}

const generateToken = (username) => {
    return jwt.sign(
        { username, role: 'admin' },
        JWT_SECRET,
        { expiresIn: '24h', algorithm: 'HS256' }
    );
};

const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (error) {
        return null;
    }
};

// ============ 🔥 Auth Middleware - مع تحقق الصلاحيات ============
const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // التحقق من صلاحية Admin
    if (decoded.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }

    req.user = decoded;
    next();
};

const requireAdmin = requireAuth; // Alias للوضوح

// ============ 🔥 Validation Helpers - مع sanitization ============
const validator = {
    email: (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },
    phone: (phone) => {
        return /^[\d+\s-()]{8,20}$/.test(phone);
    },
    name: (name) => {
        return name && name.length >= 2 && name.length <= 100;
    },
    message: (msg) => {
        return msg && msg.length >= 3 && msg.length <= 5000;
    },
    orderText: (text) => {
        return text && text.length >= 3 && text.length <= 5000;
    },
    rating: (rating) => {
        const num = parseInt(rating);
        return !isNaN(num) && num >= 1 && num <= 5;
    },
    sanitize: (str) => {
        if (typeof str !== 'string') return '';
        return str.trim()
            .replace(/[<>]/g, '') // إزالة HTML tags
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    },
    sanitizeForHTML: (str) => {
        if (typeof str !== 'string') return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
};

// ============================================================
// ============ 🚀 ALL API ROUTES ============
// ============================================================

// ---------- Auth ----------
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // استخدام مقارنة آمنة
        const adminUsername = process.env.ADMIN_USERNAME;
        const adminPassword = process.env.ADMIN_PASSWORD;

        if (!adminUsername || !adminPassword) {
            console.error('❌ ADMIN credentials not set in environment');
            return res.status(500).json({ error: 'Server configuration error' });
        }

        if (username !== adminUsername || password !== adminPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = generateToken(username);
        res.json({
            token,
            user: { username },
            expiresIn: 86400
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/verify', requireAuth, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ---------- Galleries ----------
app.get('/api/galleries', async (req, res) => {
    try {
        const snapshot = await db.collection('galleries').get();

        const galleries = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            // إزالة الحقول الداخلية الحساسة
            const { updatedAt, ...rest } = data;
            galleries.push({ id: doc.id, ...rest });
        });

        galleries.sort((a, b) => (a.order || 0) - (b.order || 0));

        res.json(galleries);
    } catch (error) {
        console.error('Error fetching galleries:', error);
        res.status(500).json({ error: 'Failed to fetch galleries' });
    }
});

app.post('/api/galleries', requireAdmin, async (req, res) => {
    try {
        const { name, description, coverImage, visible, order } = req.body;

        if (!validator.name(name)) {
            return res.status(400).json({ error: 'Gallery name must be between 2-100 characters' });
        }

        // Sanitize input
        const sanitizedName = validator.sanitize(name);
        const sanitizedDescription = validator.sanitize(description || '');
        const sanitizedCoverImage = validator.sanitize(coverImage || '');

        const galleryData = {
            name: sanitizedName,
            description: sanitizedDescription,
            coverImage: sanitizedCoverImage,
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('galleries').add(galleryData);
        res.status(201).json({ id: docRef.id, ...galleryData });
    } catch (error) {
        console.error('Error creating gallery:', error);
        res.status(500).json({ error: 'Failed to create gallery' });
    }
});

app.put('/api/galleries/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, coverImage, visible, order } = req.body;

        if (!validator.name(name)) {
            return res.status(400).json({ error: 'Gallery name must be between 2-100 characters' });
        }

        const sanitizedName = validator.sanitize(name);
        const sanitizedDescription = validator.sanitize(description || '');
        const sanitizedCoverImage = validator.sanitize(coverImage || '');

        const updateData = {
            name: sanitizedName,
            description: sanitizedDescription,
            coverImage: sanitizedCoverImage,
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await db.collection('galleries').doc(id).update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating gallery:', error);
        res.status(500).json({ error: 'Failed to update gallery' });
    }
});

app.delete('/api/galleries/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const artworksSnapshot = await db.collection('artworks')
            .where('galleryId', '==', id)
            .get();

        if (!artworksSnapshot.empty) {
            return res.status(400).json({
                error: 'Cannot delete gallery with existing artworks. Please delete or move artworks first.'
            });
        }

        await db.collection('galleries').doc(id).delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting gallery:', error);
        res.status(500).json({ error: 'Failed to delete gallery' });
    }
});

// ---------- 🔥 Artworks - مع sanitization ----------
app.get('/api/artworks', async (req, res) => {
    try {
        const { galleryId, featured } = req.query;
        let query = db.collection('artworks');

        if (galleryId) {
            query = query.where('galleryId', '==', galleryId);
        }

        if (featured === 'true') {
            query = query.where('featured', '==', true);
        }

        const snapshot = await query.get();
        const artworks = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            // Sanitize for safe display
            artworks.push({
                id: doc.id,
                title: validator.sanitizeForHTML(data.title || ''),
                description: validator.sanitizeForHTML(data.description || ''),
                imageUrl: data.imageUrl || '',
                cloudinaryPublicId: data.cloudinaryPublicId || '',
                material: validator.sanitizeForHTML(data.material || ''),
                dimensions: validator.sanitizeForHTML(data.dimensions || ''),
                price: data.price || 0,
                featured: data.featured || false,
                visible: data.visible !== undefined ? data.visible : true,
                galleryId: data.galleryId || '',
                order: data.order || 0,
                createdAt: data.createdAt?.toDate?.()?.toISOString() || null
            });
        });

        artworks.sort((a, b) => (a.order || 0) - (b.order || 0));

        res.json(artworks);
    } catch (error) {
        console.error('Error fetching artworks:', error);
        res.status(500).json({ error: 'Failed to fetch artworks' });
    }
});

app.post('/api/artworks', requireAdmin, async (req, res) => {
    try {
        const {
            galleryId, title, description, imageUrl, cloudinaryPublicId,
            material, dimensions, price, featured, visible, order
        } = req.body;

        if (!galleryId) {
            return res.status(400).json({ error: 'Gallery ID is required' });
        }

        if (!validator.name(title)) {
            return res.status(400).json({ error: 'Artwork title must be between 2-100 characters' });
        }

        if (!imageUrl) {
            return res.status(400).json({ error: 'Image URL is required' });
        }

        const artworkData = {
            galleryId: validator.sanitize(galleryId),
            title: validator.sanitize(title),
            description: validator.sanitize(description || ''),
            imageUrl: validator.sanitize(imageUrl),
            cloudinaryPublicId: validator.sanitize(cloudinaryPublicId || ''),
            material: validator.sanitize(material || ''),
            dimensions: validator.sanitize(dimensions || ''),
            price: price || 0,
            featured: featured || false,
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('artworks').add(artworkData);
        res.status(201).json({ id: docRef.id, ...artworkData });
    } catch (error) {
        console.error('Error creating artwork:', error);
        res.status(500).json({ error: 'Failed to create artwork' });
    }
});

app.put('/api/artworks/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            galleryId, title, description, imageUrl, cloudinaryPublicId,
            material, dimensions, price, featured, visible, order
        } = req.body;

        if (!galleryId) {
            return res.status(400).json({ error: 'Gallery ID is required' });
        }

        if (!validator.name(title)) {
            return res.status(400).json({ error: 'Artwork title must be between 2-100 characters' });
        }

        if (!imageUrl) {
            return res.status(400).json({ error: 'Image URL is required' });
        }

        const updateData = {
            galleryId: validator.sanitize(galleryId),
            title: validator.sanitize(title),
            description: validator.sanitize(description || ''),
            imageUrl: validator.sanitize(imageUrl),
            cloudinaryPublicId: validator.sanitize(cloudinaryPublicId || ''),
            material: validator.sanitize(material || ''),
            dimensions: validator.sanitize(dimensions || ''),
            price: price || 0,
            featured: featured || false,
            visible: visible !== undefined ? visible : true,
            order: order || 0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await db.collection('artworks').doc(id).update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating artwork:', error);
        res.status(500).json({ error: 'Failed to update artwork' });
    }
});

app.delete('/api/artworks/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const doc = await db.collection('artworks').doc(id).get();
        if (doc.exists) {
            const data = doc.data();
            if (data.cloudinaryPublicId) {
                try {
                    await cloudinary.uploader.destroy(data.cloudinaryPublicId);
                } catch (error) {
                    console.error('Error deleting from Cloudinary:', error);
                }
            }
        }

        await db.collection('artworks').doc(id).delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting artwork:', error);
        res.status(500).json({ error: 'Failed to delete artwork' });
    }
});

// ---------- 🔥 Cloudinary Upload - مع التحقق من نوع الملف ----------
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    },
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, WEBP, and GIF are allowed.'), false);
        }
    }
});

app.post('/api/upload', requireAdmin, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }

        // التحقق الإضافي من نوع الملف
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (!allowedTypes.includes(req.file.mimetype)) {
            return res.status(400).json({ error: 'Invalid file type. Only JPEG, PNG, WEBP, and GIF are allowed.' });
        }

        const b64 = Buffer.from(req.file.buffer).toString('base64');
        const dataURI = `data:${req.file.mimetype};base64,${b64}`;

        const result = await Promise.race([
            cloudinary.uploader.upload(dataURI, {
                folder: 'shulamith-gallery',
                resource_type: 'image'
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
        } else if (error.message.includes('Invalid file type')) {
            res.status(400).json({ error: error.message });
        } else {
            res.status(500).json({ error: 'Failed to upload image' });
        }
    }
});

// ---------- 🔥 Messages - مع sanitization و rate limiting ----------
app.post('/api/contact', contactLimiter, async (req, res) => {
    try {
        let { name, email, phone, message } = req.body;

        // Sanitize input
        name = validator.sanitize(name || '');
        email = validator.sanitize(email || '');
        phone = validator.sanitize(phone || '');
        message = validator.sanitize(message || '');

        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email, and message are required' });
        }

        if (!validator.name(name)) {
            return res.status(400).json({ error: 'Name must be between 2-100 characters' });
        }

        if (!validator.email(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (phone && !validator.phone(phone)) {
            return res.status(400).json({ error: 'Invalid phone number format' });
        }

        if (!validator.message(message)) {
            return res.status(400).json({ error: 'Message must be between 3-5000 characters' });
        }

        const messageData = {
            name,
            email,
            phone,
            message,
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('messages').add(messageData);

        // Send confirmation email
        if (email && transporter && emailConfigured) {
            setImmediate(async () => {
                try {
                    await transporter.sendMail({
                        from: `"${process.env.SMTP_FROM_NAME || 'Shulamith Gallery'}" <${process.env.SMTP_FROM_EMAIL}>`,
                        to: email,
                        subject: 'شكراً لتواصلك مع Shulamith Gallery',
                        html: `
                            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #1a1a1a; color: #e8e0d4; border-radius: 12px;">
                                <div style="text-align: center; margin-bottom: 30px;">
                                    <img src="https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg" alt="Shulamith Gallery" style="max-width: 150px; height: auto; border-radius: 8px;">
                                </div>
                                <h2 style="color: #d4b892; margin-bottom: 20px;">مرحباً ${validator.sanitizeForHTML(name)}،</h2>
                                <p style="line-height: 1.8; color: #d4c8b8;">تم استلام استفساركم وسيتم الرد في أقرب وقت.</p>
                                <p style="line-height: 1.8; color: #d4c8b8;">شكراً لتواصلك مع <strong style="color: #d4b892;">Shulamith Gallery</strong>.</p>
                                <div style="margin: 30px 0; padding: 20px; background: #252525; border-radius: 8px; border-right: 3px solid #d4b892;">
                                    <p style="margin: 5px 0; color: #d4c8b8;"><strong style="color: #d4b892;">رسالتك:</strong></p>
                                    <p style="margin: 10px 0 0 0; color: #e8e0d4; font-style: italic;">${validator.sanitizeForHTML(message)}</p>
                                </div>
                                <hr style="border: none; border-top: 1px solid #333; margin: 30px 0;">
                                <p style="color: #999; font-size: 14px; text-align: center;">
                                    © 2026 Shulamith Gallery. All rights reserved.
                                </p>
                            </div>
                        `
                    });
                    console.log('✅ Confirmation email sent to:', email);
                } catch (error) {
                    console.error('❌ Error sending confirmation email:', error.message);
                }
            });
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

app.get('/api/messages', requireAdmin, async (req, res) => {
    try {
        const { unread } = req.query;
        let query = db.collection('messages');

        if (unread === 'true') {
            query = query.where('read', '==', false);
        }

        const snapshot = await query.get();
        const messages = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            // إزالة الحقول الحساسة
            messages.push({
                id: doc.id,
                name: validator.sanitizeForHTML(data.name || ''),
                email: data.email || '',
                phone: data.phone || '',
                message: validator.sanitizeForHTML(data.message || ''),
                read: data.read || false,
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

app.put('/api/messages/:id/read', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { read } = req.body;

        await db.collection('messages').doc(id).update({
            read: read !== undefined ? read : true,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating message:', error);
        res.status(500).json({ error: 'Failed to update message' });
    }
});

app.delete('/api/messages/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await db.collection('messages').doc(id).delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// ---------- 🔥 RATES - مع حماية PII ----------
app.post('/api/rates', rateLimiter, async (req, res) => {
    try {
        let { name, email, rating, opinion } = req.body;

        name = validator.sanitize(name || '');
        email = validator.sanitize(email || '');
        opinion = validator.sanitize(opinion || '');

        if (!name || !email || !rating || !opinion) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validator.name(name)) {
            return res.status(400).json({ error: 'Name must be between 2-100 characters' });
        }

        if (!validator.email(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (!validator.rating(rating)) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        if (!validator.message(opinion)) {
            return res.status(400).json({ error: 'Opinion must be between 3-5000 characters' });
        }

        const rateData = {
            name,
            email,
            rating: parseInt(rating),
            opinion,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('rates').add(rateData);
        res.status(201).json({ id: docRef.id, ...rateData });
    } catch (error) {
        console.error('Error creating rate:', error);
        res.status(500).json({ error: 'Failed to submit rate' });
    }
});

app.get('/api/rates', async (req, res) => {
    try {
        const { rating } = req.query;
        let query = db.collection('rates');

        if (rating) {
            query = query.where('rating', '==', parseInt(rating));
        }

        const snapshot = await query.get();
        const rates = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            // ❌ لا نعرض email أو أي بيانات شخصية في الواجهة العامة
            rates.push({
                id: doc.id,
                name: validator.sanitizeForHTML(data.name || ''),
                rating: data.rating || 0,
                opinion: validator.sanitizeForHTML(data.opinion || ''),
                createdAt: data.createdAt?.toDate?.()?.toISOString() || null
                // ⚠️ intentionally NOT including email or phone
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

app.put('/api/rates/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        let { name, email, rating, opinion } = req.body;

        name = validator.sanitize(name || '');
        email = validator.sanitize(email || '');
        opinion = validator.sanitize(opinion || '');

        if (!name || !email || !rating || !opinion) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validator.name(name)) {
            return res.status(400).json({ error: 'Name must be between 2-100 characters' });
        }

        if (!validator.email(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (!validator.rating(rating)) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        if (!validator.message(opinion)) {
            return res.status(400).json({ error: 'Opinion must be between 3-5000 characters' });
        }

        const updateData = {
            name,
            email,
            rating: parseInt(rating),
            opinion,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await db.collection('rates').doc(id).update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating rate:', error);
        res.status(500).json({ error: 'Failed to update rate' });
    }
});

app.delete('/api/rates/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await db.collection('rates').doc(id).delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting rate:', error);
        res.status(500).json({ error: 'Failed to delete rate' });
    }
});

// ---------- 🔥 ORDERS - مع حماية IDOR ----------
app.post('/api/orders', orderLimiter, async (req, res) => {
    try {
        let { name, phone, email, orderText } = req.body;

        name = validator.sanitize(name || '');
        phone = validator.sanitize(phone || '');
        email = validator.sanitize(email || '');
        orderText = validator.sanitize(orderText || '');

        if (!name || !phone || !email || !orderText) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validator.name(name)) {
            return res.status(400).json({ error: 'Name must be between 2-100 characters' });
        }

        if (!validator.phone(phone)) {
            return res.status(400).json({ error: 'Invalid phone format' });
        }

        if (!validator.email(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (!validator.orderText(orderText)) {
            return res.status(400).json({ error: 'Order details must be between 3-5000 characters' });
        }

        const orderData = {
            name,
            phone,
            email,
            orderText,
            status: 'pending',
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

// 🔥 مع إضافة requireAuth لحماية البيانات
app.get('/api/orders', requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let query = db.collection('orders');

        if (status && status !== 'all') {
            query = query.where('status', '==', status);
        }

        const snapshot = await query.get();
        const orders = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            // إزالة الحقول الحساسة غير الضرورية
            orders.push({
                id: doc.id,
                name: validator.sanitizeForHTML(data.name || ''),
                phone: data.phone || '',
                email: data.email || '',
                orderText: validator.sanitizeForHTML(data.orderText || ''),
                status: data.status || 'pending',
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

app.put('/api/orders/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        let { name, phone, email, orderText, status } = req.body;

        name = validator.sanitize(name || '');
        phone = validator.sanitize(phone || '');
        email = validator.sanitize(email || '');
        orderText = validator.sanitize(orderText || '');

        if (!name || !phone || !email || !orderText) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validator.name(name)) {
            return res.status(400).json({ error: 'Name must be between 2-100 characters' });
        }

        if (!validator.phone(phone)) {
            return res.status(400).json({ error: 'Invalid phone format' });
        }

        if (!validator.email(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (!validator.orderText(orderText)) {
            return res.status(400).json({ error: 'Order details must be between 3-5000 characters' });
        }

        const validStatuses = ['pending', 'processing', 'completed', 'cancelled'];
        if (status && !validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const updateData = {
            name,
            phone,
            email,
            orderText,
            status: status || 'pending',
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await db.collection('orders').doc(id).update(updateData);
        res.json({ id, ...updateData });
    } catch (error) {
        console.error('Error updating order:', error);
        res.status(500).json({ error: 'Failed to update order' });
    }
});

app.put('/api/orders/:id/status', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        const validStatuses = ['pending', 'processing', 'completed', 'cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        await db.collection('orders').doc(id).update({
            status,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Send email notification
        try {
            const orderDoc = await db.collection('orders').doc(id).get();
            if (orderDoc.exists) {
                const order = orderDoc.data();
                const statusMap = {
                    pending: 'قيد الانتظار',
                    processing: 'قيد التنفيذ',
                    completed: 'مكتمل',
                    cancelled: 'ملغي'
                };
                
                const transporterInstance = await getTransporter();
                if (transporterInstance && order.email) {
                    await transporterInstance.sendMail({
                        from: `"Shulamith Gallery" <${process.env.SMTP_FROM_EMAIL}>`,
                        to: order.email,
                        subject: `تحديث حالة الطلب #${id.substring(0, 8)}`,
                        html: `
                            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #1a1a1a; color: #e8e0d4; border-radius: 12px; border: 1px solid #333;">
                                <div style="text-align: center; margin-bottom: 30px;">
                                    <img src="https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg" alt="Shulamith Gallery" style="max-width: 150px; height: auto; border-radius: 8px;">
                                </div>
                                <h2 style="color: #d4b892; margin-bottom: 20px;">مرحباً ${validator.sanitizeForHTML(order.name)}،</h2>
                                <p style="line-height: 1.8; color: #d4c8b8;">تم تحديث حالة طلبك إلى: <strong style="color: #d4b892;">${statusMap[status] || status}</strong></p>
                                <div style="margin: 20px 0; padding: 20px; background: #252525; border-radius: 8px; border-right: 3px solid #d4b892;">
                                    <p style="margin: 5px 0; color: #d4c8b8;"><strong style="color: #d4b892;">تفاصيل الطلب:</strong></p>
                                    <p style="margin: 10px 0 0 0; color: #e8e0d4;">${validator.sanitizeForHTML(order.orderText)}</p>
                                </div>
                                <hr style="border: none; border-top: 1px solid #333; margin: 30px 0;">
                                <p style="color: #999; font-size: 14px; text-align: center;">
                                    © 2026 Shulamith Gallery. All rights reserved.
                                </p>
                            </div>
                        `
                    });
                    console.log('✅ Status update email sent to:', order.email);
                }
            }
        } catch (emailError) {
            console.error('❌ Error sending status email:', emailError.message);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).json({ error: 'Failed to update order status' });
    }
});

app.delete('/api/orders/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await db.collection('orders').doc(id).delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting order:', error);
        res.status(500).json({ error: 'Failed to delete order' });
    }
});

// ---------- Settings ----------
app.get('/api/settings', async (req, res) => {
    try {
        const doc = await db.collection('settings').doc('site').get();
        if (doc.exists) {
            const data = doc.data();
            // Sanitize for safe display
            res.json({
                id: doc.id,
                siteName: validator.sanitizeForHTML(data.siteName || 'Shulamith Gallery'),
                logo: data.logo || 'https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg',
                aboutText: validator.sanitizeForHTML(data.aboutText || ''),
                phone: data.phone || '',
                email: data.email || '',
                address: validator.sanitizeForHTML(data.address || ''),
                instagram: data.instagram || '',
                facebook: data.facebook || '',
                whatsapp: data.whatsapp || '',
                heroText: validator.sanitizeForHTML(data.heroText || ''),
                footerText: validator.sanitizeForHTML(data.footerText || '')
            });
        } else {
            res.json({
                siteName: 'Shulamith Gallery',
                logo: 'https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg',
                aboutText: 'خريجة فنون جميلة، أقدم أعمال فنية ولوحات وديكور مع إمكانية تنفيذ أي تابلوه بخامة وحجم مناسبين.',
                phone: '012 76961450',
                email: 'mrmrtharwat43@gmail.com',
                address: 'Sohag, Egypt',
                instagram: '',
                facebook: 'shulamithgallery.7559699',
                whatsapp: '201276961450',
                heroText: 'شولميث جاليري - حيث يلتقي الفن بالجمال',
                footerText: '© 2026 Shulamith Gallery. All rights reserved.'
            });
        }
    } catch (error) {
        console.error('Error fetching settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.put('/api/settings', requireAdmin, async (req, res) => {
    try {
        const settings = req.body;
        const requiredFields = ['siteName', 'logo'];
        for (const field of requiredFields) {
            if (!settings[field]) {
                return res.status(400).json({ error: `${field} is required` });
            }
        }

        // Sanitize settings
        const sanitizedSettings = {};
        for (const [key, value] of Object.entries(settings)) {
            if (typeof value === 'string') {
                sanitizedSettings[key] = validator.sanitize(value);
            } else {
                sanitizedSettings[key] = value;
            }
        }
        sanitizedSettings.updatedAt = admin.firestore.FieldValue.serverTimestamp();

        await db.collection('settings').doc('site').set(sanitizedSettings, { merge: true });
        res.json({ success: true, settings: sanitizedSettings });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// ---------- 🔥 Stats - مع حماية البيانات الحساسة ----------
app.get('/api/stats', requireAdmin, async (req, res) => {
    try {
        const statsPromise = Promise.all([
            db.collection('galleries').get(),
            db.collection('artworks').get(),
            db.collection('messages').get(),
            db.collection('artworks').where('featured', '==', true).get(),
            db.collection('messages').where('read', '==', false).get()
        ]);

        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Stats request timeout')), 10000);
        });

        const [galleriesSnapshot, artworksSnapshot, messagesSnapshot, featuredSnapshot, unreadSnapshot] =
            await Promise.race([statsPromise, timeoutPromise]);

        res.json({
            galleries: galleriesSnapshot.size,
            artworks: artworksSnapshot.size,
            messages: messagesSnapshot.size,
            featured: featuredSnapshot.size,
            unreadMessages: unreadSnapshot.size
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

// ---------- 🔥 Send Email (Admin) - مع حماية HTML Injection ----------
app.post('/api/send-email', requireAdmin, async (req, res) => {
    try {
        let { name, email, message } = req.body;

        name = validator.sanitize(name || '');
        email = validator.sanitize(email || '');
        message = validator.sanitize(message || '');

        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email, and message are required' });
        }

        if (!validator.email(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (!validator.message(message)) {
            return res.status(400).json({ error: 'Message must be between 3-5000 characters' });
        }

        const smtpTransporter = await getTransporter();
        
        if (!smtpTransporter) {
            console.error('❌ Email service not available');
            return res.status(503).json({
                error: 'Email service not configured. Please try again later.',
                details: 'SMTP connection failed. Check server logs.'
            });
        }

        // Escape HTML for email content
        const escapedName = validator.sanitizeForHTML(name);
        const escapedEmail = validator.sanitizeForHTML(email);
        const escapedMessage = validator.sanitizeForHTML(message);

        const mailOptions = {
            from: `"Shulamith Gallery" <${process.env.SMTP_FROM_EMAIL}>`,
            to: email,
            subject: `رسالة من Shulamith Gallery`,
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
                        <p style="color: #d4c8b8; margin: 0 0 10px 0;"><strong style="color: #d4b892;">رسالة الى:</strong> ${escapedName}</p>
                        <p style="color: #d4c8b8; margin: 0 0 10px 0;"><strong style="color: #d4b892;">البريد:</strong> ${escapedEmail}</p>
                        <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #333;">
                            <p style="color: #d4c8b8; margin: 0 0 8px 0;"><strong style="color: #d4b892;">الرسالة:</strong></p>
                            <p style="color: #e8e0d4; margin: 0; line-height: 1.8; background: #1a1a1a; padding: 12px; border-radius: 6px;">${escapedMessage}</p>
                        </div>
                    </div>
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #333; text-align: center;">
                        <p style="color: #999; font-size: 14px; margin: 0;">
                            © 2026 <strong style="color: #d4b892;">Shulamith Gallery</strong>. All rights reserved.
                        </p>
                        <p style="color: #666; font-size: 12px; margin: 5px 0 0 0;">
                            شولميث جاليري — حيث يلتقي الفن بالجمال
                        </p>
                    </div>
                </div>
            `
        };

        await smtpTransporter.sendMail(mailOptions);
        console.log('✅ Email sent to:', email);

        res.json({ success: true, message: 'Email sent successfully' });
    } catch (error) {
        console.error('❌ Send email error:', error);
        res.status(500).json({ error: 'Failed to send email: ' + error.message });
    }
});

// ---------- 🔥 Health Check - مع إخفاء المعلومات الحساسة ----------
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString()
        // ❌ removed: uptime, smtp details, environment details
    });
});

// ============ Error Handling Middleware ============
app.use((err, req, res, next) => {
    console.error('Server error:', err);

    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'File too large. Maximum size is 5MB.' });
        }
        return res.status(400).json({ error: err.message });
    }

    res.status(500).json({ error: 'Internal server error' });
});

// ============ Start Server ============
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 Shulamith Gallery Server running on port ${PORT}`);
        console.log(`📊 Dashboard available at http://localhost:${PORT}/dashboard.html`);
        console.log(`🔐 Login at http://localhost:${PORT}/login.html`);
        console.log(`🩺 Health check at http://localhost:${PORT}/api/health`);
    });
}

module.exports = app;
