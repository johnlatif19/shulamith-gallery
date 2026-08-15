require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ Middleware ============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com", "https://i.postimg.cc"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "https://firestore.googleapis.com", "https://api.cloudinary.com"]
    }
  }
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

// ============ Rate Limiting ============
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts, please try again later.' }
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many messages sent. Please try again later.' }
});

app.use('/api/login', authLimiter);
app.use('/api/contact', contactLimiter);
app.use('/api/upload', limiter);

// ============ Firebase Admin ============
let firebaseConfig;
try {
  firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
} catch (e) {
  console.error('Error parsing FIREBASE_CONFIG:', e.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig)
});

const db = admin.firestore();

// ============ Cloudinary ============
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ============ Email Transporter ============
const transporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  }
});

// ============ JWT Helpers ============
const generateToken = (username) => {
  return jwt.sign(
    { username, role: 'admin' },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
};

// ============ Auth Middleware ============
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

// ============ Validation Helpers ============
const validateEmail = (email) => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

const validatePhone = (phone) => {
  return /^[\d+\s-()]{8,20}$/.test(phone);
};

// ============ API Routes ============

// ---------- Auth ----------
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPassword = process.env.ADMIN_PASSWORD;

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
    const snapshot = await db.collection('galleries')
      .orderBy('order', 'asc')
      .get();
    
    const galleries = [];
    snapshot.forEach(doc => {
      galleries.push({ id: doc.id, ...doc.data() });
    });
    
    res.json(galleries);
  } catch (error) {
    console.error('Error fetching galleries:', error);
    res.status(500).json({ error: 'Failed to fetch galleries' });
  }
});

app.post('/api/galleries', requireAuth, async (req, res) => {
  try {
    const { name, description, coverImage, visible, order } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Gallery name is required' });
    }

    const galleryData = {
      name,
      description: description || '',
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

app.put('/api/galleries/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, coverImage, visible, order } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Gallery name is required' });
    }

    const updateData = {
      name,
      description: description || '',
      coverImage: coverImage || '',
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

app.delete('/api/galleries/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if gallery has artworks
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

// ---------- Artworks ----------
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

    query = query.orderBy('order', 'asc');

    const snapshot = await query.get();
    const artworks = [];
    snapshot.forEach(doc => {
      artworks.push({ id: doc.id, ...doc.data() });
    });

    res.json(artworks);
  } catch (error) {
    console.error('Error fetching artworks:', error);
    res.status(500).json({ error: 'Failed to fetch artworks' });
  }
});

app.post('/api/artworks', requireAuth, async (req, res) => {
  try {
    const { 
      galleryId, title, description, imageUrl, cloudinaryPublicId,
      material, dimensions, price, featured, visible, order 
    } = req.body;

    if (!galleryId) {
      return res.status(400).json({ error: 'Gallery ID is required' });
    }

    if (!title) {
      return res.status(400).json({ error: 'Artwork title is required' });
    }

    if (!imageUrl) {
      return res.status(400).json({ error: 'Image URL is required' });
    }

    const artworkData = {
      galleryId,
      title,
      description: description || '',
      imageUrl,
      cloudinaryPublicId: cloudinaryPublicId || '',
      material: material || '',
      dimensions: dimensions || '',
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

app.put('/api/artworks/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      galleryId, title, description, imageUrl, cloudinaryPublicId,
      material, dimensions, price, featured, visible, order 
    } = req.body;

    if (!galleryId) {
      return res.status(400).json({ error: 'Gallery ID is required' });
    }

    if (!title) {
      return res.status(400).json({ error: 'Artwork title is required' });
    }

    if (!imageUrl) {
      return res.status(400).json({ error: 'Image URL is required' });
    }

    const updateData = {
      galleryId,
      title,
      description: description || '',
      imageUrl,
      cloudinaryPublicId: cloudinaryPublicId || '',
      material: material || '',
      dimensions: dimensions || '',
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

app.delete('/api/artworks/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Get artwork to delete cloudinary image if needed
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

// ---------- Cloudinary Upload ----------
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

app.post('/api/upload', requireAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Convert buffer to base64
    const b64 = Buffer.from(req.file.buffer).toString('base64');
    const dataURI = `data:${req.file.mimetype};base64,${b64}`;

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(dataURI, {
      folder: 'shulamith-gallery',
      resource_type: 'auto'
    });

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
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// ---------- Messages ----------
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;

    // Validation
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'Name, email, and message are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (phone && !validatePhone(phone)) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }

    // Save to Firebase
    const messageData = {
      name: name.trim(),
      email: email.trim(),
      phone: phone ? phone.trim() : '',
      message: message.trim(),
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('messages').add(messageData);

    // Send confirmation email
    if (email) {
      try {
        await transporter.sendMail({
          from: `"${process.env.SMTP_FROM_NAME}" <${process.env.SMTP_FROM_EMAIL}>`,
          to: email,
          subject: 'شكراً لتواصلك مع Shulamith Gallery',
          html: `
            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 30px; background: #1a1a1a; color: #e8e0d4; border-radius: 12px;">
              <div style="text-align: center; margin-bottom: 30px;">
                <img src="https://i.postimg.cc/D0rwSp7r/Shulamith-Gallery.jpg" alt="Shulamith Gallery" style="max-width: 150px; height: auto;">
              </div>
              <h2 style="color: #d4b892; margin-bottom: 20px;">مرحباً ${name}،</h2>
              <p style="line-height: 1.8; color: #d4c8b8;">تم استقبال استفساركم وسيتم الرد في أقرب وقت.</p>
              <p style="line-height: 1.8; color: #d4c8b8;">شكراً لتواصلك مع <strong style="color: #d4b892;">Shulamith Gallery</strong>.</p>
              <div style="margin: 30px 0; padding: 20px; background: #252525; border-radius: 8px; border-left: 3px solid #d4b892;">
                <p style="margin: 5px 0; color: #d4c8b8;"><strong style="color: #d4b892;">الرسالة:</strong></p>
                <p style="margin: 10px 0 0 0; color: #e8e0d4; font-style: italic;">${message}</p>
              </div>
              <hr style="border: none; border-top: 1px solid #333; margin: 30px 0;">
              <p style="color: #999; font-size: 14px; text-align: center;">
                © 2026 Shulamith Gallery. All rights reserved.
              </p>
            </div>
          `
        });
      } catch (error) {
        console.error('Error sending email:', error);
        // Don't fail the request if email fails
      }
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

app.get('/api/messages', requireAuth, async (req, res) => {
  try {
    const { unread } = req.query;
    let query = db.collection('messages')
      .orderBy('createdAt', 'desc');

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

    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.put('/api/messages/:id/read', requireAuth, async (req, res) => {
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

app.delete('/api/messages/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('messages').doc(id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// ---------- Settings ----------
app.get('/api/settings', async (req, res) => {
  try {
    const doc = await db.collection('settings').doc('site').get();
    if (doc.exists) {
      res.json({ id: doc.id, ...doc.data() });
    } else {
      // Return default settings
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

app.put('/api/settings', requireAuth, async (req, res) => {
  try {
    const settings = req.body;
    
    // Validate required fields
    const requiredFields = ['siteName', 'logo'];
    for (const field of requiredFields) {
      if (!settings[field]) {
        return res.status(400).json({ error: `${field} is required` });
      }
    }

    // Add timestamps
    settings.updatedAt = admin.firestore.FieldValue.serverTimestamp();

    await db.collection('settings').doc('site').set(settings, { merge: true });
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// ---------- Stats ----------
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [galleriesSnapshot, artworksSnapshot, messagesSnapshot, featuredSnapshot] = await Promise.all([
      db.collection('galleries').get(),
      db.collection('artworks').get(),
      db.collection('messages').get(),
      db.collection('artworks').where('featured', '==', true).get()
    ]);

    const unreadMessages = await db.collection('messages')
      .where('read', '==', false)
      .get();

    res.json({
      galleries: galleriesSnapshot.size,
      artworks: artworksSnapshot.size,
      messages: messagesSnapshot.size,
      featured: featuredSnapshot.size,
      unreadMessages: unreadMessages.size
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ============ Error Handling Middleware ============
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============ Start Server ============
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🚀 Shulamith Gallery Server running on port ${PORT}`);
    console.log(`📊 Dashboard available at http://localhost:${PORT}/dashboard.html`);
    console.log(`🔐 Login at http://localhost:${PORT}/login.html`);
  });
}

module.exports = app;
