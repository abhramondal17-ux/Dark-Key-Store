/**
 * CARROM POOL AUTOPLAY ENGINE STORE - CORE APPLICATION & CUSTOMER PLATFORM
 * Node.js 24.x Serverless Architecture for Vercel
 */

const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const http = require('http');
const https = require('https');

const app = express();

// ==========================================
// ENVIRONMENT CONFIGURATION
// ==========================================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/carrom_store';
const JWT_SECRET = process.env.SESSION_SECRET || 'luffy_super_secret_jwt_vault_key_2026';
const ADMIN_SETUP_SECRET = process.env.ADMIN_SETUP_SECRET || 'SETUP_LUFFY_SECURE_ADMIN_KEY';
const PAYTM_MID = process.env.PAYTM_MID || '';
const PAYTM_MERCHANT_KEY = process.env.PAYTM_MERCHANT_KEY || '';
const PAYTM_WEBSITE = process.env.PAYTM_WEBSITE || 'DEFAULT';
const PAYTM_ENVIRONMENT = process.env.PAYTM_ENVIRONMENT || 'STAGE'; // 'STAGE' or 'PROD'
const APP_BASE_URL = process.env.APP_BASE_URL || 'https://luffyengine.vercel.app';

// ==========================================
// MIDDLEWARES & BODY PARSERS
// ==========================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// ==========================================
// MONGODB CONNECTION CACHING (VERCEL SERVERLESS)
// ==========================================
let cached = global.mongooseConnection;
if (!cached) {
  cached = global.mongooseConnection = { conn: null, promise: null };
}

async function connectToDatabase() {
  if (cached.conn) {
    return cached.conn;
  }
  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
    };
    cached.promise = mongoose.connect(MONGODB_URI, opts).then((m) => m);
  }
  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    throw e;
  }
  return cached.conn;
}

// Ensure DB connection before handling API and views
app.use(async (req, res, next) => {
  try {
    await connectToDatabase();
    next();
  } catch (err) {
    console.error('MongoDB connection failure:', err.message);
    res.status(503).json({
      success: false,
      error: 'Database connection unavailable. Please verify MONGODB_URI.',
    });
  }
});

// ==========================================
// DATABASE SCHEMAS & MODELS
// ==========================================
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  mobile: { type: String, required: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['CUSTOMER', 'SUPER_ADMIN', 'SUPPORT_AGENT'], default: 'CUSTOMER' },
  status: { type: String, enum: ['ACTIVE', 'SUSPENDED'], default: 'ACTIVE' },
  walletBalancePaise: { type: Number, default: 0, min: 0 },
  createdAt: { type: Date, default: Date.now },
});

const ProductSchema = new mongoose.Schema({
  productId: { type: String, required: true, unique: true },
  name: { type: String, required: true, trim: true },
  description: { type: String, default: '' },
  pricePaise: { type: Number, required: true, min: 0 },
  originalPricePaise: { type: Number, default: 0 },
  durationDays: { type: Number, required: true, min: 1 },
  category: { type: String, default: 'Autoplay Engine' },
  imageUrl: { type: String, default: '' },
  deliveryPolicy: { type: String, default: 'Instant digital access key fulfillment' },
  isActive: { type: Boolean, default: true },
  isFeatured: { type: Boolean, default: false },
  sortOrder: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const InventoryKeySchema = new mongoose.Schema({
  keyId: { type: String, required: true, unique: true },
  productId: { type: String, required: true, index: true },
  keySecret: { type: String, required: true, trim: true },
  status: { type: String, enum: ['AVAILABLE', 'ASSIGNED', 'REVOKED'], default: 'AVAILABLE', index: true },
  orderId: { type: String, default: null, index: true },
  assignedToUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  assignedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
});

const OrderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  productId: { type: String, required: true },
  productName: { type: String, required: true },
  amountPaise: { type: Number, required: true },
  paymentMethod: { type: String, enum: ['MANUAL_UPI', 'PAYTM', 'WALLET'], required: true },
  paymentStatus: {
    type: String,
    enum: ['PENDING', 'AWAITING_VERIFICATION', 'PAID', 'FAILED', 'REJECTED', 'REFUNDED'],
    default: 'PENDING',
    index: true,
  },
  orderStatus: {
    type: String,
    enum: ['PROCESSING', 'COMPLETED', 'CANCELLED'],
    default: 'PROCESSING',
    index: true,
  },
  assignedKeySecret: { type: String, default: null },
  assignedKeyId: { type: String, default: null },
  manualUpiTxnRef: { type: String, default: null },
  manualUpiScreenshotUrl: { type: String, default: null },
  paytmOrderId: { type: String, default: null, index: true },
  paytmTxnId: { type: String, default: null },
  adminNotes: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date, default: null },
});

const WalletLedgerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['CREDIT', 'DEBIT'], required: true },
  amountPaise: { type: Number, required: true, min: 1 },
  balanceAfterPaise: { type: Number, required: true },
  reason: { type: String, required: true },
  referenceId: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
});

const SupportTicketSchema = new mongoose.Schema({
  ticketId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  category: { type: String, required: true },
  subject: { type: String, required: true },
  status: { type: String, enum: ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'], default: 'OPEN' },
  messages: [
    {
      sender: { type: String, enum: ['USER', 'STAFF'], required: true },
      senderName: { type: String, required: true },
      message: { type: String, required: true },
      attachmentUrl: { type: String, default: null },
      timestamp: { type: Date, default: Date.now },
    },
  ],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const StoreSettingSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: { type: mongoose.Schema.Types.Mixed, required: true },
});

const AuditLogSchema = new mongoose.Schema({
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  actorEmail: { type: String, default: 'SYSTEM' },
  action: { type: String, required: true },
  target: { type: String, default: '' },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Product = mongoose.models.Product || mongoose.model('Product', ProductSchema);
const InventoryKey = mongoose.models.InventoryKey || mongoose.model('InventoryKey', InventoryKeySchema);
const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);
const WalletLedger = mongoose.models.WalletLedger || mongoose.model('WalletLedger', WalletLedgerSchema);
const SupportTicket = mongoose.models.SupportTicket || mongoose.model('SupportTicket', SupportTicketSchema);
const StoreSetting = mongoose.models.StoreSetting || mongoose.model('StoreSetting', StoreSettingSchema);
const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', AuditLogSchema);

// Share models with admin module
const dbModels = {
  User,
  Product,
  InventoryKey,
  Order,
  WalletLedger,
  SupportTicket,
  StoreSetting,
  AuditLog,
};

// ==========================================
// SYSTEM SETTINGS SEEDER & CACHE
// ==========================================
const DEFAULT_SETTINGS = {
  storeName: 'LUFFY ENGINE STORE',
  tagline: 'Premium Carrom Pool Engine Access',
  currencySymbol: '₹',
  supportTelegram: '@LuffyEngineSupport',
  telegramChannelUrl: 'https://t.me/LuffyEngineUpdates',
  whatsappNumber: '+919000012345',
  supportEmail: 'support@example.com',
  heroHeadline: 'Unlock Your Premium Gaming Experience',
  heroSubtitle: 'Explore verified Carrom Pool autoplay engines, instant key fulfillment, and real-time live support.',
  walletEnabled: true,
  manualUpiEnabled: true,
  upiId: 'merchant@upi',
  upiPayeeName: 'Luffy Engine Store',
  upiQrUrl: 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=upi://pay?pa=merchant@upi%26pn=Luffy%20Engine%20Store%26cu=INR',
  upiInstructions: 'Pay exact amount via any UPI App (GPay/PhonePe/Paytm), take screenshot, and submit 12-digit UTR/Txn ID.',
  paytmEnabled: false,
  termsPolicy: 'Keys are digital items. One key valid per device as specified in duration.',
  refundPolicy: 'Refunds only evaluated if key is verified invalid upon manual support audit within 2 hours.',
  sampleTestimonials: [
    { name: 'Aman Sharma', rating: 5, comment: 'Instant key delivery right after payment! Autoplay precision is 100% smooth.' },
    { name: 'Vikram Joshi', rating: 5, comment: 'Luffy Engine Ultimate 30 days works flawlessly on Android 14. Highly recommended!' }
  ],
  sampleFaqs: [
    { question: 'Is root required for Carrom Pool Autoplay?', answer: 'No root is required. Our engine runs via non-root virtual space or direct overlay apk.' },
    { question: 'How quickly do I receive my access key?', answer: 'Keys are instantly delivered to your account dashboard once payment is confirmed.' }
  ]
};

async function getSetting(key) {
  const row = await StoreSetting.findOne({ key });
  if (row) return row.value;
  return DEFAULT_SETTINGS[key] !== undefined ? DEFAULT_SETTINGS[key] : null;
}

async function getAllSettings() {
  const docs = await StoreSetting.find({});
  const map = { ...DEFAULT_SETTINGS };
  docs.forEach((d) => {
    map[d.key] = d.value;
  });
  return map;
}

// Auto-seed default demonstration catalog if empty
async function seedDefaultCatalog() {
  const count = await Product.countDocuments();
  if (count === 0) {
    const demoCatalog = [
      {
        productId: 'PROD_BASIC_3D',
        name: 'Luffy Engine Basic',
        description: 'Standard precision trajectory guidance. Perfect for weekend tournaments.',
        pricePaise: 19900,
        originalPricePaise: 29900,
        durationDays: 3,
        category: 'Entry Tier',
        imageUrl: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=400&q=80',
        isActive: true,
        isFeatured: false,
        sortOrder: 1,
      },
      {
        productId: 'PROD_PREMIUM_7D',
        name: 'Luffy Engine Premium',
        description: 'High-speed auto-shot line prediction with cushion rebound calculation.',
        pricePaise: 39900,
        originalPricePaise: 59900,
        durationDays: 7,
        category: 'Popular Tier',
        imageUrl: 'https://images.unsplash.com/photo-1634017839464-5c339ebe3cb4?w=400&q=80',
        isActive: true,
        isFeatured: true,
        sortOrder: 2,
      },
      {
        productId: 'PROD_PRO_15D',
        name: 'Luffy Engine Pro',
        description: 'Multi-cushion angle assist, ultra-low latency overlay, zero-lag render.',
        pricePaise: 69900,
        originalPricePaise: 99900,
        durationDays: 15,
        category: 'Pro Tier',
        imageUrl: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=400&q=80',
        isActive: true,
        isFeatured: false,
        sortOrder: 3,
      },
      {
        productId: 'PROD_ULTIMATE_30D',
        name: 'Luffy Engine Ultimate',
        description: 'All VIP features unlocked: Auto-Aim lock, Direct Pocket Assist, 30 days non-stop.',
        pricePaise: 99900,
        originalPricePaise: 149900,
        durationDays: 30,
        category: 'VIP Tier',
        imageUrl: 'https://images.unsplash.com/photo-1634017839464-5c339ebe3cb4?w=400&q=80',
        isActive: true,
        isFeatured: true,
        sortOrder: 4,
      },
    ];
    await Product.insertMany(demoCatalog);
  }
}
seedDefaultCatalog().catch((e) => console.error('Catalog seed error:', e.message));

// ==========================================
// PAYTM BUSINESS INTEGRATION UTILITIES
// ==========================================
const PaytmHelper = {
  generateSignature: function (paramsString, merchantKey) {
    return crypto.createHmac('sha256', merchantKey).update(paramsString).digest('base64');
  },
  verifySignature: function (paramsString, merchantKey, checksumToVerify) {
    const expected = PaytmHelper.generateSignature(paramsString, merchantKey);
    return expected === checksumToVerify;
  },
  initiateTransaction: async function (orderId, amountPaise, customerId) {
    if (!PAYTM_MID || !PAYTM_MERCHANT_KEY) {
      throw new Error('Paytm merchant credentials are not configured.');
    }
    const paytmParams = {
      body: {
        requestType: 'Payment',
        mid: PAYTM_MID,
        websiteName: PAYTM_WEBSITE,
        orderId: orderId,
        callbackUrl: `${APP_BASE_URL}/api/payments/paytm/callback`,
        txnAmount: {
          value: (amountPaise / 100).toFixed(2),
          currency: 'INR',
        },
        userInfo: {
          custId: customerId.toString(),
        },
      },
    };

    const bodyString = JSON.stringify(paytmParams.body);
    const checksum = PaytmHelper.generateSignature(bodyString, PAYTM_MERCHANT_KEY);

    paytmParams.head = {
      signature: checksum,
    };

    const host = PAYTM_ENVIRONMENT === 'PROD' ? 'securegw.paytm.in' : 'securegw-stage.paytm.in';
    const path = `/theia/api/v1/initiateTransaction?mid=${PAYTM_MID}&orderId=${orderId}`;

    return new Promise((resolve, reject) => {
      const postData = JSON.stringify(paytmParams);
      const req = https.request(
        {
          hostname: host,
          port: 443,
          path: path,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
        },
        (res) => {
          let responseData = '';
          res.on('data', (chunk) => (responseData += chunk));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(responseData);
              resolve(parsed);
            } catch (err) {
              reject(new Error('Invalid response from Paytm Gateway: ' + responseData));
            }
          });
        }
      );
      req.on('error', (err) => reject(err));
      req.write(postData);
      req.end();
    });
  },
};

// ==========================================
// AUTHENTICATION MIDDLEWARES
// ==========================================
function authenticateToken(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    req.user = null;
    next();
  }
}

function requireAuth(req, res, next) {
  authenticateToken(req, res, () => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Authentication required. Please log in.' });
    }
    next();
  });
}

// ==========================================
// ATOMIC INVENTORY FULFILLMENT HELPER
// ==========================================
async function fulfillOrderWithKey(orderDoc, session = null) {
  // Prevent double fulfillment
  if (orderDoc.orderStatus === 'COMPLETED' && orderDoc.assignedKeySecret) {
    return orderDoc;
  }

  // Atomically pick one AVAILABLE key matching product
  const query = { productId: orderDoc.productId, status: 'AVAILABLE' };
  const update = {
    $set: {
      status: 'ASSIGNED',
      orderId: orderDoc.orderId,
      assignedToUser: orderDoc.userId,
      assignedAt: new Date(),
    },
  };

  const keyDoc = await InventoryKey.findOneAndUpdate(query, update, { new: true, session });

  if (!keyDoc) {
    // Inventory exhaustion fallback
    orderDoc.paymentStatus = 'PAID';
    orderDoc.orderStatus = 'PROCESSING';
    orderDoc.adminNotes = 'Payment verified, but key stock is exhausted. Needs admin manual key assignment.';
    await orderDoc.save({ session });
    return orderDoc;
  }

  orderDoc.paymentStatus = 'PAID';
  orderDoc.orderStatus = 'COMPLETED';
  orderDoc.assignedKeyId = keyDoc.keyId;
  orderDoc.assignedKeySecret = keyDoc.keySecret;
  orderDoc.completedAt = new Date();
  await orderDoc.save({ session });

  return orderDoc;
}

// Attach auth parsing to all routes
app.use(authenticateToken);

// ==========================================
// CUSTOMER & PUBLIC API ENDPOINTS
// ==========================================

// 1. Get Store Public Settings
app.get('/api/settings', async (req, res) => {
  try {
    const settings = await getAllSettings();
    // Strip sensitive details
    delete settings.paytmMerchantKey;
    res.json({ success: true, settings });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. Auth: Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, mobile, password, confirmPassword } = req.body;
    if (!fullName || !email || !mobile || !password) {
      return res.status(400).json({ success: false, error: 'All fields are required.' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Passwords do not match.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters.' });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ success: false, error: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
      fullName: fullName.trim(),
      email: email.toLowerCase().trim(),
      mobile: mobile.trim(),
      passwordHash,
      role: 'CUSTOMER',
    });
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 86400 * 1000 });

    res.json({
      success: true,
      user: { id: user._id, fullName: user.fullName, email: user.email, role: user.role, walletBalancePaise: user.walletBalancePaise },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. Auth: Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid email or password.' });
    }
    if (user.status === 'SUSPENDED') {
      return res.status(403).json({ success: false, error: 'Account suspended. Please contact customer support.' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 86400 * 1000 });

    res.json({
      success: true,
      user: { id: user._id, fullName: user.fullName, email: user.email, role: user.role, walletBalancePaise: user.walletBalancePaise },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. Auth: Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// 5. Auth: Get Current User Profile & Wallet
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. Public Product List with live available stock counts
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ isActive: true }).sort({ sortOrder: 1, createdAt: 1 }).lean();
    // Add real-time available stock count per product
    for (let p of products) {
      p.stockCount = await InventoryKey.countDocuments({ productId: p.productId, status: 'AVAILABLE' });
    }
    res.json({ success: true, products });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 7. Order Initiation & Checkout
app.post('/api/orders/create', requireAuth, async (req, res) => {
  try {
    const { productId, paymentMethod } = req.body;
    if (!productId || !paymentMethod) {
      return res.status(400).json({ success: false, error: 'Product ID and payment method are required.' });
    }

    const product = await Product.findOne({ productId, isActive: true });
    if (!product) {
      return res.status(404).json({ success: false, error: 'Selected product is unavailable or inactive.' });
    }

    const orderId = 'ORD_' + Date.now() + '_' + Math.floor(1000 + Math.random() * 9000);

    // Flow A: WALLET PAYMENT
    if (paymentMethod === 'WALLET') {
      const isWalletActive = await getSetting('walletEnabled');
      if (!isWalletActive) {
        return res.status(400).json({ success: false, error: 'Wallet payments are currently disabled.' });
      }

      const user = await User.findById(req.user.id);
      if (user.walletBalancePaise < product.pricePaise) {
        return res.status(400).json({ success: false, error: 'Insufficient wallet balance. Please add funds or pay via UPI.' });
      }

      // Check stock before debiting wallet
      const stock = await InventoryKey.countDocuments({ productId, status: 'AVAILABLE' });
      if (stock <= 0) {
        return res.status(400).json({ success: false, error: 'Product currently out of stock.' });
      }

      // Atomic balance deduction
      const updatedUser = await User.findOneAndUpdate(
        { _id: user._id, walletBalancePaise: { $gte: product.pricePaise } },
        { $inc: { walletBalancePaise: -product.pricePaise } },
        { new: true }
      );
      if (!updatedUser) {
        return res.status(400).json({ success: false, error: 'Balance deduction conflict. Please retry.' });
      }

      // Record wallet ledger
      await WalletLedger.create({
        userId: user._id,
        type: 'DEBIT',
        amountPaise: product.pricePaise,
        balanceAfterPaise: updatedUser.walletBalancePaise,
        reason: `Purchase ${product.name} (Order: ${orderId})`,
        referenceId: orderId,
      });

      const order = new Order({
        orderId,
        userId: user._id,
        productId: product.productId,
        productName: product.name,
        amountPaise: product.pricePaise,
        paymentMethod: 'WALLET',
        paymentStatus: 'PAID',
      });
      await order.save();

      // Fulfill key atomically
      const fulfilledOrder = await fulfillOrderWithKey(order);
      return res.json({ success: true, orderId: fulfilledOrder.orderId, status: fulfilledOrder.orderStatus });
    }

    // Flow B: MANUAL UPI
    if (paymentMethod === 'MANUAL_UPI') {
      const order = new Order({
        orderId,
        userId: req.user.id,
        productId: product.productId,
        productName: product.name,
        amountPaise: product.pricePaise,
        paymentMethod: 'MANUAL_UPI',
        paymentStatus: 'AWAITING_VERIFICATION',
        orderStatus: 'PROCESSING',
      });
      await order.save();
      return res.json({ success: true, orderId: order.orderId, amountPaise: order.amountPaise });
    }

    // Flow C: PAYTM GATEWAY
    if (paymentMethod === 'PAYTM') {
      const isPaytmActive = await getSetting('paytmEnabled');
      if (!isPaytmActive || !PAYTM_MID || !PAYTM_MERCHANT_KEY) {
        return res.status(400).json({ success: false, error: 'Paytm Business Gateway is not currently configured.' });
      }

      const order = new Order({
        orderId,
        userId: req.user.id,
        productId: product.productId,
        productName: product.name,
        amountPaise: product.pricePaise,
        paymentMethod: 'PAYTM',
        paymentStatus: 'PENDING',
        orderStatus: 'PROCESSING',
      });
      await order.save();

      const paytmRes = await PaytmHelper.initiateTransaction(orderId, product.pricePaise, req.user.id);
      if (paytmRes.body && paytmRes.body.resultInfo && paytmRes.body.resultInfo.resultStatus === 'S') {
        return res.json({
          success: true,
          orderId,
          txnToken: paytmRes.body.txnToken,
          mid: PAYTM_MID,
          amount: (product.pricePaise / 100).toFixed(2),
        });
      } else {
        return res.status(500).json({
          success: false,
          error: paytmRes.body?.resultInfo?.resultMsg || 'Failed to initiate Paytm transaction.',
        });
      }
    }

    return res.status(400).json({ success: false, error: 'Unsupported payment method.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 8. Submit Manual UPI Verification Details (UTR / Screenshot)
app.post('/api/orders/submit-manual-proof', requireAuth, async (req, res) => {
  try {
    const { orderId, utrNumber, screenshotUrl } = req.body;
    if (!orderId || !utrNumber) {
      return res.status(400).json({ success: false, error: 'Order ID and 12-digit UTR/Txn ID required.' });
    }

    const order = await Order.findOne({ orderId, userId: req.user.id });
    if (!order) return res.status(404).json({ success: false, error: 'Order not found.' });

    order.manualUpiTxnRef = utrNumber.trim();
    if (screenshotUrl) order.manualUpiScreenshotUrl = screenshotUrl;
    order.paymentStatus = 'AWAITING_VERIFICATION';
    await order.save();

    res.json({ success: true, message: 'Payment reference submitted. Verification in progress.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 9. Paytm Gateway Callback & Webhook Verification
app.post('/api/payments/paytm/callback', async (req, res) => {
  try {
    const paytmResponse = req.body;
    const { ORDERID, STATUS, CHECKSUMHASH, TXNAMOUNT, TXNID } = paytmResponse;

    if (!ORDERID) {
      return res.status(400).send('Malformed Paytm callback request.');
    }

    const order = await Order.findOne({ orderId: ORDERID });
    if (!order) {
      return res.status(404).send('Associated Order Not Found.');
    }

    // Verify Checksum
    const paytmParamsCopy = { ...paytmResponse };
    delete paytmParamsCopy.CHECKSUMHASH;

    let isValidChecksum = false;
    try {
      isValidChecksum = PaytmHelper.verifySignature(JSON.stringify(paytmParamsCopy), PAYTM_MERCHANT_KEY, CHECKSUMHASH);
    } catch (e) {
      isValidChecksum = false;
    }

    // If sandbox testing or signature verified
    if (STATUS === 'TXN_SUCCESS' && (isValidChecksum || PAYTM_ENVIRONMENT === 'STAGE')) {
      const paidPaise = Math.round(parseFloat(TXNAMOUNT) * 100);
      if (paidPaise === order.amountPaise) {
        order.paytmTxnId = TXNID;
        await fulfillOrderWithKey(order);
      } else {
        order.paymentStatus = 'FAILED';
        order.adminNotes = `Payment amount mismatch: Expected ${order.amountPaise} paise, received ${paidPaise} paise.`;
        await order.save();
      }
    } else {
      order.paymentStatus = 'FAILED';
      order.adminNotes = `Paytm status: ${STATUS}`;
      await order.save();
    }

    // Redirect user to customer panel order view
    return res.redirect(`/#orders`);
  } catch (err) {
    console.error('Paytm callback failure:', err);
    res.status(500).send('Paytm callback processing error.');
  }
});

// 10. Customer Order History
app.get('/api/orders/my-orders', requireAuth, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json({ success: true, orders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 11. Customer Key Access (Only if order is PAID/COMPLETED)
app.get('/api/keys/my-key/:orderId', requireAuth, async (req, res) => {
  try {
    const order = await Order.findOne({ orderId: req.params.orderId, userId: req.user.id });
    if (!order) {
      return res.status(404).json({ success: false, error: 'Order not found.' });
    }
    if (order.orderStatus !== 'COMPLETED' || !order.assignedKeySecret) {
      return res.status(403).json({
        success: false,
        error: 'Key unavailable. Order must be fully verified and completed.',
      });
    }
    res.json({
      success: true,
      productName: order.productName,
      keySecret: order.assignedKeySecret,
      completedAt: order.completedAt,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 12. Support System: Create Ticket
app.post('/api/support/tickets', requireAuth, async (req, res) => {
  try {
    const { category, subject, message } = req.body;
    if (!category || !subject || !message) {
      return res.status(400).json({ success: false, error: 'Category, subject, and message are required.' });
    }

    const ticketId = 'TCK_' + Math.floor(100000 + Math.random() * 900000);
    const user = await User.findById(req.user.id);

    const ticket = new SupportTicket({
      ticketId,
      userId: user._id,
      category,
      subject,
      messages: [
        {
          sender: 'USER',
          senderName: user.fullName,
          message: message.trim(),
        },
      ],
    });
    await ticket.save();

    res.json({ success: true, ticket });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 13. Support System: Get User Tickets
app.get('/api/support/tickets', requireAuth, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user.id }).sort({ updatedAt: -1 });
    res.json({ success: true, tickets });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 14. Support System: Reply to Ticket
app.post('/api/support/tickets/:ticketId/reply', requireAuth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ success: false, error: 'Message cannot be empty.' });

    const ticket = await SupportTicket.findOne({ ticketId: req.params.ticketId, userId: req.user.id });
    if (!ticket) return res.status(404).json({ success: false, error: 'Ticket not found.' });

    const user = await User.findById(req.user.id);
    ticket.messages.push({
      sender: 'USER',
      senderName: user.fullName,
      message: message.trim(),
    });
    ticket.status = 'OPEN';
    ticket.updatedAt = new Date();
    await ticket.save();

    res.json({ success: true, ticket });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==========================================
// MOUNT ADMIN APPLICATION & API ROUTES
// ==========================================
const adminApp = require('./admin');
app.use('/admin', adminApp.createAdminRouter({ dbModels, fulfillOrderWithKey, ADMIN_SETUP_SECRET, JWT_SECRET }));

// ==========================================
// FRONTEND SINGLE-PAGE CLAYMORPHISM UI
// ==========================================
app.get('*', async (req, res) => {
  // If request is directed to /admin, let next() or admin router handle it
  if (req.path.startsWith('/admin')) {
    return;
  }

  const settings = await getAllSettings();

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>${settings.storeName} — ${settings.tagline}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #141b2d;
      --clay-surface: linear-gradient(145deg, #182239, #0f1523);
      --clay-btn: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
      --clay-accent: #7f00ff;
      --cyan: #00f2fe;
      --neon-orange: #ff5858;
      --text: #f0f4fc;
      --text-muted: #8b9bb4;
      --clay-shadow: 10px 10px 20px #06090f, -6px -6px 14px rgba(255,255,255,0.03);
      --clay-inset: inset 2px 2px 4px rgba(255,255,255,0.08), inset -2px -2px 4px rgba(0,0,0,0.5);
      --radius: 20px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; -webkit-tap-highlight-color: transparent; }
    body { background-color: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; padding-bottom: 90px; }

    /* CLAYMORPHIC ELEMENTS */
    .clay-box {
      background: var(--clay-surface);
      border-radius: var(--radius);
      box-shadow: var(--clay-shadow);
      border: 1px solid rgba(255,255,255,0.05);
      position: relative;
    }
    .clay-btn {
      background: var(--clay-btn);
      color: #0b0f19;
      font-weight: 700;
      border: none;
      border-radius: 14px;
      padding: 12px 24px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 8px 18px rgba(0,242,254,0.3);
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      text-decoration: none;
    }
    .clay-btn:active { transform: scale(0.97); }
    .clay-btn-secondary {
      background: #1a233a;
      color: var(--text);
      box-shadow: var(--clay-shadow);
      border: 1px solid rgba(255,255,255,0.1);
    }

    /* TOP NAVBAR */
    .navbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 24px;
      background: rgba(15, 21, 35, 0.85);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
      z-index: 100;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 1.25rem; letter-spacing: -0.5px; }
    .brand-icon {
      width: 38px; height: 38px; border-radius: 12px;
      background: linear-gradient(135deg, #00f2fe, #7f00ff);
      display: grid; place-items: center; font-size: 1.2rem;
    }

    /* CONTAINER */
    .container { max-width: 1100px; margin: 0 auto; padding: 20px; }

    /* HERO */
    .hero {
      text-align: center;
      padding: 40px 20px;
      position: relative;
    }
    .hero-badge {
      display: inline-block;
      padding: 6px 14px;
      border-radius: 30px;
      background: rgba(0,242,254,0.1);
      color: var(--cyan);
      font-size: 0.8rem;
      font-weight: 700;
      margin-bottom: 16px;
      border: 1px solid rgba(0,242,254,0.3);
    }
    .hero h1 { font-size: 2.3rem; font-weight: 800; line-height: 1.2; margin-bottom: 14px; }
    .hero p { color: var(--text-muted); font-size: 1rem; max-width: 600px; margin: 0 auto 26px auto; }

    /* PRODUCT GRID */
    .section-title { font-size: 1.5rem; font-weight: 800; margin: 30px 0 20px 0; display: flex; align-items: center; gap: 10px; }
    .product-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
    .product-card {
      padding: 24px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: transform 0.2s;
    }
    .product-card:hover { transform: translateY(-4px); }
    .product-badge {
      position: absolute;
      top: 16px; right: 16px;
      background: rgba(255,88,88,0.2);
      color: var(--neon-orange);
      padding: 4px 10px;
      border-radius: 8px;
      font-size: 0.75rem;
      font-weight: 700;
      border: 1px solid rgba(255,88,88,0.3);
    }
    .product-img { width: 100%; height: 160px; object-fit: cover; border-radius: 14px; margin-bottom: 16px; }
    .price-tag { font-size: 1.8rem; font-weight: 800; color: var(--cyan); margin: 12px 0; }
    .original-price { font-size: 1rem; color: var(--text-muted); text-decoration: line-through; margin-left: 8px; font-weight: 400; }

    /* MOBILE DOCKED NAVIGATION */
    .dock {
      position: fixed;
      bottom: 14px;
      left: 50%;
      transform: translateX(-50%);
      width: calc(100% - 32px);
      max-width: 500px;
      background: rgba(18, 25, 42, 0.95);
      backdrop-filter: blur(16px);
      border-radius: 22px;
      display: flex;
      justify-content: space-around;
      padding: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.8), inset 1px 1px 2px rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.08);
      z-index: 999;
    }
    .dock-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
    }
    .dock-item.active, .dock-item:hover { color: var(--cyan); }
    .dock-icon { font-size: 1.25rem; }

    /* MODAL WINDOWS */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(4, 7, 13, 0.8);
      backdrop-filter: blur(6px);
      z-index: 1000;
      display: none;
      place-items: center;
      padding: 16px;
    }
    .modal-backdrop.active { display: grid; }
    .modal-card { width: 100%; max-width: 460px; padding: 28px; }

    /* FORMS & INPUTS */
    .form-group { margin-bottom: 16px; }
    .form-label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 6px; color: var(--text-muted); }
    .form-input {
      width: 100%;
      padding: 14px 16px;
      border-radius: 12px;
      background: #0d121e;
      border: 1px solid rgba(255,255,255,0.1);
      color: var(--text);
      font-size: 0.95rem;
      box-shadow: var(--clay-inset);
      outline: none;
    }
    .form-input:focus { border-color: var(--cyan); }

    /* KEY DISPLAY COMPONENT */
    .key-badge {
      background: #0d121e;
      padding: 14px;
      border-radius: 12px;
      font-family: monospace;
      color: var(--cyan);
      font-weight: 700;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--clay-inset);
      border: 1px dashed rgba(0,242,254,0.3);
      word-break: break-all;
    }

    /* TOAST ALERTS */
    .toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
    .toast {
      padding: 14px 20px; border-radius: 12px; background: #1c263d;
      color: #fff; font-size: 0.9rem; font-weight: 600; box-shadow: 0 10px 24px rgba(0,0,0,0.5);
      border-left: 4px solid var(--cyan); animation: slideIn 0.25s ease-out;
    }
    @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
  </style>
</head>
<body>

  <div class="toast-container" id="toastContainer"></div>

  <!-- NAVBAR -->
  <header class="navbar">
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <span id="navStoreName">${settings.storeName}</span>
    </div>
    <div id="navUserSlot">
      <button class="clay-btn" style="padding: 8px 16px; font-size: 0.85rem;" onclick="openAuthModal()">Login / Sign Up</button>
    </div>
  </header>

  <!-- MAIN VIEW CONTAINER -->
  <main class="container" id="appRoot">
    <!-- HERO SECTION -->
    <section class="hero">
      <div class="hero-badge">CARROM POOL AUTOPLAY v5.4 COMPATIBLE</div>
      <h1>${settings.heroHeadline}</h1>
      <p>${settings.heroSubtitle}</p>
      <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
        <a href="#products" class="clay-btn">Explore Engines 🎯</a>
        <a href="#orders" class="clay-btn clay-btn-secondary">My Purchased Keys 🔑</a>
      </div>
    </section>

    <!-- PRODUCT CATALOG -->
    <section id="products">
      <div class="section-title">
        <span>🔥</span> Available Engine Subscriptions
      </div>
      <div class="product-grid" id="productGrid">
        <div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--text-muted);">
          Loading engine catalog...
        </div>
      </div>
    </section>

    <!-- CUSTOMER ORDERS & KEYS VIEW -->
    <section id="ordersView" style="display: none; margin-top: 40px;">
      <div class="section-title">
        <span>🔑</span> My Keys & Order History
      </div>
      <div id="ordersList" style="display: flex; flex-direction: column; gap: 16px;">
        <!-- Dynamic Orders populated by JS -->
      </div>
    </section>

    <!-- SUPPORT TICKETS VIEW -->
    <section id="supportView" style="display: none; margin-top: 40px;">
      <div class="section-title">
        <span>💬</span> Customer Support Tickets
      </div>
      <div class="clay-box" style="padding: 24px; margin-bottom: 24px;">
        <h3 style="margin-bottom: 14px;">Open a New Support Ticket</h3>
        <div class="form-group">
          <label class="form-label">Issue Category</label>
          <select id="ticketCategory" class="form-input">
            <option value="Key Delivery Issue">Key Delivery Issue</option>
            <option value="Manual UPI Payment Proof">Manual UPI Payment Proof</option>
            <option value="Engine Crash or Technical Issue">Engine Crash or Technical Issue</option>
            <option value="General Inquiry">General Inquiry</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Subject</label>
          <input type="text" id="ticketSubject" class="form-input" placeholder="e.g. UTR verified but key pending">
        </div>
        <div class="form-group">
          <label class="form-label">Detailed Message</label>
          <textarea id="ticketMessage" class="form-input" rows="3" placeholder="Provide order ID or description of problem..."></textarea>
        </div>
        <button class="clay-btn" onclick="submitTicket()">Submit Support Ticket</button>
      </div>
      <div id="ticketList" style="display: flex; flex-direction: column; gap: 16px;"></div>
    </section>
  </main>

  <!-- MOBILE BOTTOM DOCK -->
  <nav class="dock">
    <div class="dock-item active" onclick="switchTab('store')">
      <div class="dock-icon">🛍️</div>
      <span>Store</span>
    </div>
    <div class="dock-item" onclick="switchTab('orders')">
      <div class="dock-icon">🔑</div>
      <span>My Keys</span>
    </div>
    <div class="dock-item" onclick="switchTab('support')">
      <div class="dock-icon">💬</div>
      <span>Support</span>
    </div>
    <div class="dock-item" onclick="switchTab('profile')">
      <div class="dock-icon">👤</div>
      <span>Profile</span>
    </div>
  </nav>

  <!-- MODAL: AUTHENTICATION -->
  <div class="modal-backdrop" id="authModal">
    <div class="clay-box modal-card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <h2 id="authModalTitle">Sign In</h2>
        <span style="cursor:pointer; font-size:1.5rem;" onclick="closeModal('authModal')">✕</span>
      </div>
      <div id="authError" style="color:var(--neon-orange); font-size:0.85rem; margin-bottom:12px; display:none;"></div>
      
      <div id="registerFields" style="display:none;">
        <div class="form-group">
          <label class="form-label">Full Name</label>
          <input type="text" id="regName" class="form-input" placeholder="Alex Morgan">
        </div>
        <div class="form-group">
          <label class="form-label">Mobile Number</label>
          <input type="text" id="regMobile" class="form-input" placeholder="10-digit number">
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Email Address</label>
        <input type="email" id="authEmail" class="form-input" placeholder="you@domain.com">
      </div>
      <div class="form-group">
        <label class="form-label">Password</label>
        <input type="password" id="authPassword" class="form-input" placeholder="••••••••">
      </div>

      <div id="confirmPassField" style="display:none;" class="form-group">
        <label class="form-label">Confirm Password</label>
        <input type="password" id="regConfirmPassword" class="form-input" placeholder="••••••••">
      </div>

      <button class="clay-btn" style="width:100%; margin-top:10px;" id="authSubmitBtn" onclick="submitAuth()">Login</button>
      
      <p style="text-align:center; font-size:0.85rem; color:var(--text-muted); margin-top:16px;">
        <span id="authToggleText">Don't have an account?</span>
        <a href="javascript:void(0)" id="authToggleLink" onclick="toggleAuthMode()" style="color:var(--cyan); font-weight:700; text-decoration:none;">Sign Up</a>
      </p>
    </div>
  </div>

  <!-- MODAL: CHECKOUT & PAYMENT -->
  <div class="modal-backdrop" id="checkoutModal">
    <div class="clay-box modal-card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <h3>Complete Purchase</h3>
        <span style="cursor:pointer; font-size:1.5rem;" onclick="closeModal('checkoutModal')">✕</span>
      </div>
      <div id="checkoutProductSummary" style="margin-bottom:16px;"></div>

      <div class="form-group">
        <label class="form-label">Select Payment Method</label>
        <select id="checkoutMethod" class="form-input" onchange="togglePaymentMethodView()">
          <option value="MANUAL_UPI">Manual UPI (GooglePay / PhonePe / QR)</option>
          <option value="WALLET">Luffy Store Wallet</option>
          <option value="PAYTM">Paytm Business Gateway</option>
        </select>
      </div>

      <!-- MANUAL UPI INSTRUCTIONS & PROOF BOX -->
      <div id="manualUpiPanel" style="display:block; background:#0d121e; padding:16px; border-radius:14px; margin-bottom:16px;">
        <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">Scan QR or pay to UPI ID:</p>
        <div style="text-align:center; margin-bottom:12px;">
          <img src="${settings.upiQrUrl}" alt="UPI QR" style="width:160px; height:160px; border-radius:12px; background:#fff; padding:6px;">
          <div style="font-weight:700; color:var(--cyan); margin-top:8px;">${settings.upiId}</div>
          <div style="font-size:0.8rem; color:var(--text-muted);">${settings.upiPayeeName}</div>
        </div>
        <div class="form-group">
          <label class="form-label">Enter 12-Digit UPI Ref / UTR</label>
          <input type="text" id="manualUtrInput" class="form-input" placeholder="e.g. 408123456789">
        </div>
      </div>

      <button class="clay-btn" style="width:100%;" onclick="executeOrder()">Pay & Place Order</button>
    </div>
  </div>

  <script>
    // GLOBAL STATE
    let currentUser = null;
    let productsCache = [];
    let activeCheckoutProduct = null;
    let isRegisterMode = false;

    function showToast(msg) {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerText = msg;
      container.appendChild(toast);
      setTimeout(() => toast.remove(), 4000);
    }

    function openModal(id) { document.getElementById(id).classList.add('active'); }
    function closeModal(id) { document.getElementById(id).classList.remove('active'); }

    // AUTH TOGGLING
    function toggleAuthMode() {
      isRegisterMode = !isRegisterMode;
      document.getElementById('authModalTitle').innerText = isRegisterMode ? 'Create Account' : 'Sign In';
      document.getElementById('registerFields').style.display = isRegisterMode ? 'block' : 'none';
      document.getElementById('confirmPassField').style.display = isRegisterMode ? 'block' : 'none';
      document.getElementById('authSubmitBtn').innerText = isRegisterMode ? 'Register Now' : 'Login';
      document.getElementById('authToggleText').innerText = isRegisterMode ? 'Already have an account?' : "Don't have an account?";
      document.getElementById('authToggleLink').innerText = isRegisterMode ? 'Sign In' : 'Sign Up';
    }

    function openAuthModal() {
      isRegisterMode = false;
      toggleAuthMode(); // sets to login
      openModal('authModal');
    }

    async function submitAuth() {
      const email = document.getElementById('authEmail').value;
      const password = document.getElementById('authPassword').value;
      const endpoint = isRegisterMode ? '/api/auth/register' : '/api/auth/login';

      const payload = { email, password };
      if (isRegisterMode) {
        payload.fullName = document.getElementById('regName').value;
        payload.mobile = document.getElementById('regMobile').value;
        payload.confirmPassword = document.getElementById('regConfirmPassword').value;
      }

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!data.success) {
          const errDiv = document.getElementById('authError');
          errDiv.innerText = data.error;
          errDiv.style.display = 'block';
          return;
        }
        closeModal('authModal');
        showToast('Welcome back, ' + data.user.fullName);
        checkSession();
      } catch (err) {
        showToast('Network error during authentication.');
      }
    }

    async function checkSession() {
      try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        if (data.success && data.user) {
          currentUser = data.user;
          const walletFormatted = (currentUser.walletBalancePaise / 100).toFixed(2);
          document.getElementById('navUserSlot').innerHTML = \`
            <div style="display:flex; align-items:center; gap:12px;">
              <span style="font-size:0.85rem; font-weight:700; color:var(--cyan);">₹\${walletFormatted}</span>
              <button class="clay-btn clay-btn-secondary" style="padding: 6px 12px; font-size:0.8rem;" onclick="logout()">Logout</button>
            </div>
          \`;
        } else {
          currentUser = null;
          document.getElementById('navUserSlot').innerHTML = \`
            <button class="clay-btn" style="padding: 8px 16px; font-size: 0.85rem;" onclick="openAuthModal()">Login / Sign Up</button>
          \`;
        }
      } catch (e) {
        currentUser = null;
      }
    }

    async function logout() {
      await fetch('/api/auth/logout', { method: 'POST' });
      currentUser = null;
      checkSession();
      showToast('Logged out.');
      switchTab('store');
    }

    // LOAD CATALOG
    async function loadProducts() {
      try {
        const res = await fetch('/api/products');
        const data = await res.json();
        if (data.success) {
          productsCache = data.products;
          renderProductGrid();
        }
      } catch (e) {
        showToast('Error loading store catalog.');
      }
    }

    function renderProductGrid() {
      const container = document.getElementById('productGrid');
      if (productsCache.length === 0) {
        container.innerHTML = '<div style="grid-column:1/-1; text-align:center; padding:30px;">No engines currently active.</div>';
        return;
      }

      container.innerHTML = productsCache.map(p => {
        const price = (p.pricePaise / 100).toFixed(0);
        const originalPrice = p.originalPricePaise ? (p.originalPricePaise / 100).toFixed(0) : null;
        const stockStatus = p.stockCount > 0 
          ? \`<span style="color:#00f2fe; font-size:0.8rem; font-weight:700;">🟢 \${p.stockCount} Keys In Stock</span>\`
          : \`<span style="color:var(--neon-orange); font-size:0.8rem; font-weight:700;">🔴 Out of Stock</span>\`;

        return \`
          <div class="clay-box product-card">
            \${p.isFeatured ? '<div class="product-badge">POPULAR CHOICE</div>' : ''}
            <img src="\${p.imageUrl || 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=400&q=80'}" class="product-img" alt="\${p.name}">
            <div>
              <div style="font-size:0.8rem; color:var(--text-muted); text-transform:uppercase; font-weight:700;">\${p.category} • \${p.durationDays} Days</div>
              <h3 style="margin: 6px 0; font-size: 1.25rem;">\${p.name}</h3>
              <p style="font-size:0.85rem; color:var(--text-muted); line-height:1.4;">\${p.description}</p>
            </div>
            <div>
              <div class="price-tag">
                ₹\${price}
                \${originalPrice ? \`<span class="original-price">₹\${originalPrice}</span>\` : ''}
              </div>
              <div style="margin-bottom:12px;">\${stockStatus}</div>
              <button class="clay-btn" style="width: 100%;" onclick="initiateCheckout('\${p.productId}')" \${p.stockCount <= 0 ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>
                \${p.stockCount > 0 ? 'Buy Access Key ⚡' : 'Sold Out'}
              </button>
            </div>
          </div>
        \`;
      }).join('');
    }

    // CHECKOUT LOGIC
    function initiateCheckout(productId) {
      if (!currentUser) {
        showToast('Please sign in or register to purchase.');
        openAuthModal();
        return;
      }
      activeCheckoutProduct = productsCache.find(p => p.productId === productId);
      if (!activeCheckoutProduct) return;

      document.getElementById('checkoutProductSummary').innerHTML = \`
        <div style="background:#0d121e; padding:12px; border-radius:12px;">
          <div style="font-weight:700;">\${activeCheckoutProduct.name}</div>
          <div style="color:var(--cyan); font-weight:800; font-size:1.1rem; margin-top:4px;">
            Payable: ₹\${(activeCheckoutProduct.pricePaise / 100).toFixed(2)}
          </div>
        </div>
      \`;
      openModal('checkoutModal');
    }

    function togglePaymentMethodView() {
      const method = document.getElementById('checkoutMethod').value;
      document.getElementById('manualUpiPanel').style.display = method === 'MANUAL_UPI' ? 'block' : 'none';
    }

    async function executeOrder() {
      const paymentMethod = document.getElementById('checkoutMethod').value;
      const utrNumber = document.getElementById('manualUtrInput').value;

      if (paymentMethod === 'MANUAL_UPI' && !utrNumber.trim()) {
        showToast('Please enter the 12-digit UPI UTR / Transaction reference.');
        return;
      }

      try {
        const res = await fetch('/api/orders/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ productId: activeCheckoutProduct.productId, paymentMethod })
        });
        const data = await res.json();
        if (!data.success) {
          showToast(data.error);
          return;
        }

        // Handle Manual UPI reference submission
        if (paymentMethod === 'MANUAL_UPI') {
          await fetch('/api/orders/submit-manual-proof', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ orderId: data.orderId, utrNumber })
          });
          closeModal('checkoutModal');
          showToast('Payment submitted for manual approval! Check My Keys tab.');
          switchTab('orders');
          loadOrders();
          return;
        }

        // Handle Wallet Instant Fulfillment
        if (paymentMethod === 'WALLET') {
          closeModal('checkoutModal');
          showToast('Purchase completed using wallet balance!');
          checkSession();
          switchTab('orders');
          loadOrders();
          return;
        }

        // Handle Paytm Gateway
        if (paymentMethod === 'PAYTM') {
          showToast('Redirecting to Paytm Gateway...');
          // Trigger standard Paytm Checkout Form
        }

      } catch (err) {
        showToast('Checkout transaction failed.');
      }
    }

    // MY ORDERS & KEYS VIEW
    async function loadOrders() {
      if (!currentUser) return;
      try {
        const res = await fetch('/api/orders/my-orders');
        const data = await res.json();
        const listDiv = document.getElementById('ordersList');

        if (!data.success || data.orders.length === 0) {
          listDiv.innerHTML = '<div style="text-align:center; padding:30px; color:var(--text-muted);">No orders found.</div>';
          return;
        }

        listDiv.innerHTML = data.orders.map(o => {
          let statusBadge = '';
          if (o.orderStatus === 'COMPLETED') {
            statusBadge = '<span style="color:#00f2fe; font-weight:700;">● COMPLETED</span>';
          } else if (o.paymentStatus === 'AWAITING_VERIFICATION') {
            statusBadge = '<span style="color:#ffaa00; font-weight:700;">● VERIFICATION PENDING</span>';
          } else {
            statusBadge = \`<span style="color:var(--neon-orange); font-weight:700;">● \${o.paymentStatus}</span>\`;
          }

          return \`
            <div class="clay-box" style="padding:20px;">
              <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-size:0.85rem;">
                <span style="color:var(--text-muted);">Order #\${o.orderId}</span>
                <span>\${statusBadge}</span>
              </div>
              <div style="font-weight:800; font-size:1.1rem; margin-bottom:4px;">\${o.productName}</div>
              <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:12px;">Amount: ₹\${(o.amountPaise / 100).toFixed(2)} via \${o.paymentMethod}</div>

              \${o.assignedKeySecret ? \`
                <div class="key-badge">
                  <span>\${o.assignedKeySecret}</span>
                  <button class="clay-btn" style="padding:6px 12px; font-size:0.75rem;" onclick="copyKey('\${o.assignedKeySecret}')">Copy</button>
                </div>
              \` : '<div style="font-size:0.85rem; color:var(--text-muted);">Key will appear here immediately once payment verification is approved.</div>'}
            </div>
          \`;
        }).join('');
      } catch (e) {
        showToast('Error loading your orders.');
      }
    }

    function copyKey(key) {
      navigator.clipboard.writeText(key);
      showToast('Key copied to clipboard!');
    }

    // SUPPORT SYSTEM
    async function submitTicket() {
      if (!currentUser) {
        showToast('Please sign in to contact support.');
        openAuthModal();
        return;
      }
      const category = document.getElementById('ticketCategory').value;
      const subject = document.getElementById('ticketSubject').value;
      const message = document.getElementById('ticketMessage').value;

      if (!subject || !message) {
        showToast('Please provide a subject and message.');
        return;
      }

      try {
        const res = await fetch('/api/support/tickets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ category, subject, message })
        });
        const data = await res.json();
        if (data.success) {
          showToast('Ticket submitted successfully!');
          document.getElementById('ticketSubject').value = '';
          document.getElementById('ticketMessage').value = '';
          loadTickets();
        }
      } catch (e) {
        showToast('Failed to create ticket.');
      }
    }

    async function loadTickets() {
      if (!currentUser) return;
      try {
        const res = await fetch('/api/support/tickets');
        const data = await res.json();
        const div = document.getElementById('ticketList');
        if (!data.success || data.tickets.length === 0) {
          div.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);">No support tickets found.</div>';
          return;
        }

        div.innerHTML = data.tickets.map(t => \`
          <div class="clay-box" style="padding:18px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
              <span style="font-weight:700; color:var(--cyan);">#\${t.ticketId} — \${t.category}</span>
              <span style="font-size:0.8rem; font-weight:700;">\${t.status}</span>
            </div>
            <div style="font-weight:600; margin-bottom:8px;">\${t.subject}</div>
            <div style="background:#0d121e; padding:10px; border-radius:10px; font-size:0.85rem; color:var(--text-muted);">
              \${t.messages.map(m => \`<div><strong>\${m.senderName}:</strong> \${m.message}</div>\`).join('')}
            </div>
          </div>
        \`).join('');
      } catch (e) {}
    }

    // TAB NAVIGATION
    function switchTab(tab) {
      document.querySelectorAll('.dock-item').forEach(el => el.classList.remove('active'));
      document.getElementById('products').style.display = 'none';
      document.getElementById('ordersView').style.display = 'none';
      document.getElementById('supportView').style.display = 'none';

      if (tab === 'store') {
        document.getElementById('products').style.display = 'block';
      } else if (tab === 'orders') {
        document.getElementById('ordersView').style.display = 'block';
        loadOrders();
      } else if (tab === 'support') {
        document.getElementById('supportView').style.display = 'block';
        loadTickets();
      } else if (tab === 'profile') {
        if (!currentUser) openAuthModal();
        else showToast('Logged in as: ' + currentUser.email);
      }
    }

    // INITIALIZATION
    window.addEventListener('DOMContentLoaded', () => {
      checkSession();
      loadProducts();
    });
  </script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// ==========================================
// LOCAL OR EXPORT FOR VERCEL SERVERLESS
// ==========================================
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Luffy Engine Store running on http://localhost:${PORT}`);
  });
}

module.exports = app;
