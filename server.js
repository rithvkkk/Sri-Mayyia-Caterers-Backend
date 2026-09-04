const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
global.crypto = require('crypto');
require('dotenv').config();

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));
app.options('*', cors());
app.use(express.json({ limit: '1mb' }));

// ─────────────────── SECURITY MIDDLEWARES ───────────────────

// 1. IP & User-based Rate Limiter (Sliding Window In-Memory Store)
const rateLimitStore = new Map();

// Periodic cleanup of stale rate-limit entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now > record.resetTime) {
      rateLimitStore.delete(key);
    }
  }
}, 10 * 60 * 1000);

const createRateLimiter = (options = {}) => {
  const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes default
  const maxRequests = options.max || 120; // 120 requests default

  return (req, res, next) => {
    // Client IP detection (supporting proxy headers like Vercel / Cloudflare)
    const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
    const userIdentifier = req.body?.username ? `${clientIp}_${String(req.body.username).toLowerCase()}` : clientIp;
    const key = `${req.path}:${userIdentifier}`;

    const now = Date.now();
    let record = rateLimitStore.get(key);

    if (!record || now > record.resetTime) {
      record = { count: 1, resetTime: now + windowMs };
    } else {
      record.count += 1;
    }

    rateLimitStore.set(key, record);

    const remaining = Math.max(0, maxRequests - record.count);
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));

    if (record.count > maxRequests) {
      const retryAfterSec = Math.ceil((record.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfterSec);
      return res.status(429).json({
        error: 'Too Many Requests',
        message: options.message || 'Rate limit exceeded. Please wait a few minutes before trying again.',
        status: 429,
        retryAfterSeconds: retryAfterSec
      });
    }

    next();
  };
};

// Global rate limiter for all public endpoints: 150 requests / 15 mins
app.use(createRateLimiter({ windowMs: 15 * 60 * 1000, max: 150 }));

// Dedicated strict login rate limiter: 10 attempts / 15 mins
const loginRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Account temporarily locked for 15 minutes.'
});

// 2. Input Sanitization & Safety Middleware (NoSQL & XSS prevention)
const sanitizeInput = (req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    const sanitizeValue = (val, key = '') => {
      // Reject NoSQL injection operators starting with $ or containing .
      if (key.startsWith('$') || key.includes('.')) {
        return undefined;
      }
      if (typeof val === 'string') {
        // Strip script tags and HTML dangerous constructs
        let sanitized = val.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                           .replace(/javascript:/gi, '');
        // Length sanity check (max 2000 chars per text field)
        if (sanitized.length > 2000) {
          sanitized = sanitized.substring(0, 2000);
        }
        return sanitized.trim();
      }
      if (Array.isArray(val)) {
        return val.map(item => sanitizeValue(item));
      }
      if (val !== null && typeof val === 'object') {
        const cleanObj = {};
        for (const [k, v] of Object.entries(val)) {
          if (!k.startsWith('$') && !k.includes('.')) {
            cleanObj[k] = sanitizeValue(v, k);
          }
        }
        return cleanObj;
      }
      return val;
    };

    req.body = sanitizeValue(req.body);
  }
  next();
};

app.use(sanitizeInput);

// Cached Mongoose connection helper for Vercel Serverless Functions
let cached = global.mongoose;
if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) {
    return cached.conn;
  }
  if (!cached.promise) {
    const uri = process.env.MONGODB_URI || MONGODB_URI;
    if (!uri) {
      throw new Error('MONGODB_URI environment variable is missing in Vercel settings');
    }
    console.log('Connecting to MongoDB Atlas...');
    cached.promise = mongoose.connect(uri, {
      serverSelectionTimeoutMS: 3000,
      connectTimeoutMS: 3000
    }).then((m) => {
      console.log('Connected to MongoDB online');
      return m;
    });
  }
  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    throw e;
  }
  return cached.conn;
}

// Middleware to ensure DB connection
app.use(async (req, res, next) => {
  if (req.path === '/' || req.path === '/status' || req.path === '/api/status') return next();
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error('DB connection failed:', err);
    res.status(500).json({ error: `Database Connection Failed: ${err.message || String(err)}` });
  }
});

app.get('/', (req, res) => {
  res.send('<h2>CaterFlow Enterprise Catering API is Online!</h2><p>Connect your frontend React client to this URL.</p>');
});

app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    db_state: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    db_state: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// ─────────────────── MONGOOSE MODELS ───────────────────

// 1. Venue
const venueSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  capacity: { type: Number, required: true },
  price: { type: Number, required: true },
  address: { type: String, required: true }
});
const Venue = mongoose.model('Venue', venueSchema);

// 2. Raw Material
const rawMaterialSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true }, // Grocery, Dairy, Veg/Fruit, Fuel
  unit: { type: String, required: true },
  costPerUnit: { type: Number, required: true }
});
const RawMaterial = mongoose.model('RawMaterial', rawMaterialSchema);

// 3. Dish
const recipeItemSchema = new mongoose.Schema({
  materialId: { type: String, required: true },
  quantity: { type: Number, required: true }
}, { _id: false });

const dishSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true },
  subCategory: { type: String },
  dietary: [{ type: String }],
  price: { type: Number, required: true },
  recipe: [recipeItemSchema]
}, { timestamps: true });
const Dish = mongoose.model('Dish', dishSchema);

// 4. Supplier
const supplierSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true }, // Grocery, Dairy, Veg/Fruit, Fuel
  contact: { type: String, default: '' },
  phone: { type: String, default: '' },
  address: { type: String, default: '' },
  email: { type: String, default: '' }
}, { timestamps: true });
const Supplier = mongoose.model('Supplier', supplierSchema);

// 5. Labor Rate
const laborRateSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  type: { type: String, required: true },
  rate: { type: Number, required: true }
});
const LaborRate = mongoose.model('LaborRate', laborRateSchema);

// 6. Agency
const agencySchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  contact: { type: String, required: true },
  phone: { type: String, required: true },
  categories: [{ type: String }] // Waiter / Service Staff, Captain/Supervisor, Bartender, etc.
});
const Agency = mongoose.model('Agency', agencySchema);

// 6b. Vessel / Equipment
const vesselSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true }, // Cooking Vessel, Serving Gear, Utensils, Heating & Fuel
  totalQty: { type: Number, required: true },
  availableQty: { type: Number, required: true },
  inUseQty: { type: Number, default: 0 },
  damagedQty: { type: Number, default: 0 },
  location: { type: String, default: 'Main Store' },
  valuePerUnit: { type: Number, default: 0 }
});
const Vessel = mongoose.model('Vessel', vesselSchema);

// 6c. Provision / Dry Grocery
const provisionSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true }, // Grocery, Ghee & Oils, Spices & Condiments, Dry Fruits
  unit: { type: String, required: true }, // kg, ltr, bag, pkt
  stockQty: { type: Number, required: true },
  reorderLevel: { type: Number, required: true },
  costPerUnit: { type: Number, required: true },
  supplierId: { type: String, default: '' }
});
const Provision = mongoose.model('Provision', provisionSchema);

// 6d. Vegetable / Fresh Produce
const vegetableSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true }, // Vegetable, Fruit, Dairy & Fresh, Herbs & Greens
  unit: { type: String, required: true }, // kg, ltr, bunch, box
  stockQty: { type: Number, required: true },
  marketPrice: { type: Number, required: true },
  freshnessStatus: { type: String, default: 'Fresh' }, // Fresh, 1-2 Days Left, Urgent Use
  supplierId: { type: String, default: '' }
});
const Vegetable = mongoose.model('Vegetable', vegetableSchema);

// 6e. Labour Worker Master
const labourWorkerSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, required: true }, // Chef, Assistant Chef, Captain/Supervisor, Waiter, Kitchen Helper, Cleaner
  phone: { type: String, required: true },
  dailyRate: { type: Number, required: true },
  agencyId: { type: String, default: 'Direct Hire' },
  type: { type: String, default: 'Direct' }, // Direct, Agency
  status: { type: String, default: 'Active' } // Active, On Leave, Inactive
});
const LabourWorker = mongoose.model('LabourWorker', labourWorkerSchema);

// 6f. Labour Attendance Log
const labourAttendanceSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  workerId: { type: String, required: true },
  workerName: { type: String, required: true },
  date: { type: String, required: true },
  eventId: { type: String, default: '' },
  eventName: { type: String, default: '' },
  shiftType: { type: String, default: 'Full Day' }, // Full Day, Morning, Evening, Double Shift
  shifts: { type: Number, default: 1 },
  dailyRate: { type: Number, required: true },
  totalWage: { type: Number, required: true },
  status: { type: String, default: 'Present' }, // Present, Half-Day, Overtime, Absent, On Leave
  notes: { type: String, default: '' }
}, { timestamps: true });
const LabourAttendance = mongoose.model('LabourAttendance', labourAttendanceSchema);

// 7. Company Profile
const companyProfileSchema = new mongoose.Schema({
  _id: { type: String, default: 'current_profile' },
  name: { type: String, default: 'Sri Mayyia Caterers' },
  tagline: { type: String, default: 'Legacy of Royal Flavors Since 1953' },
  phone: { type: String, default: '+91 99988 77766' },
  email: { type: String, default: 'info@srimayyiacaterers.com' },
  address: { type: String, default: 'No 43, 2nd Cross, Malleshwaram, Bangalore - 560003' },
  gstin: { type: String, default: '24AAAAA1111A1Z1' },
  defaultTaxRate: { type: Number, default: 18 },
  currency: { type: String, default: '₹' }
});
const CompanyProfile = mongoose.model('CompanyProfile', companyProfileSchema);

// 7b. User/Credential Management Schema
const userSchema = new mongoose.Schema({
  _id: { type: String, required: true }, // Username
  password: { type: String, required: true },
  role: { type: String, required: true } // Admin, HR, Inhouse Inventory Manager, Accountant, Sales Executive, Agency, Chef
});
const User = mongoose.model('User', userSchema);

// 7c. Role-Based Access Control (RBAC) Matrix Schema
const rbacMatrixSchema = new mongoose.Schema({
  _id: { type: String, default: 'current_matrix' },
  matrix: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });
const RbacMatrix = mongoose.model('RbacMatrix', rbacMatrixSchema);

// 7d. Historical Legacy Events Ingestion & Machine Learning Schema
const historicalEventSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  eventType: { type: String, required: true },
  guestCount: { type: Number, required: true },
  actualPax: { type: Number },
  serviceStyle: { type: String, default: 'Traditional Banana Leaf' },
  season: { type: String, default: 'Regular' },
  foodCostPerPax: { type: Number, default: 320 },
  wastePercent: { type: Number, default: 4.5 },
  netMarginPercent: { type: Number, default: 45.0 },
  menuSummary: [{ type: String }],
  rawMaterialActuals: [{
    materialId: String,
    materialName: String,
    consumedQty: Number,
    unit: String
  }],
  postEventNotes: { type: String, default: '' },
  ingestedAt: { type: Date, default: Date.now }
}, { timestamps: true });
const HistoricalEvent = mongoose.model('HistoricalEvent', historicalEventSchema);


// 8. Event
const subFunctionSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, required: true },
  date: { type: String, default: '' },
  guestCount: { type: Number, default: 100 },
  menuItems: [{ type: String }], // Array of dish IDs
  clientNotes: { type: String, default: '' }
}, { _id: false });

const laborAllocationSchema = new mongoose.Schema({
  agencyId: { type: String, required: true },
  laborType: { type: String, required: true },
  count: { type: Number, required: true },
  shifts: { type: Number, required: true },
  totalPayout: { type: Number, required: true },
  status: { type: String, default: 'Pending' } // Pending, Verified, Paid, Cancelled
}, { _id: false });

const manualMaterialSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  requiredQty: { type: Number, required: true },
  unit: { type: String, required: true },
  costPerUnit: { type: Number, required: true },
  totalCost: { type: Number, required: true },
  supplier: {
    _id: { type: String },
    name: { type: String },
    contact: { type: String },
    category: { type: String }
  }
}, { _id: false });

const vehicleExpenseSchema = new mongoose.Schema({
  id: { type: String, required: true },
  vehicleType: { type: String, required: true }, // Tempo, Mini-Truck (14ft), Auto, Refrigerated Van, Eeco
  vehicleNumber: { type: String, default: '' },
  trips: { type: Number, default: 1 },
  ratePerTrip: { type: Number, default: 0 },
  totalCost: { type: Number, default: 0 },
  driverName: { type: String, default: '' },
  driverPhone: { type: String, default: '' }
}, { _id: false });

const porterExpenseSchema = new mongoose.Schema({
  id: { type: String, required: true },
  description: { type: String, default: 'Loading & Unloading Porter' },
  count: { type: Number, default: 1 },
  ratePerPorter: { type: Number, default: 0 },
  totalCost: { type: Number, default: 0 }
}, { _id: false });

const reminderSchema = new mongoose.Schema({
  id: { type: String, required: true },
  date: { type: String, required: true },
  time: { type: String, default: '10:00' },
  note: { type: String, required: true },
  priority: { type: String, default: 'Medium' }, // High, Medium, Low
  completed: { type: Boolean, default: false },
  createdAt: { type: String, default: () => new Date().toISOString() }
}, { _id: false });

const eventSchema = new mongoose.Schema({
  _id: { type: String, required: true }, // EV-YYYY-XXX
  customer: {
    name: { type: String, required: true, default: 'Client' },
    phone: { type: String, default: '' },
    email: { type: String, default: '' }
  },
  eventType: { type: String, default: 'Wedding Reception' },
  venueId: { type: String, default: '' },
  date: { type: String, required: true }, // Primary / Commencement Date
  dates: [{ type: String }], // Array of multiple event dates
  menuNotes: { type: String, default: '' },
  status: { type: String, default: 'Inquiry' }, // Inquiry, Confirmed, Completed, Cancelled
  createdBy: { type: String, default: 'admin' },
  createdByName: { type: String, default: 'Admin' },
  salesExecutive: { type: String, default: 'admin' },
  reminders: [reminderSchema],
  subFunctions: [subFunctionSchema],
  manualMaterials: [manualMaterialSchema],
  transport: {
    vehicles: [vehicleExpenseSchema],
    porters: [porterExpenseSchema],
    totalTransportCost: { type: Number, default: 0 }
  },
  execution: {
    teamRoutes: { type: Map, of: String }, // dishId -> 'internal' | 'outsourced' | 'agency'
    dishStatuses: { type: Map, of: String }, // dishId -> preparation status
    costs: {
      rawMaterialsCost: { type: Number, default: 0 },
      laborCost: { type: Number, default: 0 },
      transportCost: { type: Number, default: 0 },
      venueRent: { type: Number, default: 0 },
      otherExpenses: { type: Number, default: 0 }
    }
  },
  laborAllocations: [laborAllocationSchema],
  billing: {
    pricePerPlate: { type: Number, default: 800 },
    subtotal: { type: Number, default: 0 },
    taxRate: { type: Number, default: 5 },
    taxType: { type: String, default: 'GST' }, // 'GST' | 'NON_GST'
    isInterState: { type: Boolean, default: false },
    taxAmount: { type: Number, default: 0 },
    totalAmount: { type: Number, default: 0 },
    advancePaid: { type: Number, default: 0 },
    balanceDue: { type: Number, default: 0 },
    status: { type: String, default: 'Unpaid' } // Unpaid, Partially Paid, Fully Paid
  }
}, { timestamps: true });
const Event = mongoose.model('Event', eventSchema);

// JSON formatting helper for API payloads
const toJSON = (doc) => {
  if (!doc) return null;
  const obj = doc.toObject ? doc.toObject() : doc;
  obj.id = obj._id;
  delete obj._id;
  delete obj.__v;
  return obj;
};

// ──────────────────── REST API ROUTES ────────────────────

// Generic CRUD factory
const createCRUDRoutes = (app, routePath, Model) => {
  // GET all
  app.get(routePath, async (req, res) => {
    try {
      const items = await Model.find();
      res.json(items.map(toJSON));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST create
  app.post(routePath, async (req, res) => {
    try {
      const payload = { ...req.body };
      if (payload.id && !payload._id) {
        payload._id = payload.id;
      }
      const item = await Model.create(payload);
      res.status(201).json(toJSON(item));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // PUT update
  app.put(`${routePath}/:id`, async (req, res) => {
    try {
      const updated = await Model.findByIdAndUpdate(req.params.id, req.body, { new: true });
      if (!updated) return res.status(404).json({ error: 'Item not found' });
      res.json(toJSON(updated));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // DELETE
  app.delete(`${routePath}/:id`, async (req, res) => {
    try {
      const deleted = await Model.findByIdAndDelete(req.params.id);
      if (!deleted) return res.status(404).json({ error: 'Item not found' });
      res.json({ success: true, message: 'Deleted successfully' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
};

// Dedicated resilient creation for Events (guarantees safe ID generation, field fallbacks, and upsert)
const handleEventCreation = async (req, res) => {
  try {
    const payload = { ...req.body };
    const year = new Date().getFullYear();

    let targetId = payload._id || payload.id;
    if (targetId) {
      const existing = await Event.findById(targetId);
      if (existing) {
        // If an event exists with this exact ID, calculate the next safe sequential ID
        const allYearEvents = await Event.find({ _id: new RegExp(`^EV-${year}-`) }, '_id');
        let maxNum = 0;
        allYearEvents.forEach(e => {
          const parts = e._id.split('-');
          const n = parseInt(parts[2], 10);
          if (!isNaN(n) && n > maxNum) maxNum = n;
        });
        targetId = `EV-${year}-${String(maxNum + 1).padStart(3, '0')}`;
      }
    } else {
      const allYearEvents = await Event.find({ _id: new RegExp(`^EV-${year}-`) }, '_id');
      let maxNum = 0;
      allYearEvents.forEach(e => {
        const parts = e._id.split('-');
        const n = parseInt(parts[2], 10);
        if (!isNaN(n) && n > maxNum) maxNum = n;
      });
      targetId = `EV-${year}-${String(maxNum + 1).padStart(3, '0')}`;
    }

    payload._id = targetId;
    payload.id = targetId;

    if (!payload.customer) payload.customer = {};
    if (!payload.customer.name) payload.customer.name = 'Client';
    if (payload.customer.phone === undefined) payload.customer.phone = '';
    if (payload.customer.email === undefined) payload.customer.email = '';
    if (payload.venueId === undefined) payload.venueId = '';
    if (!payload.eventType) payload.eventType = 'Wedding Reception';
    if (!payload.date) payload.date = new Date().toISOString().split('T')[0];
    if (!Array.isArray(payload.dates) || payload.dates.length === 0) payload.dates = [payload.date];
    if (!payload.createdBy) payload.createdBy = 'admin';
    if (!payload.createdByName) payload.createdByName = 'Admin';
    if (!payload.salesExecutive) payload.salesExecutive = payload.createdBy || 'admin';

    const item = await Event.findByIdAndUpdate(targetId, payload, { upsert: true, new: true, setDefaultsOnInsert: true });
    res.status(201).json(toJSON(item));
  } catch (err) {
    console.error('Error in resilient event creation:', err);
    res.status(400).json({ error: err.message });
  }
};

app.post('/api/events', handleEventCreation);
app.post('/events', handleEventCreation);

createCRUDRoutes(app, '/api/venues', Venue);
createCRUDRoutes(app, '/api/raw-materials', RawMaterial);
createCRUDRoutes(app, '/api/dishes', Dish);
createCRUDRoutes(app, '/api/suppliers', Supplier);
createCRUDRoutes(app, '/api/labor-rates', LaborRate);
createCRUDRoutes(app, '/api/agencies', Agency);
createCRUDRoutes(app, '/api/events', Event);
createCRUDRoutes(app, '/api/vessels', Vessel);
createCRUDRoutes(app, '/api/provisions', Provision);
createCRUDRoutes(app, '/api/vegetables', Vegetable);
createCRUDRoutes(app, '/api/labour-workers', LabourWorker);
createCRUDRoutes(app, '/api/labour-attendance', LabourAttendance);

// ─────────────────── MASTER MENU JSON DIRECT MONGO UPLOAD ───────────────────
app.post('/api/menu/upload-json', async (req, res) => {
  try {
    let masterMenu = req.body;
    if (!masterMenu || (Array.isArray(masterMenu) && masterMenu.length === 0) || (!Array.isArray(masterMenu) && (!masterMenu.categories || !Array.isArray(masterMenu.categories)))) {
      // Load from local catering_master_menu.json
      const fs = require('fs');
      const path = require('path');
      const jsonPath = path.join(__dirname, 'catering_master_menu.json');
      if (fs.existsSync(jsonPath)) {
        masterMenu = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      } else {
        return res.status(400).json({ error: 'No menu JSON provided and catering_master_menu.json file not found on server.' });
      }
    }

    const allDishes = [];
    if (Array.isArray(masterMenu)) {
      masterMenu.forEach(item => {
        allDishes.push({
          _id: item._id || item.id,
          name: item.name,
          category: item.category,
          subCategory: item.subCategory,
          dietary: item.dietary || ['Vegetarian'],
          price: item.price || 100,
          recipe: item.recipe || []
        });
      });
    } else {
      (masterMenu.categories || []).forEach(cat => {
        const catName = cat.name;
        (cat.subCategories || []).forEach(sub => {
          const subName = sub.name;
          (sub.items || []).forEach(item => {
            allDishes.push({
              _id: item._id || item.id,
              name: item.name,
              category: item.category || catName,
              subCategory: item.subCategory || subName,
              dietary: item.dietary || ['Vegetarian'],
              price: item.price || 100,
              recipe: item.recipe || []
            });
          });
        });
      });
    }

    const bulkOps = allDishes.map(dish => ({
      updateOne: {
        filter: { _id: dish._id },
        update: { $set: dish },
        upsert: true
      }
    }));

    const result = await Dish.bulkWrite(bulkOps);

    res.json({
      success: true,
      message: 'Master Menu JSON successfully uploaded to MongoDB!',
      totalDishes: allDishes.length,
      matchedCount: result.matchedCount || 0,
      upsertedCount: result.upsertedCount || 0,
      modifiedCount: result.modifiedCount || 0
    });
  } catch (err) {
    console.error('Error uploading menu to MongoDB:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/menu/master-json', async (req, res) => {
  try {
    const fs = require('fs');
    const path = require('path');
    const jsonPath = path.join(__dirname, 'catering_master_menu.json');
    if (fs.existsSync(jsonPath)) {
      const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      return res.json(data);
    }
    const dishes = await Dish.find();
    res.json({ categories: [], dishes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────── RBAC MATRIX ENDPOINTS ───────────────────
app.get('/api/rbac-matrix', async (req, res) => {
  try {
    const doc = await RbacMatrix.findById('current_matrix');
    res.json(doc ? doc.matrix : {});
  } catch (err) {
    res.json({});
  }
});

app.post('/api/rbac-matrix', async (req, res) => {
  try {
    const matrix = req.body;
    await RbacMatrix.findByIdAndUpdate(
      'current_matrix',
      { matrix },
      { upsert: true, new: true }
    );
    res.json({ success: true, message: 'RBAC matrix updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────── HISTORICAL DATA SEEDING & INGESTION ───────────────────
app.get('/api/historical-events', async (req, res) => {
  try {
    const events = await HistoricalEvent.find().sort({ createdAt: -1 }).limit(200);
    res.json(events.map(e => ({ ...e.toObject(), id: e._id })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/historical-events/ingest-batch', async (req, res) => {
  try {
    const records = req.body;
    if (!Array.isArray(records) || records.length === 0) {
      return res.status(400).json({ error: 'Expected an array of legacy event records.' });
    }

    const bulkOps = records.map(rec => ({
      updateOne: {
        filter: { _id: String(rec.id || rec._id || `hist_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`) },
        update: {
          $set: {
            eventType: rec.eventType || 'Wedding Catering',
            guestCount: Number(rec.guestCount || rec.actualPax || 100),
            actualPax: Number(rec.actualPax || rec.guestCount || 100),
            serviceStyle: rec.serviceStyle || 'Traditional Banana Leaf',
            season: rec.season || 'Regular',
            foodCostPerPax: Number(rec.foodCostPerPax || 320),
            wastePercent: Number(rec.wastePercent || 4.5),
            netMarginPercent: Number(rec.netMarginPercent || 45.0),
            menuSummary: Array.isArray(rec.menuSummary) ? rec.menuSummary : [],
            rawMaterialActuals: Array.isArray(rec.rawMaterialActuals) ? rec.rawMaterialActuals : [],
            postEventNotes: rec.postEventNotes || '',
            ingestedAt: new Date()
          }
        },
        upsert: true
      }
    }));

    const result = await HistoricalEvent.bulkWrite(bulkOps);
    res.json({
      success: true,
      ingestedCount: (result.upsertedCount || 0) + (result.modifiedCount || 0) + (result.matchedCount || 0),
      message: `Successfully ingested ${records.length} legacy events into learning memory.`
    });
  } catch (err) {
    console.error('Historical Batch Ingestion Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────── LABOUR ATTENDANCE BATCH IMPORT ───────────────────
app.post('/api/labour-attendance/batch', async (req, res) => {
  try {
    const records = req.body;
    if (!Array.isArray(records) || records.length === 0) {
      return res.status(400).json({ error: 'Expected an array of attendance records.' });
    }

    const bulkOps = records.map(rec => ({
      updateOne: {
        filter: { _id: String(rec.id || rec._id || `att_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`) },
        update: {
          $set: {
            workerId: String(rec.workerId || 'unknown'),
            workerName: String(rec.workerName || 'Staff Member'),
            date: String(rec.date || new Date().toISOString().split('T')[0]),
            eventId: String(rec.eventId || ''),
            eventName: String(rec.eventName || ''),
            shiftType: String(rec.shiftType || 'Full Day'),
            shifts: Number(rec.shifts || 1),
            dailyRate: Number(rec.dailyRate || 900),
            totalWage: Number(rec.totalWage || 900),
            status: String(rec.status || 'Present'),
            notes: String(rec.notes || '')
          }
        },
        upsert: true
      }
    }));

    const result = await LabourAttendance.bulkWrite(bulkOps);
    res.json({
      success: true,
      count: (result.upsertedCount || 0) + (result.modifiedCount || 0) + (result.matchedCount || 0),
      message: `Successfully imported ${records.length} labour attendance records.`
    });
  } catch (err) {
    console.error('Labour Attendance Batch Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Secure /api/users endpoints with hashing
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users.map(u => ({ id: u._id, role: u.role, password: '••••••••' })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const { id, password, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = await User.create({ _id: id.toLowerCase(), password: hashedPassword, role });
    res.status(201).json({ id: user._id, role: user.role, password: '••••••••' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { password, role } = req.body;
    const updateData = { role };
    if (password && password !== '••••••••') {
      updateData.password = bcrypt.hashSync(password, 10);
    }
    const updated = await User.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ error: 'User not found' });
    res.json({ id: updated._id, role: updated.role, password: '••••••••' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: 'Deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Dedicated login validation route supporting Bcrypt, SHA-256, and Plaintext (Strict 10 attempts / 15 min limit)
app.post('/api/users/login', loginRateLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    const cleanUsername = String(username).trim().toLowerCase();
    const cleanPassword = String(password).trim();

    // Auto-seed admin user if users collection in MongoDB is empty
    const userCount = await User.countDocuments();
    if (userCount === 0 && cleanUsername === 'admin') {
      const defaultAdminPass = bcrypt.hashSync('admin123', 10);
      await User.create({ _id: 'admin', password: defaultAdminPass, role: 'Admin' }).catch(() => null);
    }

    let user = await User.findOne({ _id: cleanUsername });
    if (!user) {
      user = await User.findOne({ _id: new RegExp(`^${cleanUsername}$`, 'i') });
    }

    if (!user) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    let isValid = false;

    // 1. Check Bcrypt ($2a$, $2b$, $2y$)
    if (user.password && user.password.startsWith('$2')) {
      try {
        isValid = bcrypt.compareSync(cleanPassword, user.password);
      } catch (e) {
        isValid = false;
      }
    }

    // 2. Check SHA-256
    if (!isValid) {
      const sha256Hash = crypto.createHash('sha256').update(cleanPassword).digest('hex');
      if (user.password === sha256Hash) {
        isValid = true;
      }
    }

    // 3. Check Plain Text
    if (!isValid) {
      if (user.password === cleanPassword) {
        isValid = true;
      }
    }

    if (isValid) {
      // Auto-upgrade unhashed passwords to Bcrypt for maximum security
      if (!user.password.startsWith('$2')) {
        user.password = bcrypt.hashSync(cleanPassword, 10);
        await user.save().catch(() => null);
      }
      return res.json({ success: true, role: user.role, username: user._id });
    }

    res.json({ success: false, message: 'Invalid credentials' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Special routes for Company Profile (Single-Document state)
app.get('/api/company-profile', async (req, res) => {
  try {
    let profile = await CompanyProfile.findOne({ _id: 'current_profile' });
    if (!profile) {
      profile = await CompanyProfile.create({ _id: 'current_profile' });
    }
    res.json(toJSON(profile));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/company-profile', async (req, res) => {
  try {
    const profile = await CompanyProfile.findOneAndUpdate(
      { _id: 'current_profile' },
      { ...req.body, _id: 'current_profile' },
      { new: true, upsert: true }
    );
    res.json(toJSON(profile));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Seed endpoint
app.post('/api/seed', async (req, res) => {
  try {
    // 1. Clear existing database collections
    await Promise.all([
      Venue.deleteMany({}),
      RawMaterial.deleteMany({}),
      Dish.deleteMany({}),
      Supplier.deleteMany({}),
      LaborRate.deleteMany({}),
      Agency.deleteMany({}),
      Event.deleteMany({}),
      CompanyProfile.deleteMany({}),
      User.deleteMany({}),
      Vessel.deleteMany({}),
      Provision.deleteMany({}),
      Vegetable.deleteMany({}),
      LabourWorker.deleteMany({})
    ]);

    // 2. Mock Data Definitions
    const initialVenues = [
      { _id: 'v1', name: 'Royal Grand Ballroom', capacity: 500, price: 150000, address: 'S.G. Highway, Ahmedabad' },
      { _id: 'v2', name: 'Lakeside Pavilion', capacity: 300, price: 120000, address: 'Kankaria Lake, Ahmedabad' },
      { _id: 'v3', name: 'Garden Terrace & Lawn', capacity: 800, price: 200000, address: 'Bodakdev, Ahmedabad' },
      { _id: 'v4', name: 'Elite Banquet Hall', capacity: 150, price: 75000, address: 'C.G. Road, Ahmedabad' }
    ];

    const initialRawMaterials = [
      { _id: 'rm1', name: 'Basmati Rice', category: 'Grocery', unit: 'kg', costPerUnit: 90 },
      { _id: 'rm2', name: 'Wheat Flour (Atta)', category: 'Grocery', unit: 'kg', costPerUnit: 45 },
      { _id: 'rm3', name: 'Sugar', category: 'Grocery', unit: 'kg', costPerUnit: 40 },
      { _id: 'rm4', name: 'Spices Mix', category: 'Grocery', unit: 'kg', costPerUnit: 350 },
      { _id: 'rm5', name: 'Cooking Oil', category: 'Grocery', unit: 'ltr', costPerUnit: 140 },
      { _id: 'rm6', name: 'Lentils (Dal)', category: 'Grocery', unit: 'kg', costPerUnit: 120 },
      { _id: 'rm7', name: 'Tea Leaves', category: 'Grocery', unit: 'kg', costPerUnit: 280 },
      { _id: 'rm8', name: 'Chinese Sauces', category: 'Grocery', unit: 'ltr', costPerUnit: 95 },
      { _id: 'rm9', name: 'Fresh Paneer', category: 'Dairy', unit: 'kg', costPerUnit: 380 },
      { _id: 'rm10', name: 'Amul Butter', category: 'Dairy', unit: 'kg', costPerUnit: 520 },
      { _id: 'rm11', name: 'Fresh Cream', category: 'Dairy', unit: 'ltr', costPerUnit: 220 },
      { _id: 'rm12', name: 'Full Cream Milk', category: 'Dairy', unit: 'ltr', costPerUnit: 66 },
      { _id: 'rm13', name: 'Khoya (Mawa)', category: 'Dairy', unit: 'kg', costPerUnit: 320 },
      { _id: 'rm14', name: 'Desi Ghee', category: 'Dairy', unit: 'kg', costPerUnit: 650 },
      { _id: 'rm15', name: 'Mixed Vegetables', category: 'Veg/Fruit', unit: 'kg', costPerUnit: 50 },
      { _id: 'rm16', name: 'Onions & Potatoes', category: 'Veg/Fruit', unit: 'kg', costPerUnit: 35 },
      { _id: 'rm17', name: 'Capsicum & Tomato', category: 'Veg/Fruit', unit: 'kg', costPerUnit: 60 },
      { _id: 'rm18', name: 'Mint & Lemon', category: 'Veg/Fruit', unit: 'kg', costPerUnit: 80 },
      { _id: 'rm19', name: 'Assorted Fresh Fruits', category: 'Veg/Fruit', unit: 'kg', costPerUnit: 120 },
      { _id: 'rm20', name: 'LPG Commercial Cylinder', category: 'Fuel', unit: 'cylinder', costPerUnit: 1850 },
      { _id: 'rm21', name: 'Charcoal / Wood', category: 'Fuel', unit: 'bag', costPerUnit: 450 }
    ];

    let masterMenuData = { categories: [] };
    try {
      masterMenuData = require('./catering_master_menu.json');
    } catch (e) {
      console.warn('Could not load ./catering_master_menu.json, using fallback');
    }

    const initialDishes = Array.isArray(masterMenuData)
      ? masterMenuData.map(item => ({
          _id: item._id || item.id,
          name: item.name,
          category: item.category,
          subCategory: item.subCategory,
          dietary: item.dietary || ['Vegetarian'],
          price: item.price || 100,
          recipe: item.recipe || []
        }))
      : (masterMenuData.categories || []).flatMap(cat =>
          (cat.subCategories || []).flatMap(sub =>
            (sub.items || []).map(item => ({
              _id: item._id || item.id,
              name: item.name,
              category: item.category || cat.name,
              subCategory: item.subCategory || sub.name,
              dietary: item.dietary || ['Vegetarian'],
              price: item.price || 100,
              recipe: item.recipe || []
            }))
          )
        );

    const initialSuppliers = [
      { _id: 's1', name: 'Krishna Grocery Wholesalers', category: 'Grocery', contact: 'Ramesh Patel', phone: '+91 98765 43210' },
      { _id: 's2', name: 'Amul Dairy Distributors', category: 'Dairy', contact: 'Suresh Shah', phone: '+91 98250 12345' },
      { _id: 's3', name: 'Green Market Fresh Produce', category: 'Veg/Fruit', contact: 'Vijay Khetan', phone: '+91 99099 87654' },
      { _id: 's4', name: 'HP Commercial Gas Corp', category: 'Fuel', contact: 'Dinesh Mehta', phone: '+91 97243 55566' }
    ];

    const initialLaborRates = [
      { _id: 'l1', type: 'Captain/Supervisor', rate: 1400 },
      { _id: 'l2', type: 'Waiter / Service Staff', rate: 900 },
      { _id: 'l3', type: 'Bartender / Mixologist', rate: 1600 },
      { _id: 'l4', type: 'Kitchen Helper', rate: 750 },
      { _id: 'l5', type: 'Utility Cleaner', rate: 650 }
    ];

    const initialAgencies = [
      { _id: 'a1', name: 'Royal Hospitality Services', contact: 'Harsh Vyas', phone: '+91 98111 22233', categories: ['Waiter / Service Staff', 'Captain/Supervisor'] },
      { _id: 'a2', name: 'Apex Event Staffing Co', contact: 'Nikhil Parmar', phone: '+91 98980 44455', categories: ['Bartender / Mixologist', 'Kitchen Helper', 'Utility Cleaner'] }
    ];

    const initialEvents = [
      {
        _id: 'EV-2026-001',
        customer: { name: 'Venkatesh Reddy', phone: '+91 98765 11111', email: 'venkatesh.reddy@gmail.com' },
        eventType: 'Authentic Andhra Wedding Feast',
        venueId: 'v3',
        date: '2026-06-15',
        status: 'Completed',
        subFunctions: [
          { id: 'sf-1', name: 'Traditional Andhra Lunch', guestCount: 500, menuItems: ['d_a1', 'd_a2', 'd_a6', 'd_a8', 'd_a9', 'd_a10', 'd_a12', 'd_a15', 'd_a18', 'd_a20', 'd_a22', 'd_a24', 'd_a31', 'd_a36', 'd_a37'] }
        ],
        execution: {
          teamRoutes: { 'd_a1': 'internal', 'd_a2': 'outsourced', 'd_a9': 'internal', 'd_a10': 'internal', 'd_a15': 'agency' },
          dishStatuses: { 'd_a1': 'Served', 'd_a2': 'Served', 'd_a9': 'Served', 'd_a10': 'Served', 'd_a15': 'Served' },
          costs: { rawMaterialsCost: 185000, laborCost: 45000, venueRent: 200000, otherExpenses: 25000 }
        },
        laborAllocations: [
          { agencyId: 'a1', laborType: 'Captain/Supervisor', count: 4, shifts: 2, totalPayout: 11200, status: 'Paid' },
          { agencyId: 'a1', laborType: 'Waiter / Service Staff', count: 35, shifts: 2, totalPayout: 63000, status: 'Paid' }
        ],
        billing: {
          pricePerPlate: 950, subtotal: 475000, taxRate: 18, taxAmount: 85500, totalAmount: 560500,
          advancePaid: 300000, balanceDue: 0, status: 'Fully Paid'
        }
      },
      {
        _id: 'EV-2026-002',
        customer: { name: 'Priya Sundaram', phone: '+91 99240 88888', email: 'priya.sundaram@yahoo.com' },
        eventType: 'Tamil Nadu Style Gala Breakfast & Evening High Tea',
        venueId: 'v1',
        date: '2026-07-28',
        status: 'Confirmed',
        subFunctions: [
          { id: 'sf-2', name: 'Tamil Nadu Traditional Breakfast', guestCount: 300, menuItems: ['d_tn1', 'd_tn2', 'd_tn3', 'd_tn7', 'd_tn8', 'd_tn9', 'd_tn12'] },
          { id: 'sf-3', name: 'Evening High Tea & Refreshments', guestCount: 250, menuItems: ['d_s1', 'd_s2', 'd_s5', 'd_s8', 'd_s9', 'd_s12', 'd_s14'] }
        ],
        execution: {
          teamRoutes: { 'd_tn1': 'internal', 'd_tn2': 'internal', 'd_tn7': 'internal', 'd_s5': 'outsourced', 'd_s8': 'agency' },
          dishStatuses: { 'd_tn1': 'Preparing', 'd_tn2': 'Preparing', 'd_tn7': 'Preparing', 'd_s5': 'Pending', 'd_s8': 'Pending' },
          costs: { rawMaterialsCost: 120000, laborCost: 28000, venueRent: 150000, otherExpenses: 15000 }
        },
        laborAllocations: [
          { agencyId: 'a1', laborType: 'Captain/Supervisor', count: 2, shifts: 1, totalPayout: 2800, status: 'Verified' },
          { agencyId: 'a1', laborType: 'Waiter / Service Staff', count: 20, shifts: 1, totalPayout: 18000, status: 'Verified' }
        ],
        billing: {
          pricePerPlate: 1100, subtotal: 605000, taxRate: 18, taxAmount: 108900, totalAmount: 713900,
          advancePaid: 350000, balanceDue: 363900, status: 'Partially Paid'
        }
      },
      {
        _id: 'EV-2026-003',
        customer: { name: 'Vikramaditya Rathore', phone: '+91 97129 33333', email: 'v.rathore@rajasthantech.com' },
        eventType: 'Royal Rajasthani Imperial Dinner',
        venueId: 'v2',
        date: '2026-08-20',
        status: 'Inquiry',
        subFunctions: [
          { id: 'sf-4', name: 'Royal Rajasthani Banquet', guestCount: 400, menuItems: ['d_r1', 'd_r2', 'd_r3', 'd_r9', 'd_r10', 'd_r13', 'd_r16', 'd_r19', 'd_r26', 'd_r28'] }
        ],
        execution: {
          teamRoutes: { 'd_r1': 'internal', 'd_r9': 'internal', 'd_r19': 'internal', 'd_r28': 'outsourced' },
          dishStatuses: { 'd_r1': 'Pending', 'd_r9': 'Pending', 'd_r19': 'Pending', 'd_r28': 'Pending' },
          costs: { rawMaterialsCost: 195000, laborCost: 48000, venueRent: 120000, otherExpenses: 20000 }
        },
        laborAllocations: [
          { agencyId: 'a1', laborType: 'Captain/Supervisor', count: 3, shifts: 1, totalPayout: 4200, status: 'Pending' },
          { agencyId: 'a1', laborType: 'Waiter / Service Staff', count: 30, shifts: 1, totalPayout: 27000, status: 'Pending' }
        ],
        billing: {
          pricePerPlate: 1400, subtotal: 560000, taxRate: 18, taxAmount: 100800, totalAmount: 660800,
          advancePaid: 0, balanceDue: 660800, status: 'Unpaid'
        }
      },
      {
        _id: 'EV-2026-004',
        customer: { name: 'Kavitha & Arvind Rao', phone: '+91 99887 66554', email: 'arvind.rao@techindia.io' },
        eventType: 'Grand Multi-Cuisine Extravaganza Dinner',
        venueId: 'v3',
        date: '2026-09-12',
        status: 'Confirmed',
        subFunctions: [
          { id: 'sf-5', name: 'Global Multi-Cuisine Gala Dinner', guestCount: 650, menuItems: ['d_d1', 'd_d4', 'd_d12', 'd_d15', 'd_d23', 'd_d26', 'd_d45', 'd_d47', 'd_d56', 'd_d64', 'd_d65', 'd_d81', 'd_d86', 'd_d102', 'd_d105', 'd_d110', 'd_d113'] }
        ],
        execution: {
          teamRoutes: { 'd_d15': 'agency', 'd_d26': 'outsourced', 'd_d45': 'internal', 'd_d65': 'internal', 'd_d81': 'internal' },
          dishStatuses: { 'd_d15': 'Pending', 'd_d26': 'Pending', 'd_d45': 'Pending', 'd_d65': 'Pending', 'd_d81': 'Pending' },
          costs: { rawMaterialsCost: 340000, laborCost: 85000, venueRent: 200000, otherExpenses: 40000 }
        },
        laborAllocations: [
          { agencyId: 'a1', laborType: 'Captain/Supervisor', count: 5, shifts: 2, totalPayout: 14000, status: 'Pending' },
          { agencyId: 'a1', laborType: 'Waiter / Service Staff', count: 45, shifts: 2, totalPayout: 81000, status: 'Pending' },
          { agencyId: 'a2', laborType: 'Bartender / Mixologist', count: 6, shifts: 1, totalPayout: 9600, status: 'Pending' }
        ],
        billing: {
          pricePerPlate: 1850, subtotal: 1202500, taxRate: 18, taxAmount: 216450, totalAmount: 1418950,
          advancePaid: 600000, balanceDue: 818950, status: 'Partially Paid'
        }
      }
    ];

    const defaultProfile = {
      _id: 'current_profile',
      name: 'Sri Mayyia Caterers',
      tagline: 'Legacy of Royal Flavors Since 1953',
      phone: '+91 99988 77766',
      email: 'info@srimayyiacaterers.com',
      address: 'No 43, 2nd Cross, Malleshwaram, Bangalore - 560003',
      gstin: '24AAAAA1111A1Z1',
      defaultTaxRate: 18,
      currency: '₹'
    };

    const adminPass = process.env.INITIAL_ADMIN_PASSWORD || '$2a$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeg6Lruj3vjPGga31lW';
    const initialUsers = [
      { _id: 'admin', password: adminPass.startsWith('$2a$') ? adminPass : bcrypt.hashSync(adminPass, 10), role: 'Admin' }
    ];

    const initialVessels = [
      { _id: 'ves_1', name: 'Aluminium Degchi (100 Litre)', category: 'Cooking Vessel', totalQty: 12, availableQty: 10, inUseQty: 2, damagedQty: 0, location: 'Kitchen Store A', valuePerUnit: 8500 },
      { _id: 'ves_2', name: 'Brass Biryani Handi (50L)', category: 'Cooking Vessel', totalQty: 8, availableQty: 6, inUseQty: 2, damagedQty: 0, location: 'Kitchen Store A', valuePerUnit: 12000 },
      { _id: 'ves_3', name: 'Stainless Steel Kadai (Big)', category: 'Cooking Vessel', totalQty: 15, availableQty: 12, inUseQty: 3, damagedQty: 0, location: 'Kitchen Store B', valuePerUnit: 4500 },
      { _id: 'ves_4', name: 'Chafing Dishes Roll-Top Set', category: 'Serving Gear', totalQty: 30, availableQty: 25, inUseQty: 5, damagedQty: 0, location: 'Banquet Store', valuePerUnit: 3200 },
      { _id: 'ves_5', name: 'Thermal Hot Transport Boxes (80L)', category: 'Serving Gear', totalQty: 20, availableQty: 18, inUseQty: 2, damagedQty: 0, location: 'Logistics Bay', valuePerUnit: 6500 },
      { _id: 'ves_6', name: 'Royal Melamine Dinner Plates (Set of 100)', category: 'Utensils', totalQty: 15, availableQty: 14, inUseQty: 1, damagedQty: 0, location: 'Crockery Rack', valuePerUnit: 4800 },
      { _id: 'ves_7', name: 'Commercial 3-Burner Gas Stove', category: 'Heating & Fuel', totalQty: 6, availableQty: 5, inUseQty: 1, damagedQty: 0, location: 'Kitchen Store B', valuePerUnit: 14500 }
    ];

    const initialProvisions = [
      { _id: 'prv_1', name: 'Royal Aged Basmati Rice', category: 'Grocery', unit: 'kg', stockQty: 450, reorderLevel: 100, costPerUnit: 110, supplierId: 's1' },
      { _id: 'prv_2', name: 'Premium Whole Wheat Atta', category: 'Grocery', unit: 'kg', stockQty: 300, reorderLevel: 75, costPerUnit: 45, supplierId: 's1' },
      { _id: 'prv_3', name: 'Pure Cow Desi Ghee', category: 'Ghee & Oils', unit: 'kg', stockQty: 85, reorderLevel: 25, costPerUnit: 650, supplierId: 's2' },
      { _id: 'prv_4', name: 'Refined Groundnut Oil', category: 'Ghee & Oils', unit: 'ltr', stockQty: 220, reorderLevel: 50, costPerUnit: 145, supplierId: 's1' },
      { _id: 'prv_5', name: 'Shahi Garam Masala Blend', category: 'Spices & Condiments', unit: 'kg', stockQty: 18, reorderLevel: 5, costPerUnit: 420, supplierId: 's1' },
      { _id: 'prv_6', name: 'Almonds & Cashew Nuts Mix', category: 'Dry Fruits', unit: 'kg', stockQty: 35, reorderLevel: 10, costPerUnit: 850, supplierId: 's1' }
    ];

    const initialVegetables = [
      { _id: 'veg_1', name: 'Nashik Red Onions', category: 'Vegetable', unit: 'kg', stockQty: 250, marketPrice: 35, freshnessStatus: 'Fresh', supplierId: 's3' },
      { _id: 'veg_2', name: 'Fresh Farm Potatoes', category: 'Vegetable', unit: 'kg', stockQty: 300, marketPrice: 30, freshnessStatus: 'Fresh', supplierId: 's3' },
      { _id: 'veg_3', name: 'Hybrid Tomatoes', category: 'Vegetable', unit: 'kg', stockQty: 120, marketPrice: 55, freshnessStatus: 'Fresh', supplierId: 's3' },
      { _id: 'veg_4', name: 'Fresh Cottage Cheese (Paneer)', category: 'Dairy & Fresh', unit: 'kg', stockQty: 60, marketPrice: 380, freshnessStatus: 'Fresh', supplierId: 's2' },
      { _id: 'veg_5', name: 'Fresh Mint & Coriander Leaves', category: 'Herbs & Greens', unit: 'bunch', stockQty: 80, marketPrice: 15, freshnessStatus: 'Fresh', supplierId: 's3' },
      { _id: 'veg_6', name: 'Seasonal Assorted Cut Fruits', category: 'Fruit', unit: 'kg', stockQty: 45, marketPrice: 120, freshnessStatus: '1-2 Days Left', supplierId: 's3' }
    ];

    const initialLabourWorkers = [
      { _id: 'lw_1', name: 'Master Chef Rameshwar Sharma', role: 'Head Chef', phone: '+91 98765 12001', dailyRate: 3500, agencyId: 'Direct Hire', type: 'Direct', status: 'Active' },
      { _id: 'lw_2', name: 'Sanjay Verma', role: 'Assistant Chef', phone: '+91 98765 12002', dailyRate: 2200, agencyId: 'Direct Hire', type: 'Direct', status: 'Active' },
      { _id: 'lw_3', name: 'Rajesh Kumar', role: 'Captain/Supervisor', phone: '+91 98111 22233', dailyRate: 1400, agencyId: 'a1', type: 'Agency', status: 'Active' },
      { _id: 'lw_4', name: 'Vikram Singh', role: 'Waiter / Service Staff', phone: '+91 98111 22234', dailyRate: 900, agencyId: 'a1', type: 'Agency', status: 'Active' },
      { _id: 'lw_5', name: 'Amit Patel', role: 'Kitchen Helper', phone: '+91 98980 44456', dailyRate: 750, agencyId: 'a2', type: 'Agency', status: 'Active' },
      { _id: 'lw_6', name: 'Dinesh Solanki', role: 'Utility Cleaner', phone: '+91 98980 44457', dailyRate: 650, agencyId: 'a2', type: 'Agency', status: 'Active' }
    ];

    // 3. Create items in Atlas
    await Promise.all([
      Venue.create(initialVenues),
      RawMaterial.create(initialRawMaterials),
      Dish.create(initialDishes),
      Supplier.create(initialSuppliers),
      LaborRate.create(initialLaborRates),
      Agency.create(initialAgencies),
      Event.create(initialEvents),
      CompanyProfile.create(defaultProfile),
      User.create(initialUsers),
      Vessel.create(initialVessels),
      Provision.create(initialProvisions),
      Vegetable.create(initialVegetables),
      LabourWorker.create(initialLabourWorkers)
    ]);

    res.json({ success: true, message: 'Seeded Cloud Database successfully for Sri Mayyia Caterers' });
  } catch (err) {
    console.error('Seeding error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Export Express app for Vercel Serverless Function execution
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`CaterFlow Enterprise API running on http://localhost:${PORT}`);
    
    if (MONGODB_URI) {
      connectDB().catch(err => {
        console.warn('MongoDB Atlas connection warning:', err.message);
      });
    }
  });
}

module.exports = app;
