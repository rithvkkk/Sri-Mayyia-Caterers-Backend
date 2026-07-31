const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
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
app.use(express.json());

// Database connection helper
async function connectDB() {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }
  console.log('🔄 Connecting to MongoDB Atlas...');
  return mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 5000
  }).then((m) => {
    console.log('✅ Connected to MongoDB online');
    return m;
  });
}

// Middleware to ensure DB connection
app.use(async (req, res, next) => {
  if (req.path === '/' || req.path === '/status' || req.path === '/api/status') return next();
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error('❌ DB connection failed:', err);
    res.status(500).json({ error: `Database Connection Failed: ${err.message || String(err)}` });
  }
});

app.get('/', (req, res) => {
  res.send('<h2>👑 CaterFlow Enterprise Catering API is Online!</h2><p>Connect your frontend React client to this URL.</p>');
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
  category: { type: String, required: true }, // Starters, Mains, Desserts, Beverages
  price: { type: Number, required: true },
  recipe: [recipeItemSchema]
});
const Dish = mongoose.model('Dish', dishSchema);

// 4. Supplier
const supplierSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  name: { type: String, required: true },
  category: { type: String, required: true }, // Grocery, Dairy, Veg/Fruit, Fuel
  contact: { type: String, required: true },
  phone: { type: String, required: true }
});
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
  role: { type: String, required: true } // Admin, Manager, Chef, Accountant, Agency
});
const User = mongoose.model('User', userSchema);


// 8. Event
const subFunctionSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, required: true },
  guestCount: { type: Number, required: true },
  menuItems: [{ type: String }] // Array of dish IDs
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

const eventSchema = new mongoose.Schema({
  _id: { type: String, required: true }, // EV-YYYY-XXX
  customer: {
    name: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true }
  },
  eventType: { type: String, required: true },
  venueId: { type: String, required: true },
  date: { type: String, required: true },
  status: { type: String, default: 'Inquiry' }, // Inquiry, Confirmed, Completed, Cancelled
  subFunctions: [subFunctionSchema],
  manualMaterials: [manualMaterialSchema],
  execution: {
    teamRoutes: { type: Map, of: String }, // dishId -> 'internal' | 'outsourced' | 'agency'
    dishStatuses: { type: Map, of: String }, // dishId -> preparation status
    costs: {
      rawMaterialsCost: { type: Number, default: 0 },
      laborCost: { type: Number, default: 0 },
      venueRent: { type: Number, default: 0 },
      otherExpenses: { type: Number, default: 0 }
    }
  },
  laborAllocations: [laborAllocationSchema],
  billing: {
    pricePerPlate: { type: Number, required: true },
    subtotal: { type: Number, default: 0 },
    taxRate: { type: Number, default: 18 },
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
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const user = await User.create({ _id: id, password: hashedPassword, role });
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
      updateData.password = crypto.createHash('sha256').update(password).digest('hex');
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

// Dedicated login validation route
app.post('/api/users/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const user = await User.findById(username.toLowerCase());
    if (!user) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }
    const inputHash = crypto.createHash('sha256').update(password).digest('hex');
    if (user.password === inputHash) {
      return res.json({ success: true, role: user.role });
    }
    res.json({ success: false, message: 'Invalid credentials' });
  } catch (err) {
    res.status(500).json({ error: err.message });
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

    const initialDishes = [
      {
        _id: 'd1',
        name: 'Paneer Tikka Angara',
        category: 'Starters',
        price: 180,
        recipe: [
          { materialId: 'rm9', quantity: 0.12 },
          { materialId: 'rm11', quantity: 0.02 },
          { materialId: 'rm4', quantity: 0.01 },
          { materialId: 'rm5', quantity: 0.015 },
          { materialId: 'rm21', quantity: 0.05 }
        ]
      },
      {
        _id: 'd2',
        name: 'Veg Manchurian Dry',
        category: 'Starters',
        price: 150,
        recipe: [
          { materialId: 'rm15', quantity: 0.10 },
          { materialId: 'rm8', quantity: 0.02 },
          { materialId: 'rm2', quantity: 0.03 },
          { materialId: 'rm5', quantity: 0.02 },
          { materialId: 'rm20', quantity: 0.005 }
        ]
      },
      {
        _id: 'd3',
        name: 'Hara Bhara Kabab',
        category: 'Starters',
        price: 140,
        recipe: [
          { materialId: 'rm15', quantity: 0.08 },
          { materialId: 'rm16', quantity: 0.05 },
          { materialId: 'rm5', quantity: 0.025 },
          { materialId: 'rm4', quantity: 0.005 }
        ]
      },
      {
        _id: 'd4',
        name: 'Dal Makhani Special',
        category: 'Mains',
        price: 220,
        recipe: [
          { materialId: 'rm6', quantity: 0.08 },
          { materialId: 'rm10', quantity: 0.025 },
          { materialId: 'rm11', quantity: 0.02 },
          { materialId: 'rm4', quantity: 0.008 },
          { materialId: 'rm20', quantity: 0.008 }
        ]
      },
      {
        _id: 'd5',
        name: 'Shahi Kadhai Paneer',
        category: 'Mains',
        price: 250,
        recipe: [
          { materialId: 'rm9', quantity: 0.12 },
          { materialId: 'rm17', quantity: 0.06 },
          { materialId: 'rm11', quantity: 0.015 },
          { materialId: 'rm4', quantity: 0.01 },
          { materialId: 'rm5', quantity: 0.015 },
          { materialId: 'rm20', quantity: 0.006 }
        ]
      },
      {
        _id: 'd6',
        name: 'Jeera Rice / Veg Pulao',
        category: 'Mains',
        price: 130,
        recipe: [
          { materialId: 'rm1', quantity: 0.10 },
          { materialId: 'rm15', quantity: 0.04 },
          { materialId: 'rm14', quantity: 0.01 },
          { materialId: 'rm20', quantity: 0.004 }
        ]
      },
      {
        _id: 'd7',
        name: 'Butter Naan / Tandoori Roti',
        category: 'Mains',
        price: 40,
        recipe: [
          { materialId: 'rm2', quantity: 0.08 },
          { materialId: 'rm10', quantity: 0.015 },
          { materialId: 'rm21', quantity: 0.06 }
        ]
      },
      {
        _id: 'd8',
        name: 'Gulab Jamun (Double)',
        category: 'Desserts',
        price: 80,
        recipe: [
          { materialId: 'rm13', quantity: 0.06 },
          { materialId: 'rm3', quantity: 0.10 },
          { materialId: 'rm14', quantity: 0.015 },
          { materialId: 'rm20', quantity: 0.008 }
        ]
      },
      {
        _id: 'd9',
        name: 'Kesar Pista Ice Cream',
        category: 'Desserts',
        price: 90,
        recipe: [
          { materialId: 'rm12', quantity: 0.15 },
          { materialId: 'rm3', quantity: 0.02 },
          { materialId: 'rm19', quantity: 0.01 }
        ]
      },
      {
        _id: 'd10',
        name: 'Fresh Mint Mojito',
        category: 'Beverages',
        price: 100,
        recipe: [
          { materialId: 'rm18', quantity: 0.05 },
          { materialId: 'rm3', quantity: 0.025 }
        ]
      },
      {
        _id: 'd11',
        name: 'Masala Shahi Tea',
        category: 'Beverages',
        price: 40,
        recipe: [
          { materialId: 'rm12', quantity: 0.08 },
          { materialId: 'rm7', quantity: 0.006 },
          { materialId: 'rm3', quantity: 0.015 },
          { materialId: 'rm4', quantity: 0.002 }
        ]
      }
    ];

    const initialSuppliers = [
      { _id: 's1', name: 'Krishna Grocery Wholesalers', category: 'Grocery', contact: 'Ramesh Patel', phone: '+91 98765 43210' },
      { _id: 's2', name: 'Amul Dairy Distributors', category: 'Dairy', contact: 'Suresh Shah', phone: '+91 98250 12345' },
      { _id: 's3', name: 'Green Market Fresh Produce', category: 'Veg/Fruit', contact: 'Vijay Khetan', phone: '+91 99099 87654' },
      { _id: 's4', name: 'HP Commercial Gas Corp', category: 'Fuel', contact: 'Dinesh Mehta', phone: '+91 97243 55566' }
    ];

    const initialLaborRates = [
      { _id: 'l1', type: 'Captain/Supervisor', rate: 1200 },
      { _id: 'l2', type: 'Waiter / Service Staff', rate: 800 },
      { _id: 'l3', type: 'Bartender', rate: 1500 },
      { _id: 'l4', type: 'Kitchen Helper', rate: 700 },
      { _id: 'l5', type: 'Utility Cleaner', rate: 600 }
    ];

    const initialAgencies = [
      { _id: 'a1', name: 'Royal Hospitality Services', contact: 'Harsh Vyas', phone: '+91 98111 22233', categories: ['Waiter / Service Staff', 'Captain/Supervisor'] },
      { _id: 'a2', name: 'Apex Event Staffing Co', contact: 'Nikhil Parmar', phone: '+91 98980 44455', categories: ['Bartender', 'Kitchen Helper', 'Utility Cleaner'] }
    ];

    const initialEvents = [
      {
        _id: 'EV-2026-001',
        customer: { name: 'Anil Sharma', phone: '+91 98765 11111', email: 'anil.sharma@gmail.com' },
        eventType: 'Wedding Reception',
        venueId: 'v3',
        date: '2026-06-15',
        status: 'Completed',
        subFunctions: [
          { id: 'sf-1', name: 'Wedding Lunch', guestCount: 400, menuItems: ['d1', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd11'] },
          { id: 'sf-2', name: 'Grand Reception Dinner', guestCount: 600, menuItems: ['d1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'd10', 'd11'] }
        ],
        execution: {
          teamRoutes: {
            'd1': 'internal', 'd2': 'outsourced', 'd3': 'internal', 'd4': 'internal', 'd5': 'agency',
            'd6': 'internal', 'd7': 'agency', 'd8': 'internal', 'd9': 'outsourced', 'd10': 'agency', 'd11': 'internal'
          },
          dishStatuses: {
            'd1': 'Served', 'd2': 'Served', 'd3': 'Served', 'd4': 'Served', 'd5': 'Served',
            'd6': 'Served', 'd7': 'Served', 'd8': 'Served', 'd9': 'Served', 'd10': 'Served', 'd11': 'Served'
          },
          costs: { rawMaterialsCost: 285000, laborCost: 65000, venueRent: 200000, otherExpenses: 45000 }
        },
        laborAllocations: [
          { agencyId: 'a1', laborType: 'Captain/Supervisor', count: 4, shifts: 2, totalPayout: 9600, status: 'Paid' },
          { agencyId: 'a1', laborType: 'Waiter / Service Staff', count: 30, shifts: 2, totalPayout: 48000, status: 'Paid' },
          { agencyId: 'a2', laborType: 'Bartender', count: 4, shifts: 1, totalPayout: 6000, status: 'Paid' }
        ],
        billing: {
          pricePerPlate: 950, subtotal: 950000, taxRate: 18, taxAmount: 171000, totalAmount: 1121000,
          advancePaid: 500000, balanceDue: 0, status: 'Fully Paid'
        }
      },
      {
        _id: 'EV-2026-002',
        customer: { name: 'Preeti Patel', phone: '+91 99240 88888', email: 'preeti.patel@yahoo.com' },
        eventType: '25th Anniversary Gala',
        venueId: 'v1',
        date: '2026-07-28',
        status: 'Confirmed',
        subFunctions: [
          { id: 'sf-3', name: 'Anniversary Dinner', guestCount: 250, menuItems: ['d1', 'd2', 'd5', 'd6', 'd7', 'd9', 'd10'] }
        ],
        execution: {
          teamRoutes: {
            'd1': 'internal', 'd2': 'internal', 'd5': 'internal', 'd6': 'internal', 'd7': 'agency',
            'd9': 'outsourced', 'd10': 'agency'
          },
          dishStatuses: {
            'd1': 'Pending', 'd2': 'Pending', 'd5': 'Pending', 'd6': 'Pending', 'd7': 'Pending',
            'd9': 'Pending', 'd10': 'Pending'
          },
          costs: { rawMaterialsCost: 85200, laborCost: 18600, venueRent: 150000, otherExpenses: 12000 }
        },
        laborAllocations: [
          { agencyId: 'a1', laborType: 'Captain/Supervisor', count: 2, shifts: 1, totalPayout: 2400, status: 'Verified' },
          { agencyId: 'a1', laborType: 'Waiter / Service Staff', count: 15, shifts: 1, totalPayout: 12000, status: 'Verified' },
          { agencyId: 'a2', laborType: 'Bartender', count: 2, shifts: 1, totalPayout: 3000, status: 'Verified' },
          { agencyId: 'a2', laborType: 'Utility Cleaner', count: 2, shifts: 1, totalPayout: 1200, status: 'Pending' }
        ],
        billing: {
          pricePerPlate: 1200, subtotal: 300000, taxRate: 18, taxAmount: 54000, totalAmount: 354000,
          advancePaid: 150000, balanceDue: 204000, status: 'Partially Paid'
        }
      },
      {
        _id: 'EV-2026-003',
        customer: { name: 'Rohan Mehta (Adani Group)', phone: '+91 97129 33333', email: 'rohan.mehta@adani.com' },
        eventType: 'Corporate Annual Meet',
        venueId: 'v4',
        date: '2026-08-10',
        status: 'Inquiry',
        subFunctions: [
          { id: 'sf-4', name: 'Conference Lunch', guestCount: 120, menuItems: ['d3', 'd4', 'd6', 'd7', 'd8', 'd11'] }
        ],
        execution: {
          teamRoutes: {
            'd3': 'internal', 'd4': 'internal', 'd6': 'internal', 'd7': 'internal', 'd8': 'internal', 'd11': 'internal'
          },
          dishStatuses: {
            'd3': 'Pending', 'd4': 'Pending', 'd6': 'Pending', 'd7': 'Pending', 'd8': 'Pending', 'd11': 'Pending'
          },
          costs: { rawMaterialsCost: 28400, laborCost: 6800, venueRent: 75000, otherExpenses: 5000 }
        },
        laborAllocations: [
          { agencyId: 'a1', laborType: 'Captain/Supervisor', count: 1, shifts: 1, totalPayout: 1200, status: 'Pending' },
          { agencyId: 'a1', laborType: 'Waiter / Service Staff', count: 7, shifts: 1, totalPayout: 5600, status: 'Pending' }
        ],
        billing: {
          pricePerPlate: 850, subtotal: 102000, taxRate: 18, taxAmount: 18360, totalAmount: 120360,
          advancePaid: 0, balanceDue: 120360, status: 'Unpaid'
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

    const initialUsers = [
      { _id: 'admin', password: crypto.createHash('sha256').update('admin123').digest('hex'), role: 'Admin' },
      { _id: 'manager', password: crypto.createHash('sha256').update('manager123').digest('hex'), role: 'Manager' },
      { _id: 'chef', password: crypto.createHash('sha256').update('chef123').digest('hex'), role: 'Chef' },
      { _id: 'accountant', password: crypto.createHash('sha256').update('accountant123').digest('hex'), role: 'Accountant' },
      { _id: 'agency', password: crypto.createHash('sha256').update('agency123').digest('hex'), role: 'Agency' }
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
    console.error('❌ Seeding error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Start listening locally (non-blocking start so sandbox environments can run the process)
app.listen(PORT, () => {
  console.log(`👑 CaterFlow Enterprise API running on http://localhost:${PORT}`);
  
  if (MONGODB_URI) {
    connectDB().catch(err => {
      console.warn('⚠️ MongoDB Atlas connection warning (expected in sandboxed environments):', err.message);
      console.warn('The API server is successfully running and will retry connection on client requests.');
    });
  } else {
    console.error('❌ MONGODB_URI is not set in backend/.env!');
  }
});
