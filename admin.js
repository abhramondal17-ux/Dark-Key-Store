/**
 * CARROM POOL AUTOPLAY ENGINE STORE - FULL ADMINISTRATIVE SYSTEM
 * Complete Claymorphism Dashboard, Inventory Control, Payment Verification & Settings Engine
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

function createAdminRouter({ dbModels, fulfillOrderWithKey, ADMIN_SETUP_SECRET, JWT_SECRET }) {
  const router = express.Router();
  const { User, Product, InventoryKey, Order, WalletLedger, SupportTicket, StoreSetting, AuditLog } = dbModels;

  // ------------------------------------------
  // ADMINISTRATIVE AUTHENTICATION MIDDLEWARES
  // ------------------------------------------
  async function adminAuth(req, res, next) {
    const token = req.cookies.admin_token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
    if (!token) {
      return res.status(401).json({ success: false, error: 'Unauthorized: Admin token required.' });
    }
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role !== 'SUPER_ADMIN' && decoded.role !== 'SUPPORT_AGENT') {
        return res.status(403).json({ success: false, error: 'Access forbidden: Insufficient administrative privileges.' });
      }
      req.admin = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ success: false, error: 'Session expired or invalid. Please re-login.' });
    }
  }

  // ------------------------------------------
  // 1. BOOTSTRAP INITIAL SUPER ADMIN
  // ------------------------------------------
  router.post('/api/setup-bootstrap', async (req, res) => {
    try {
      const { setupSecret, email, fullName, password } = req.body;
      if (!setupSecret || setupSecret !== ADMIN_SETUP_SECRET) {
        return res.status(403).json({ success: false, error: 'Invalid administrator setup secret.' });
      }

      const existingSuperAdmin = await User.findOne({ role: 'SUPER_ADMIN' });
      if (existingSuperAdmin) {
        return res.status(400).json({ success: false, error: 'Initial administrator setup has already been completed.' });
      }

      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);

      const admin = new User({
        fullName: fullName || 'Super Administrator',
        email: email.toLowerCase().trim(),
        mobile: '0000000000',
        passwordHash,
        role: 'SUPER_ADMIN',
      });
      await admin.save();

      await AuditLog.create({
        actorEmail: admin.email,
        action: 'BOOTSTRAP_ADMIN_SETUP',
        details: { message: 'Initial super admin established.' },
      });

      res.json({ success: true, message: 'Super admin successfully created. You can now log into /admin.' });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 2. ADMIN LOGIN & SESSION
  // ------------------------------------------
  router.post('/api/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email: email.toLowerCase().trim() });
      if (!user || (user.role !== 'SUPER_ADMIN' && user.role !== 'SUPPORT_AGENT')) {
        return res.status(401).json({ success: false, error: 'Invalid administrative credentials.' });
      }

      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ success: false, error: 'Invalid administrative credentials.' });
      }

      const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '2d' });
      res.cookie('admin_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 2 * 86400 * 1000,
      });

      res.json({
        success: true,
        admin: { id: user._id, fullName: user.fullName, email: user.email, role: user.role },
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  router.post('/api/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true, message: 'Logged out of admin console.' });
  });

  // ------------------------------------------
  // 3. STATISTICAL METRICS (COMPREHENSIVE)
  // ------------------------------------------
  router.get('/api/metrics', adminAuth, async (req, res) => {
    try {
      const totalUsers = await User.countDocuments({ role: 'CUSTOMER' });
      const totalProducts = await Product.countDocuments();
      const availableKeys = await InventoryKey.countDocuments({ status: 'AVAILABLE' });
      const assignedKeys = await InventoryKey.countDocuments({ status: 'ASSIGNED' });
      const totalOrders = await Order.countDocuments();
      const awaitingVerification = await Order.countDocuments({ paymentStatus: 'AWAITING_VERIFICATION' });
      const completedOrders = await Order.countDocuments({ orderStatus: 'COMPLETED' });

      // Calculate Gross Payment Volume
      const paidOrders = await Order.find({ paymentStatus: 'PAID' }, 'amountPaise');
      const grossPaise = paidOrders.reduce((acc, curr) => acc + curr.amountPaise, 0);

      const openTickets = await SupportTicket.countDocuments({ status: 'OPEN' });

      res.json({
        success: true,
        metrics: {
          totalUsers,
          totalProducts,
          availableKeys,
          assignedKeys,
          totalOrders,
          awaitingVerification,
          completedOrders,
          grossVolumeRupees: (grossPaise / 100).toFixed(2),
          openTickets,
        },
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 4. MANUAL INVENTORY KEYS BULK INGESTION
  // ------------------------------------------
  router.post('/api/keys/import', adminAuth, async (req, res) => {
    try {
      const { productId, rawKeysText } = req.body;
      if (!productId || !rawKeysText) {
        return res.status(400).json({ success: false, error: 'Product ID and raw keys required.' });
      }

      const product = await Product.findOne({ productId });
      if (!product) {
        return res.status(404).json({ success: false, error: 'Target product not found.' });
      }

      // Parse multiline keys and strip empty lines
      const lines = rawKeysText
        .split('\n')
        .map((k) => k.trim())
        .filter((k) => k.length > 0);

      if (lines.length === 0) {
        return res.status(400).json({ success: false, error: 'No valid keys provided.' });
      }

      const docsToInsert = lines.map((keySecret) => ({
        keyId: 'KEY_' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        productId,
        keySecret,
        status: 'AVAILABLE',
      }));

      await InventoryKey.insertMany(docsToInsert);

      await AuditLog.create({
        actorEmail: req.admin.email,
        action: 'IMPORT_KEYS',
        target: productId,
        details: { count: docsToInsert.length },
      });

      res.json({ success: true, count: docsToInsert.length });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 5. MANUAL PAYMENT APPROVAL & FULFILLMENT
  // ------------------------------------------
  router.post('/api/orders/:orderId/verify-payment', adminAuth, async (req, res) => {
    try {
      const { approve, rejectionReason } = req.body;
      const order = await Order.findOne({ orderId: req.params.orderId });

      if (!order) {
        return res.status(404).json({ success: false, error: 'Order not found.' });
      }

      if (order.paymentStatus === 'PAID' && order.orderStatus === 'COMPLETED') {
        return res.status(400).json({ success: false, error: 'Order is already marked PAID and completed.' });
      }

      if (approve) {
        // Run atomic assignment and mark paid
        const fulfilled = await fulfillOrderWithKey(order);
        await AuditLog.create({
          actorEmail: req.admin.email,
          action: 'MANUAL_PAYMENT_APPROVED',
          target: order.orderId,
          details: { assignedKey: fulfilled.assignedKeySecret },
        });
        return res.json({ success: true, order: fulfilled });
      } else {
        order.paymentStatus = 'REJECTED';
        order.orderStatus = 'CANCELLED';
        order.adminNotes = rejectionReason || 'Payment reference could not be verified by admin.';
        await order.save();

        await AuditLog.create({
          actorEmail: req.admin.email,
          action: 'MANUAL_PAYMENT_REJECTED',
          target: order.orderId,
          details: { reason: order.adminNotes },
        });

        return res.json({ success: true, order });
      }
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 6. PRODUCT CRUD CONTROLS
  // ------------------------------------------
  router.get('/api/products', adminAuth, async (req, res) => {
    try {
      const products = await Product.find({}).sort({ sortOrder: 1, createdAt: -1 });
      res.json({ success: true, products });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  router.post('/api/products/save', adminAuth, async (req, res) => {
    try {
      const { productId, name, description, priceRupees, durationDays, category, imageUrl, isActive, isFeatured } = req.body;
      if (!name || !priceRupees || !durationDays) {
        return res.status(400).json({ success: false, error: 'Name, price, and duration are required.' });
      }

      const pricePaise = Math.round(parseFloat(priceRupees) * 100);
      const generatedId = productId || 'PROD_' + Date.now();

      const product = await Product.findOneAndUpdate(
        { productId: generatedId },
        {
          $set: {
            productId: generatedId,
            name: name.trim(),
            description: description || '',
            pricePaise,
            durationDays: parseInt(durationDays),
            category: category || 'General',
            imageUrl: imageUrl || '',
            isActive: isActive !== undefined ? isActive : true,
            isFeatured: isFeatured !== undefined ? isFeatured : false,
          },
        },
        { upsert: true, new: true }
      );

      res.json({ success: true, product });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 7. ORDER MANAGEMENT & SEARCH
  // ------------------------------------------
  router.get('/api/orders', adminAuth, async (req, res) => {
    try {
      const filter = {};
      if (req.query.status) filter.paymentStatus = req.query.status;
      const orders = await Order.find(filter).sort({ createdAt: -1 }).limit(100);
      res.json({ success: true, orders });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 8. STORE SETTINGS MANAGEMENT
  // ------------------------------------------
  router.get('/api/settings', adminAuth, async (req, res) => {
    try {
      const settingsDocs = await StoreSetting.find({});
      const map = {};
      settingsDocs.forEach((d) => (map[d.key] = d.value));
      res.json({ success: true, settings: map });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  router.post('/api/settings', adminAuth, async (req, res) => {
    try {
      const updates = req.body;
      for (const [key, value] of Object.entries(updates)) {
        await StoreSetting.findOneAndUpdate({ key }, { $set: { key, value } }, { upsert: true });
      }
      res.json({ success: true, message: 'Settings saved successfully.' });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 9. SUPPORT TICKETS RESOLUTION
  // ------------------------------------------
  router.get('/api/support/tickets', adminAuth, async (req, res) => {
    try {
      const tickets = await SupportTicket.find({}).sort({ updatedAt: -1 }).limit(50);
      res.json({ success: true, tickets });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  router.post('/api/support/tickets/:ticketId/reply', adminAuth, async (req, res) => {
    try {
      const { message, status } = req.body;
      const ticket = await SupportTicket.findOne({ ticketId: req.params.ticketId });
      if (!ticket) return res.status(404).json({ success: false, error: 'Ticket not found.' });

      ticket.messages.push({
        sender: 'STAFF',
        senderName: 'Support Agent (' + req.admin.email + ')',
        message: message.trim(),
      });
      if (status) ticket.status = status;
      ticket.updatedAt = new Date();
      await ticket.save();

      res.json({ success: true, ticket });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ------------------------------------------
  // 10. ADMINISTRATIVE CONSOLE SINGLE-PAGE UI
  // ------------------------------------------
  router.get('*', (req, res) => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard — Engine Portal</title>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #121929;
      --clay-surface: linear-gradient(145deg, #162035, #0e1422);
      --clay-accent: #00f2fe;
      --neon-orange: #ff5858;
      --text: #f0f4fc;
      --text-muted: #8292ab;
      --clay-shadow: 10px 10px 22px #04060a, -6px -6px 14px rgba(255,255,255,0.03);
      --radius: 16px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; }

    /* SIDEBAR */
    .sidebar {
      width: 260px;
      background: #0d121e;
      border-right: 1px solid rgba(255,255,255,0.06);
      padding: 24px 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .nav-item {
      padding: 12px 16px;
      border-radius: 12px;
      color: var(--text-muted);
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 600;
      margin-bottom: 6px;
      transition: all 0.2s;
    }
    .nav-item.active, .nav-item:hover { background: rgba(0,242,254,0.1); color: var(--clay-accent); }

    /* CONTENT PANEL */
    .main-content { flex: 1; padding: 32px; overflow-y: auto; height: 100vh; }
    .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px; }

    /* CLAY COMPONENTS */
    .clay-box {
      background: var(--clay-surface);
      border-radius: var(--radius);
      box-shadow: var(--clay-shadow);
      border: 1px solid rgba(255,255,255,0.05);
      padding: 24px;
      margin-bottom: 24px;
    }
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-card { padding: 20px; }
    .stat-val { font-size: 1.8rem; font-weight: 800; color: var(--clay-accent); margin-top: 6px; }

    .clay-btn {
      background: linear-gradient(135deg, #00f2fe, #4facfe);
      color: #090d16;
      font-weight: 700;
      padding: 10px 18px;
      border-radius: 12px;
      border: none;
      cursor: pointer;
    }
    .form-input {
      width: 100%;
      padding: 12px;
      border-radius: 10px;
      background: #0a0e17;
      border: 1px solid rgba(255,255,255,0.1);
      color: #fff;
      margin-top: 6px;
      margin-bottom: 14px;
    }

    /* TABLE */
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 0.9rem; }
    th { color: var(--text-muted); font-weight: 700; }
  </style>
</head>
<body>

  <!-- ADMIN SIDEBAR -->
  <aside class="sidebar">
    <div>
      <div style="font-weight:800; font-size:1.15rem; margin-bottom:28px; color:var(--clay-accent);">LUFFY ADMIN</div>
      <div class="nav-item active" onclick="showTab('dashboard')">📊 Metrics Overview</div>
      <div class="nav-item" onclick="showTab('payments')">💳 Payment Verification</div>
      <div class="nav-item" onclick="showTab('inventory')">🔑 Key Inventory</div>
      <div class="nav-item" onclick="showTab('products')">📦 Engine Products</div>
      <div class="nav-item" onclick="showTab('settings')">⚙️ Store Settings</div>
      <div class="nav-item" onclick="showTab('support')">💬 Support Center</div>
    </div>
    <div class="nav-item" onclick="adminLogout()" style="color:var(--neon-orange);">🚪 Logout</div>
  </aside>

  <!-- CONTENT -->
  <main class="main-content">
    <div class="header-bar">
      <h2 id="viewHeading">Dashboard Overview</h2>
      <div id="adminUserBadge">Logged in as Admin</div>
    </div>

    <!-- METRICS VIEW -->
    <div id="dashboardView">
      <div class="stat-grid" id="statCards">
        <div class="clay-box stat-card"><div>Gross Volume</div><div class="stat-val" id="statGross">₹0.00</div></div>
        <div class="clay-box stat-card"><div>Pending Payments</div><div class="stat-val" id="statPending" style="color:#ffaa00;">0</div></div>
        <div class="clay-box stat-card"><div>Available Stock Keys</div><div class="stat-val" id="statStock">0</div></div>
        <div class="clay-box stat-card"><div>Completed Orders</div><div class="stat-val" id="statCompleted">0</div></div>
      </div>
    </div>

    <!-- MANUAL PAYMENT VERIFICATION VIEW -->
    <div id="paymentsView" style="display:none;">
      <div class="clay-box">
        <h3>Pending Manual UPI Verifications</h3>
        <table>
          <thead>
            <tr>
              <th>Order ID</th>
              <th>Product</th>
              <th>Amount</th>
              <th>UTR / Reference</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="paymentTableBody">
            <tr><td colspan="5">Loading pending payments...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- INVENTORY INGESTION VIEW -->
    <div id="inventoryView" style="display:none;">
      <div class="clay-box">
        <h3>Bulk Add Product Keys</h3>
        <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:16px;">
          Paste raw keys one per line. They will be stored as AVAILABLE inventory.
        </p>
        <label>Select Engine Product</label>
        <select id="importProductId" class="form-input"></select>
        <label>Keys List (One key per line)</label>
        <textarea id="rawKeysText" class="form-input" rows="6" placeholder="KEY-LUFFY-1001\nKEY-LUFFY-1002"></textarea>
        <button class="clay-btn" onclick="submitKeysImport()">Import Keys Atomically</button>
      </div>
    </div>

    <!-- PRODUCTS MANAGEMENT VIEW -->
    <div id="productsView" style="display:none;">
      <div class="clay-box">
        <h3>Configure Engine Subscription Products</h3>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
          <div>
            <label>Product Name</label>
            <input type="text" id="pName" class="form-input" placeholder="Luffy VIP 7-Days">
          </div>
          <div>
            <label>Price (INR)</label>
            <input type="number" id="pPrice" class="form-input" placeholder="399">
          </div>
          <div>
            <label>Duration (Days)</label>
            <input type="number" id="pDuration" class="form-input" placeholder="7">
          </div>
          <div>
            <label>Category</label>
            <input type="text" id="pCategory" class="form-input" placeholder="VIP Engines">
          </div>
        </div>
        <button class="clay-btn" onclick="saveProduct()">Save Product</button>
      </div>
    </div>

    <!-- SETTINGS VIEW -->
    <div id="settingsView" style="display:none;">
      <div class="clay-box">
        <h3>Store & Gateway Settings</h3>
        <label>Manual UPI ID</label>
        <input type="text" id="setUpiId" class="form-input">
        <label>Payee Name</label>
        <input type="text" id="setPayee" class="form-input">
        <label>Enable Wallet Payments (true/false)</label>
        <input type="text" id="setWallet" class="form-input">
        <button class="clay-btn" onclick="saveSettings()">Save Settings</button>
      </div>
    </div>

    <!-- SUPPORT TICKETS VIEW -->
    <div id="supportView" style="display:none;">
      <div class="clay-box">
        <h3>Customer Support Management</h3>
        <div id="ticketContainer"></div>
      </div>
    </div>
  </main>

  <script>
    async function loadMetrics() {
      try {
        const res = await fetch('/admin/api/metrics');
        const data = await res.json();
        if (data.success) {
          const m = data.metrics;
          document.getElementById('statGross').innerText = '₹' + m.grossVolumeRupees;
          document.getElementById('statPending').innerText = m.awaitingVerification;
          document.getElementById('statStock').innerText = m.availableKeys;
          document.getElementById('statCompleted').innerText = m.completedOrders;
        }
      } catch (e) {}
    }

    async function loadPayments() {
      try {
        const res = await fetch('/admin/api/orders?status=AWAITING_VERIFICATION');
        const data = await res.json();
        const tbody = document.getElementById('paymentTableBody');
        if (!data.success || data.orders.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5">No pending manual payments.</td></tr>';
          return;
        }
        tbody.innerHTML = data.orders.map(o => \`
          <tr>
            <td>\${o.orderId}</td>
            <td>\${o.productName}</td>
            <td>₹\${(o.amountPaise/100).toFixed(2)}</td>
            <td><strong style="color:var(--clay-accent);">\${o.manualUpiTxnRef || 'N/A'}</strong></td>
            <td>
              <button class="clay-btn" style="padding:6px 12px; font-size:0.8rem;" onclick="verifyPayment('\${o.orderId}', true)">Approve</button>
              <button class="clay-btn" style="padding:6px 12px; font-size:0.8rem; background:var(--neon-orange);" onclick="verifyPayment('\${o.orderId}', false)">Reject</button>
            </td>
          </tr>
        \`).join('');
      } catch (e) {}
    }

    async function verifyPayment(orderId, approve) {
      await fetch('/admin/api/orders/' + orderId + '/verify-payment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approve })
      });
      loadPayments();
      loadMetrics();
    }

    async function submitKeysImport() {
      const productId = document.getElementById('importProductId').value;
      const rawKeysText = document.getElementById('rawKeysText').value;
      const res = await fetch('/admin/api/keys/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ productId, rawKeysText })
      });
      const data = await res.json();
      if (data.success) {
        alert('Successfully imported ' + data.count + ' keys!');
        document.getElementById('rawKeysText').value = '';
        loadMetrics();
      } else {
        alert('Import failed: ' + data.error);
      }
    }

    async function loadProductsList() {
      const res = await fetch('/admin/api/products');
      const data = await res.json();
      if (data.success) {
        const sel = document.getElementById('importProductId');
        sel.innerHTML = data.products.map(p => \`<option value="\${p.productId}">\${p.name} (\${p.productId})</option>\`).join('');
      }
    }

    async function saveProduct() {
      const name = document.getElementById('pName').value;
      const priceRupees = document.getElementById('pPrice').value;
      const durationDays = document.getElementById('pDuration').value;
      const category = document.getElementById('pCategory').value;

      await fetch('/admin/api/products/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, priceRupees, durationDays, category })
      });
      alert('Product saved!');
      loadProductsList();
    }

    async function saveSettings() {
      const upiId = document.getElementById('setUpiId').value;
      const upiPayeeName = document.getElementById('setPayee').value;
      const walletEnabled = document.getElementById('setWallet').value === 'true';

      await fetch('/admin/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ upiId, upiPayeeName, walletEnabled })
      });
      alert('Store settings updated!');
    }

    async function adminLogout() {
      await fetch('/admin/api/logout', { method: 'POST' });
      window.location.reload();
    }

    function showTab(tab) {
      ['dashboard', 'payments', 'inventory', 'products', 'settings', 'support'].forEach(t => {
        const el = document.getElementById(t + 'View');
        if (el) el.style.display = t === tab ? 'block' : 'none';
      });
      if (tab === 'dashboard') loadMetrics();
      if (tab === 'payments') loadPayments();
      if (tab === 'inventory') loadProductsList();
    }

    window.addEventListener('DOMContentLoaded', () => {
      loadMetrics();
      loadProductsList();
    });
  </script>
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  return router;
}

module.exports = { createAdminRouter };
