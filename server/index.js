import express from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const uploadDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `qr-${Date.now()}${path.extname(file.originalname)}`)
});

const imageFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  const ext = path.extname(file.originalname).toLowerCase();
  
  if (allowedTypes.includes(file.mimetype) && allowedExtensions.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only image files (JPG, PNG, GIF, WebP) are allowed'), false);
  }
};

const upload = multer({ 
  storage, 
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: imageFilter
});

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const JWT_SECRET = process.env.JWT_SECRET || 'vclub-secret-key-2024';

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(uploadDir));

const authenticateToken = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id, username, role, balance FROM users WHERE id = $1', [decoded.userId]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    req.user = result.rows[0];
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    
    const existingUser = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) return res.status(400).json({ error: 'Username already exists' });
    
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, role, balance) VALUES ($1, $2, $3, $4) RETURNING id, username, role, balance',
      [username, passwordHash, 'user', 0]
    );
    
    const token = jwt.sign({ userId: result.rows[0].id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ user: result.rows[0], token });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid credentials' });
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: user.id, username: user.username, role: user.role, balance: user.balance }, token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/settings/public', async (req, res) => {
  try {
    const result = await pool.query('SELECT wallet_address, qr_code_url, site_name, btc_rate, bonus_percentage, min_bonus_amount, exchange_fee FROM admin_settings WHERE id = 1');
    res.json(result.rows[0] || {});
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.get('/api/listings', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT l.*, u.username as seller_name 
      FROM listings l 
      JOIN users u ON l.seller_id = u.id 
      WHERE l.status = 'active' 
      ORDER BY l.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch listings' });
  }
});

app.get('/api/listings/my', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM listings WHERE seller_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch listings' });
  }
});

app.post('/api/listings', authenticateToken, async (req, res) => {
  try {
    const { title, card_type, card_brand, country, price, details, card_number, exp_month, exp_year, cvv } = req.body;
    if (!title || !price) return res.status(400).json({ error: 'Title and price required' });
    if (!card_number || !exp_month || !exp_year || !cvv) {
      return res.status(400).json({ error: 'Card details are required' });
    }
    
    if (req.user.role === 'user') {
      await pool.query('UPDATE users SET role = $1 WHERE id = $2', ['seller', req.user.id]);
    }
    
    const result = await pool.query(
      'INSERT INTO listings (seller_id, title, card_type, card_brand, country, price, details, card_number, exp_month, exp_year, cvv) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *',
      [req.user.id, title, card_type, card_brand, country, price, details, card_number, exp_month, exp_year, cvv]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create listing' });
  }
});

app.put('/api/listings/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, card_type, card_brand, country, price, details, status } = req.body;
    
    const listing = await pool.query('SELECT seller_id FROM listings WHERE id = $1', [id]);
    if (listing.rows.length === 0) return res.status(404).json({ error: 'Listing not found' });
    if (listing.rows[0].seller_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    const result = await pool.query(
      'UPDATE listings SET title = $1, card_type = $2, card_brand = $3, country = $4, price = $5, details = $6, status = $7, updated_at = CURRENT_TIMESTAMP WHERE id = $8 RETURNING *',
      [title, card_type, card_brand, country, price, details, status, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update listing' });
  }
});

app.delete('/api/listings/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const listing = await pool.query('SELECT seller_id FROM listings WHERE id = $1', [id]);
    if (listing.rows.length === 0) return res.status(404).json({ error: 'Listing not found' });
    if (listing.rows[0].seller_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    await pool.query('DELETE FROM listings WHERE id = $1', [id]);
    res.json({ message: 'Listing deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete listing' });
  }
});

app.post('/api/listings/:id/purchase', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { id } = req.params;
    
    const listing = await client.query('SELECT * FROM listings WHERE id = $1 AND status = $2 FOR UPDATE', [id, 'active']);
    if (listing.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Listing not available' });
    }
    
    const item = listing.rows[0];
    if (parseFloat(req.user.balance) < parseFloat(item.price)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [item.price, req.user.id]);
    await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [item.price, item.seller_id]);
    await client.query('UPDATE listings SET status = $1 WHERE id = $2', ['sold', id]);
    
    await client.query(
      'INSERT INTO transactions (user_id, listing_id, type, amount, status) VALUES ($1, $2, $3, $4, $5)',
      [req.user.id, id, 'purchase', item.price, 'confirmed']
    );
    await client.query(
      'INSERT INTO transactions (user_id, listing_id, type, amount, status) VALUES ($1, $2, $3, $4, $5)',
      [item.seller_id, id, 'sale', item.price, 'confirmed']
    );
    
    await client.query('COMMIT');
    res.json({ message: 'Purchase successful', listing: item });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Purchase failed' });
  } finally {
    client.release();
  }
});

app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT t.*, l.title as listing_title FROM transactions t LEFT JOIN listings l ON t.listing_id = l.id WHERE t.user_id = $1 ORDER BY t.created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.*, l.title as listing_title, l.id as listing_id 
       FROM transactions t 
       LEFT JOIN listings l ON t.listing_id = l.id 
       WHERE t.user_id = $1 AND t.type = 'purchase' 
       ORDER BY t.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.get('/api/orders/:listingId/card-details', authenticateToken, async (req, res) => {
  try {
    const { listingId } = req.params;
    const purchase = await pool.query(
      `SELECT t.id FROM transactions t WHERE t.user_id = $1 AND t.listing_id = $2 AND t.type = 'purchase'`,
      [req.user.id, listingId]
    );
    if (purchase.rows.length === 0) {
      return res.status(403).json({ error: 'You have not purchased this item' });
    }
    const listing = await pool.query(
      `SELECT card_number, exp_month, exp_year, cvv, card_brand, card_type, country, details 
       FROM listings WHERE id = $1`,
      [listingId]
    );
    if (listing.rows.length === 0) {
      return res.status(404).json({ error: 'Listing not found' });
    }
    res.json(listing.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch card details' });
  }
});

app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role, balance, created_at FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role, balance } = req.body;
    const result = await pool.query(
      'UPDATE users SET role = $1, balance = $2 WHERE id = $3 RETURNING id, username, role, balance',
      [role, balance, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/admin/settings', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM admin_settings WHERE id = 1');
    res.json(result.rows[0] || {});
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { wallet_address, qr_code_url, site_name, btc_rate, bonus_percentage, min_bonus_amount, exchange_fee } = req.body;
    const result = await pool.query(
      'UPDATE admin_settings SET wallet_address = $1, qr_code_url = $2, site_name = $3, btc_rate = $4, bonus_percentage = $5, min_bonus_amount = $6, exchange_fee = $7, updated_at = CURRENT_TIMESTAMP WHERE id = 1 RETURNING *',
      [wallet_address, qr_code_url, site_name, btc_rate, bonus_percentage, min_bonus_amount, exchange_fee]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

app.get('/api/admin/listings', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT l.*, u.username as seller_name 
      FROM listings l 
      JOIN users u ON l.seller_id = u.id 
      ORDER BY l.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch listings' });
  }
});

app.put('/api/admin/listings/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'UPDATE listings SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
      ['active', id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Listing not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to approve listing' });
  }
});

app.put('/api/admin/listings/:id/reject', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'UPDATE listings SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
      ['rejected', id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Listing not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to reject listing' });
  }
});

app.get('/api/admin/transactions', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT t.*, u.username, l.title as listing_title 
      FROM transactions t 
      JOIN users u ON t.user_id = u.id 
      LEFT JOIN listings l ON t.listing_id = l.id 
      ORDER BY t.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.post('/api/transactions/:id/refund', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ error: 'Reason is required' });
    
    const tx = await pool.query('SELECT * FROM transactions WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    if (tx.rows.length === 0) return res.status(404).json({ error: 'Transaction not found' });
    if (tx.rows[0].type !== 'purchase') return res.status(400).json({ error: 'Can only refund purchases' });
    
    const existing = await pool.query('SELECT id FROM refund_requests WHERE transaction_id = $1', [id]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Refund already requested' });
    
    await pool.query(
      'INSERT INTO refund_requests (transaction_id, user_id, reason, status) VALUES ($1, $2, $3, $4)',
      [id, req.user.id, reason, 'pending']
    );
    await pool.query('UPDATE transactions SET refund_status = $1, refund_reason = $2, refund_requested_at = CURRENT_TIMESTAMP WHERE id = $3',
      ['pending', reason, id]);
    
    res.json({ message: 'Refund request submitted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to request refund' });
  }
});

app.get('/api/refunds/my', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, t.amount, l.title as listing_title 
      FROM refund_requests r 
      JOIN transactions t ON r.transaction_id = t.id 
      LEFT JOIN listings l ON t.listing_id = l.id 
      WHERE r.user_id = $1 
      ORDER BY r.created_at DESC
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch refunds' });
  }
});

app.get('/api/admin/refunds', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, t.amount, l.title as listing_title, u.username 
      FROM refund_requests r 
      JOIN transactions t ON r.transaction_id = t.id 
      JOIN users u ON r.user_id = u.id 
      LEFT JOIN listings l ON t.listing_id = l.id 
      ORDER BY r.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch refunds' });
  }
});

app.put('/api/admin/refunds/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { id } = req.params;
    
    const refund = await client.query(`
      SELECT r.*, t.amount, t.user_id as buyer_id, l.seller_id, l.id as listing_id
      FROM refund_requests r 
      JOIN transactions t ON r.transaction_id = t.id 
      LEFT JOIN listings l ON t.listing_id = l.id 
      WHERE r.id = $1
    `, [id]);
    
    if (refund.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Refund request not found' });
    }
    
    const r = refund.rows[0];
    if (r.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Refund already processed' });
    }
    
    await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [r.amount, r.buyer_id]);
    if (r.seller_id) {
      await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [r.amount, r.seller_id]);
    }
    
    await client.query('UPDATE refund_requests SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', ['approved', id]);
    await client.query('UPDATE transactions SET refund_status = $1 WHERE id = $2', ['approved', r.transaction_id]);
    
    await client.query(
      'INSERT INTO transactions (user_id, listing_id, type, amount, status) VALUES ($1, $2, $3, $4, $5)',
      [r.buyer_id, r.listing_id, 'refund', r.amount, 'confirmed']
    );
    
    await client.query('COMMIT');
    res.json({ message: 'Refund approved' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to approve refund' });
  } finally {
    client.release();
  }
});

app.put('/api/admin/refunds/:id/reject', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const refund = await pool.query('SELECT * FROM refund_requests WHERE id = $1', [id]);
    if (refund.rows.length === 0) return res.status(404).json({ error: 'Refund request not found' });
    if (refund.rows[0].status !== 'pending') return res.status(400).json({ error: 'Refund already processed' });
    
    await pool.query('UPDATE refund_requests SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', ['rejected', id]);
    await pool.query('UPDATE transactions SET refund_status = $1 WHERE id = $2', ['rejected', refund.rows[0].transaction_id]);
    
    res.json({ message: 'Refund rejected' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reject refund' });
  }
});

app.post('/api/admin/upload-qr', authenticateToken, isAdmin, (req, res) => {
  upload.single('qr')(req, res, async (err) => {
    if (err) {
      if (err.message.includes('Only image files')) {
        return res.status(400).json({ error: err.message });
      }
      return res.status(400).json({ error: 'File upload failed' });
    }
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const url = `/uploads/${req.file.filename}`;
      await pool.query('UPDATE admin_settings SET qr_code_url = $1 WHERE id = 1', [url]);
      res.json({ url });
    } catch (err) {
      res.status(500).json({ error: 'Failed to upload QR code' });
    }
  });
});

const PORT = 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`API server running on port ${PORT}`);
});
