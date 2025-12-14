import './App.css'
import { useState, useEffect, createContext, useContext } from 'react'

const API_URL = '/api'
const AuthContext = createContext(null)

const useAuth = () => useContext(AuthContext)

const api = {
  async request(endpoint, options = {}) {
    const res = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options.headers },
      credentials: 'include'
    })
    const data = await res.json()
    if (!res.ok) throw new Error(data.error || 'Request failed')
    return data
  },
  get: (endpoint) => api.request(endpoint),
  post: (endpoint, body) => api.request(endpoint, { method: 'POST', body: JSON.stringify(body) }),
  put: (endpoint, body) => api.request(endpoint, { method: 'PUT', body: JSON.stringify(body) }),
  delete: (endpoint) => api.request(endpoint, { method: 'DELETE' })
}

export default function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [settings, setSettings] = useState({})

  useEffect(() => {
    Promise.all([
      api.get('/auth/me').then(d => setUser(d.user)).catch(() => {}),
      api.get('/settings/public').then(setSettings).catch(() => {})
    ]).finally(() => setLoading(false))
  }, [])

  const login = async (username, password) => {
    const data = await api.post('/auth/login', { username, password })
    setUser(data.user)
    return data
  }

  const register = async (username, password) => {
    const data = await api.post('/auth/register', { username, password })
    setUser(data.user)
    return data
  }

  const logout = async () => {
    await api.post('/auth/logout')
    setUser(null)
  }

  const refreshUser = async () => {
    const data = await api.get('/auth/me')
    setUser(data.user)
  }

  if (loading) return <div className="loading">Loading...</div>

  return (
    <AuthContext.Provider value={{ user, login, register, logout, refreshUser, settings, setSettings }}>
      {user ? <MainApp /> : <AuthPages />}
    </AuthContext.Provider>
  )
}

function AuthPages() {
  const [isLogin, setIsLogin] = useState(true)
  return isLogin ? 
    <LoginPage onSwitch={() => setIsLogin(false)} /> : 
    <RegisterPage onSwitch={() => setIsLogin(true)} />
}

function LoginPage({ onSwitch }) {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
    } catch (err) {
      setError(err.message)
    }
    setLoading(false)
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-header">
          <span className="logo-icon">💎</span>
          <h1>VClub</h1>
        </div>
        <h2>Welcome Back</h2>
        {error && <div className="error-msg">{error}</div>}
        <form onSubmit={handleSubmit}>
          <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} required />
          <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required />
          <button type="submit" disabled={loading}>{loading ? 'Loading...' : 'Sign In'}</button>
        </form>
        <p className="auth-switch">Don't have an account? <span onClick={onSwitch}>Register</span></p>
      </div>
    </div>
  )
}

function RegisterPage({ onSwitch }) {
  const { register } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await register(username, password)
    } catch (err) {
      setError(err.message)
    }
    setLoading(false)
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-header">
          <span className="logo-icon">💎</span>
          <h1>VClub</h1>
        </div>
        <h2>Create Account</h2>
        {error && <div className="error-msg">{error}</div>}
        <form onSubmit={handleSubmit}>
          <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} required />
          <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required minLength={4} />
          <button type="submit" disabled={loading}>{loading ? 'Loading...' : 'Create Account'}</button>
        </form>
        <p className="auth-switch">Already have an account? <span onClick={onSwitch}>Sign In</span></p>
      </div>
    </div>
  )
}

function RulesModal({ onClose }) {
  return (
    <div className="rules-modal-overlay">
      <div className="rules-modal">
        <div className="rules-header">
          <div className="language-toggle">
            <span className="lang-active">English</span>
            <span className="lang-inactive">Russian</span>
          </div>
          <button className="rules-close-btn" onClick={onClose}>×</button>
        </div>
        <h2 className="rules-title">RULES</h2>
        
        <div className="rules-section">
          <h3 className="rules-section-title">Refund:</h3>
          <ol className="rules-list">
            <li>System cannot guarantee any balance on cards you purchase, and we cannot refund or replace card for this reason.</li>
            <li>If card not verified by visa or security 3d MC protect, we cannot not replace or refund.</li>
            <li>No refund or replace for invalid address, state, city,zip, phone, dob, ssn, mmn, ip and etc...</li>
            <li>System can't refund or replace if our checker say card is approval.</li>
            <li>Refund time is 5-10 min after buy.</li>
            <li>No refund for GOLD bases. GOLD color means base has no refunds at all.</li>
          </ol>
        </div>

        <div className="rules-section">
          <h3 className="rules-section-title">Payment:</h3>
          <ol className="rules-list">
            <li>All payments can be made only via Bitcoin and "NO REFUND" after the payment is loaded successfully to your account.</li>
            <li>After send payment via bitcoin, your balance will be automatically loaded after 2 confirmed in bitcoin system.</li>
            <li>Bitcoin confirm could take from 5 minutes to 2 hours. We have no control over bitcoin system, so you need to wait.</li>
          </ol>
        </div>

        <div className="rules-section">
          <h3 className="rules-section-title">Notice:</h3>
          <ol className="rules-list notice-list">
            <li className="notice-highlight">Receive 14% bonus if you're depositing $500 and more!</li>
            <li className="notice-warning">Disclaimer - Consider electronic currency value fluctuations and 4% payment processing fee.</li>
          </ol>
        </div>

        <div className="rules-section">
          <h3 className="rules-section-title">Other:</h3>
          <ol className="rules-list">
            <li>All payments can be made only via Bitcoin and NO REFUNDS after the payment is loaded successfully to your account.</li>
            <li>Valid rate of all our bases differs from %50 to %100.</li>
            <li>We answer your problems only in ticket system.</li>
          </ol>
        </div>

        <div className="rules-section">
          <h3 className="rules-section-title">Reseller:</h3>
          <ol className="rules-list">
            <li>Valid rate more than 75%.</li>
            <li>AutoPay out system, you don't need ask support for you money.</li>
            <li>Fast sales!</li>
          </ol>
        </div>

        <div className="rules-support">
          <p className="support-text">[*] Contact support on Telegram available 24/7.</p>
          <p className="support-handle">@VclubshopSupport</p>
        </div>
      </div>
    </div>
  )
}

function MainApp() {
  const { user, logout, settings, refreshUser } = useAuth()
  const [page, setPage] = useState('deposit')
  const [menuOpen, setMenuOpen] = useState(false)
  const [expandedMenus, setExpandedMenus] = useState({})
  const [showRulesModal, setShowRulesModal] = useState(true)

  const toggleSubmenu = (id) => {
    setExpandedMenus(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const navItems = [
    { id: 'news', icon: '📰', label: 'News' },
    { id: 'ccs-fullz', icon: '💳', label: 'CCS/Fullz', submenu: [
      { id: 'buy-ccs', label: 'Buy CCS/Fullz' },
      { id: 'cart-ccs', label: 'Cart CCS/Fullz' },
      { id: 'orders-ccs', label: 'Orders CCS/Fullz' },
      { id: 'binlookup', label: 'Binlookup' },
      { id: 'bin-preorder', label: 'Bin Preorder' },
    ]},
    { id: 'dumps', icon: '💾', label: 'Dumps' },
    { id: 'proxy-socks', icon: '🔒', label: 'Proxy/Socks 5' },
    { id: 'rent-sim', icon: '📱', label: 'Rent SIM/Receive SMS' },
    { id: 'lottery', icon: '🎰', label: 'Lottery' },
    { id: 'ssn-dob', icon: '🆔', label: 'SSN/DOB' },
    { id: 'accounts', icon: '👤', label: 'Accounts' },
    { id: 'billing', icon: '💰', label: 'Billing', submenu: [
      { id: 'deposit', label: 'Deposit' },
      { id: 'transactions', label: 'Transactions' },
      { id: 'refunds', label: 'My Refunds' },
    ]},
    { id: 'support', icon: '🎧', label: 'Support' },
    { id: 'profile', icon: '⚙️', label: 'Profile' },
  ]

  const adminItems = [
    { id: 'admin-users', icon: '👥', label: 'Manage Users' },
    { id: 'admin-settings', icon: '⚙️', label: 'Site Settings' },
    { id: 'admin-listings', icon: '📋', label: 'All Listings' },
    { id: 'admin-refunds', icon: '💸', label: 'Refund Requests' },
  ]

  const sellerItems = [
    { id: 'sell', icon: '💳', label: 'Sell CC' },
    { id: 'my-listings', icon: '📦', label: 'My Listings' },
  ]

  return (
    <div className="app">
      <header className="header">
        <button className="menu-btn" onClick={() => setMenuOpen(!menuOpen)}>☰</button>
        <div className="brand">💎 {settings.site_name || 'VClub'}</div>
        <div className="balance">${parseFloat(user.balance || 0).toFixed(2)}</div>
      </header>

      <nav className={`nav ${menuOpen ? 'open' : ''}`}>
        <div className="nav-header">
          <span>👤</span>
          <div>
            <div className="nav-user">{user.username}</div>
            <div className="nav-role">{user.role}</div>
          </div>
        </div>
        
        {navItems.map(item => (
          <div key={item.id}>
            <div className={`nav-item ${page === item.id || (item.submenu && item.submenu.some(s => s.id === page)) ? 'active' : ''}`} 
                 onClick={() => item.submenu ? toggleSubmenu(item.id) : (setPage(item.id), setMenuOpen(false))}>
              <span>{item.icon}</span> {item.label}
              {item.submenu && <span className="submenu-arrow">{expandedMenus[item.id] ? '▼' : '▶'}</span>}
            </div>
            {item.submenu && expandedMenus[item.id] && (
              <div className="submenu">
                {item.submenu.map(sub => (
                  <div key={sub.id} className={`nav-item submenu-item ${page === sub.id ? 'active' : ''}`}
                       onClick={() => { setPage(sub.id); setMenuOpen(false) }}>
                    {sub.label}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}

        <div className="nav-divider">SELLER</div>
        {sellerItems.map(item => (
          <div key={item.id} className={`nav-item ${page === item.id ? 'active' : ''}`} 
               onClick={() => { setPage(item.id); setMenuOpen(false) }}>
            <span>{item.icon}</span> {item.label}
          </div>
        ))}

        {user.role === 'admin' && (
          <>
            <div className="nav-divider">ADMIN</div>
            {adminItems.map(item => (
              <div key={item.id} className={`nav-item ${page === item.id ? 'active' : ''}`} 
                   onClick={() => { setPage(item.id); setMenuOpen(false) }}>
                <span>{item.icon}</span> {item.label}
              </div>
            ))}
          </>
        )}

        <div className="nav-item logout" onClick={logout}><span>🚪</span> Logout</div>
      </nav>

      {menuOpen && <div className="overlay" onClick={() => setMenuOpen(false)}></div>}

      {showRulesModal && <RulesModal onClose={() => setShowRulesModal(false)} />}

      <main className="main">
        {page === 'news' && <NewsPage />}
        {page === 'buy-ccs' && <MarketPage refreshUser={refreshUser} />}
        {page === 'cart-ccs' && <CartPage />}
        {page === 'orders-ccs' && <OrdersPage />}
        {page === 'binlookup' && <BinLookupPage />}
        {page === 'bin-preorder' && <BinPreorderPage />}
        {page === 'dumps' && <DumpsPage />}
        {page === 'proxy-socks' && <ProxySocksPage />}
        {page === 'rent-sim' && <RentSimPage />}
        {page === 'lottery' && <LotteryPage />}
        {page === 'ssn-dob' && <SsnDobPage />}
        {page === 'accounts' && <AccountsPage />}
        {page === 'deposit' && <DepositPage settings={settings} />}
        {page === 'transactions' && <TransactionsPage refreshUser={refreshUser} />}
        {page === 'refunds' && <MyRefundsPage />}
        {page === 'support' && <SupportPage />}
        {page === 'profile' && <ProfilePage />}
        {page === 'sell' && <SellPage onSuccess={() => setPage('my-listings')} />}
        {page === 'my-listings' && <MyListingsPage />}
        {page === 'admin-users' && <AdminUsersPage />}
        {page === 'admin-settings' && <AdminSettingsPage />}
        {page === 'admin-listings' && <AdminListingsPage />}
        {page === 'admin-refunds' && <AdminRefundsPage />}
      </main>

      <footer className="footer">
        <span className="seller-tag">SELLERS</span>
        <span>SELL YOUR STUFF WITH US</span>
        <span>Balance: ${parseFloat(user.balance || 0).toFixed(2)} 🟢</span>
      </footer>
    </div>
  )
}

function MarketPage({ refreshUser }) {
  const [listings, setListings] = useState([])
  const [loading, setLoading] = useState(true)
  const [buying, setBuying] = useState(null)

  useEffect(() => {
    api.get('/listings').then(setListings).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const buy = async (listing) => {
    if (!window.confirm(`Buy "${listing.title}" for $${listing.price}?`)) return
    setBuying(listing.id)
    try {
      await api.post(`/listings/${listing.id}/purchase`)
      alert('Purchase successful!')
      setListings(prev => prev.filter(l => l.id !== listing.id))
      refreshUser()
    } catch (err) {
      alert(err.message)
    }
    setBuying(null)
  }

  if (loading) return <div className="page-loading">Loading listings...</div>

  return (
    <div className="page">
      <h2>🏪 Marketplace</h2>
      {listings.length === 0 ? (
        <div className="empty-state">No listings available</div>
      ) : (
        <div className="listings-grid">
          {listings.map(listing => (
            <div key={listing.id} className="listing-card">
              <div className="listing-header">
                <span className="listing-type">{listing.card_brand || 'CC'}</span>
                <span className="listing-price">${parseFloat(listing.price).toFixed(2)}</span>
              </div>
              <h3>{listing.title}</h3>
              <div className="listing-info">
                <span>🌍 {listing.country || 'Unknown'}</span>
                <span>💳 {listing.card_type || 'Card'}</span>
              </div>
              <p className="listing-details">{listing.details || 'No details'}</p>
              <div className="listing-seller">Seller: {listing.seller_name}</div>
              <button className="buy-btn" onClick={() => buy(listing)} disabled={buying === listing.id}>
                {buying === listing.id ? 'Buying...' : 'Buy Now'}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function DepositPage({ settings }) {
  const [copied, setCopied] = useState(false)

  const copyAddress = () => {
    navigator.clipboard.writeText(settings.wallet_address || '')
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="page">
      <div className="notice-banner">
        <span>🎁</span>
        <p>Receive <strong>{settings.bonus_percentage || 14}% bonus</strong> if you're depositing ${settings.min_bonus_amount || 500} and more!</p>
      </div>

      <div className="info-box">
        <p>ℹ️ Exchange fee is {settings.exchange_fee || 4}%. You need 2 confirmations to deposit money to your account.</p>
      </div>

      <div className="deposit-card">
        <h3>₿ Bitcoin Wallet Address</h3>
        <div className="wallet-address">{settings.wallet_address || 'Loading...'}</div>
        <button className="copy-btn" onClick={copyAddress}>
          📋 {copied ? 'Copied!' : 'Copy Address'}
        </button>
      </div>

      <div className="rate-card">
        <div className="rate-info">
          <span className="btc-icon">₿</span>
          <div>
            <div className="rate-label">Current Rate</div>
            <div className="rate-value">1 BTC = ${parseFloat(settings.btc_rate || 93156).toLocaleString()}</div>
          </div>
        </div>
        <div className="qr-placeholder">
          {settings.qr_code_url ? (
            <img src={settings.qr_code_url} alt="QR Code" />
          ) : (
            <div className="qr-box">QR</div>
          )}
        </div>
      </div>

      <div className="instructions">
        <h3>📖 How to Deposit</h3>
        <ol>
          <li>Send BTC to the wallet address above</li>
          <li>Wait for 2 confirmations</li>
          <li>Balance will be added automatically</li>
        </ol>
      </div>

      <div className="transactions-section">
        <h3>⏳ Pending Transactions</h3>
        <div className="table-header">
          <span>Date</span>
          <span>Amount</span>
          <span>Status</span>
        </div>
        <div className="empty-state">No pending transactions</div>
      </div>
    </div>
  )
}

function SellPage({ onSuccess }) {
  const [form, setForm] = useState({ 
    title: '', card_type: '', card_brand: '', country: '', price: '', details: '',
    card_number: '', exp_month: '', exp_year: '', cvv: ''
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (!form.card_number || form.card_number.length < 13) {
      setError('Valid card number is required')
      return
    }
    if (!form.exp_month || !form.exp_year) {
      setError('Expiry month and year are required')
      return
    }
    if (!form.cvv || form.cvv.length < 3) {
      setError('Valid CVV is required')
      return
    }
    setLoading(true)
    try {
      await api.post('/listings', form)
      alert('Listing created successfully! Awaiting admin approval.')
      onSuccess()
    } catch (err) {
      setError(err.message)
    }
    setLoading(false)
  }

  return (
    <div className="page">
      <h2>💳 Sell Your CC</h2>
      {error && <div className="error-msg">{error}</div>}
      <form className="sell-form" onSubmit={handleSubmit}>
        <input type="text" placeholder="Title (e.g., Premium Visa Card)" value={form.title} 
               onChange={e => setForm({...form, title: e.target.value})} required />
        <select value={form.card_brand} onChange={e => setForm({...form, card_brand: e.target.value})} required>
          <option value="">Select Card Brand</option>
          <option value="Visa">Visa</option>
          <option value="Mastercard">Mastercard</option>
          <option value="Amex">American Express</option>
          <option value="Discover">Discover</option>
        </select>
        <select value={form.card_type} onChange={e => setForm({...form, card_type: e.target.value})} required>
          <option value="">Select Card Type</option>
          <option value="Credit">Credit</option>
          <option value="Debit">Debit</option>
          <option value="Prepaid">Prepaid</option>
        </select>
        
        <div className="form-section">
          <label>Card Details</label>
          <input type="text" placeholder="Card Number (16 digits)" value={form.card_number}
                 onChange={e => setForm({...form, card_number: e.target.value.replace(/\D/g, '').slice(0, 16)})} 
                 required maxLength={16} />
          <div className="form-row">
            <select value={form.exp_month} onChange={e => setForm({...form, exp_month: e.target.value})} required>
              <option value="">Month</option>
              {Array.from({length: 12}, (_, i) => (
                <option key={i+1} value={String(i+1).padStart(2, '0')}>{String(i+1).padStart(2, '0')}</option>
              ))}
            </select>
            <select value={form.exp_year} onChange={e => setForm({...form, exp_year: e.target.value})} required>
              <option value="">Year</option>
              {Array.from({length: 10}, (_, i) => {
                const year = new Date().getFullYear() + i
                return <option key={year} value={year}>{year}</option>
              })}
            </select>
            <input type="text" placeholder="CVV" value={form.cvv}
                   onChange={e => setForm({...form, cvv: e.target.value.replace(/\D/g, '').slice(0, 4)})}
                   required maxLength={4} />
          </div>
        </div>

        <input type="text" placeholder="Country (e.g., USA)" value={form.country}
               onChange={e => setForm({...form, country: e.target.value})} />
        <input type="number" placeholder="Price ($)" value={form.price}
               onChange={e => setForm({...form, price: e.target.value})} required min="0.01" step="0.01" />
        <textarea placeholder="Details (BIN, Level, Bank, etc.)" value={form.details}
                  onChange={e => setForm({...form, details: e.target.value})} rows={4} />
        <button type="submit" disabled={loading}>{loading ? 'Creating...' : 'Create Listing'}</button>
      </form>
    </div>
  )
}

function MyListingsPage() {
  const [listings, setListings] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/listings/my').then(setListings).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const deleteListing = async (id) => {
    if (!window.confirm('Delete this listing?')) return
    try {
      await api.delete(`/listings/${id}`)
      setListings(prev => prev.filter(l => l.id !== id))
    } catch (err) {
      alert(err.message)
    }
  }

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>📦 My Listings</h2>
      {listings.length === 0 ? (
        <div className="empty-state">You haven't listed anything yet</div>
      ) : (
        <div className="listings-grid">
          {listings.map(listing => (
            <div key={listing.id} className={`listing-card ${listing.status}`}>
              <div className="listing-header">
                <span className={`status-badge ${listing.status}`}>{listing.status}</span>
                <span className="listing-price">${parseFloat(listing.price).toFixed(2)}</span>
              </div>
              <h3>{listing.title}</h3>
              <div className="listing-info">
                <span>🌍 {listing.country || 'N/A'}</span>
                <span>💳 {listing.card_brand || 'N/A'}</span>
              </div>
              {listing.status === 'active' && (
                <button className="delete-btn" onClick={() => deleteListing(listing.id)}>Delete</button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function TransactionsPage({ refreshUser }) {
  const [transactions, setTransactions] = useState([])
  const [loading, setLoading] = useState(true)
  const [refundReason, setRefundReason] = useState('')
  const [refundingId, setRefundingId] = useState(null)

  useEffect(() => {
    api.get('/transactions').then(setTransactions).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const requestRefund = async (txId) => {
    if (!refundReason.trim()) {
      alert('Please enter a reason for the refund')
      return
    }
    try {
      await api.post(`/transactions/${txId}/refund`, { reason: refundReason })
      alert('Refund request submitted!')
      setRefundingId(null)
      setRefundReason('')
      const updated = await api.get('/transactions')
      setTransactions(updated)
    } catch (err) {
      alert(err.message)
    }
  }

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>📊 Transactions</h2>
      {transactions.length === 0 ? (
        <div className="empty-state">No transactions yet</div>
      ) : (
        <div className="transactions-list">
          {transactions.map(tx => (
            <div key={tx.id} className={`transaction-item ${tx.type}`}>
              <div className="tx-icon">
                {tx.type === 'purchase' ? '🛒' : tx.type === 'sale' ? '💵' : tx.type === 'deposit' ? '⬇️' : tx.type === 'refund' ? '💸' : '⬆️'}
              </div>
              <div className="tx-info">
                <div className="tx-type">{tx.type.charAt(0).toUpperCase() + tx.type.slice(1)}</div>
                <div className="tx-title">{tx.listing_title || 'Deposit'}</div>
                <div className="tx-date">{new Date(tx.created_at).toLocaleDateString()}</div>
                {tx.refund_status && (
                  <div className={`refund-status ${tx.refund_status}`}>Refund: {tx.refund_status}</div>
                )}
              </div>
              <div className={`tx-amount ${tx.type === 'sale' || tx.type === 'deposit' || tx.type === 'refund' ? 'positive' : 'negative'}`}>
                {tx.type === 'sale' || tx.type === 'deposit' || tx.type === 'refund' ? '+' : '-'}${parseFloat(tx.amount).toFixed(2)}
              </div>
              {tx.type === 'purchase' && !tx.refund_status && (
                <div className="tx-actions">
                  {refundingId === tx.id ? (
                    <div className="refund-form">
                      <input type="text" placeholder="Reason for refund" value={refundReason}
                             onChange={e => setRefundReason(e.target.value)} />
                      <button className="refund-submit-btn" onClick={() => requestRefund(tx.id)}>Submit</button>
                      <button className="refund-cancel-btn" onClick={() => setRefundingId(null)}>Cancel</button>
                    </div>
                  ) : (
                    <button className="refund-btn" onClick={() => setRefundingId(tx.id)}>Request Refund</button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function AdminUsersPage() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/admin/users').then(setUsers).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const updateUser = async (id, updates) => {
    try {
      const updated = await api.put(`/admin/users/${id}`, updates)
      setUsers(prev => prev.map(u => u.id === id ? updated : u))
    } catch (err) {
      alert(err.message)
    }
  }

  const deleteUser = async (id) => {
    if (!window.confirm('Delete this user?')) return
    try {
      await api.delete(`/admin/users/${id}`)
      setUsers(prev => prev.filter(u => u.id !== id))
    } catch (err) {
      alert(err.message)
    }
  }

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>👥 Manage Users</h2>
      <div className="users-list">
        {users.map(user => (
          <div key={user.id} className="user-card">
            <div className="user-info">
              <div className="user-name">{user.username}</div>
              <div className="user-meta">
                <select value={user.role} onChange={e => updateUser(user.id, { ...user, role: e.target.value })}>
                  <option value="user">User</option>
                  <option value="seller">Seller</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>
            <div className="user-balance">
              <input type="number" value={user.balance} step="0.01"
                     onChange={e => updateUser(user.id, { ...user, balance: e.target.value })} />
            </div>
            <button className="delete-btn" onClick={() => deleteUser(user.id)}>🗑️</button>
          </div>
        ))}
      </div>
    </div>
  )
}

function AdminSettingsPage() {
  const { setSettings } = useAuth()
  const [form, setForm] = useState({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [uploading, setUploading] = useState(false)

  useEffect(() => {
    api.get('/admin/settings').then(setForm).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      const updated = await api.put('/admin/settings', form)
      setForm(updated)
      setSettings(updated)
      alert('Settings saved!')
    } catch (err) {
      alert(err.message)
    }
    setSaving(false)
  }

  const handleQRUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setUploading(true)
    const formData = new FormData()
    formData.append('qr', file)
    try {
      const res = await fetch('/api/admin/upload-qr', {
        method: 'POST',
        body: formData,
        credentials: 'include'
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      setForm(prev => ({ ...prev, qr_code_url: data.url }))
      alert('QR Code uploaded!')
    } catch (err) {
      alert(err.message)
    }
    setUploading(false)
  }

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>⚙️ Site Settings</h2>
      <form className="settings-form" onSubmit={handleSubmit}>
        <label>Site Name</label>
        <input type="text" value={form.site_name || ''} onChange={e => setForm({...form, site_name: e.target.value})} />
        
        <label>Wallet Address</label>
        <input type="text" value={form.wallet_address || ''} onChange={e => setForm({...form, wallet_address: e.target.value})} />
        
        <label>QR Code</label>
        <div className="qr-upload-section">
          {form.qr_code_url && <img src={form.qr_code_url} alt="QR Code" className="qr-preview" />}
          <input type="file" accept="image/*" onChange={handleQRUpload} disabled={uploading} />
          {uploading && <span>Uploading...</span>}
        </div>
        <input type="text" placeholder="Or enter QR Code URL" value={form.qr_code_url || ''} 
               onChange={e => setForm({...form, qr_code_url: e.target.value})} />
        
        <label>BTC Rate ($)</label>
        <input type="number" value={form.btc_rate || ''} step="0.01" onChange={e => setForm({...form, btc_rate: e.target.value})} />
        
        <label>Bonus Percentage (%)</label>
        <input type="number" value={form.bonus_percentage || ''} onChange={e => setForm({...form, bonus_percentage: e.target.value})} />
        
        <label>Minimum Bonus Amount ($)</label>
        <input type="number" value={form.min_bonus_amount || ''} step="0.01" onChange={e => setForm({...form, min_bonus_amount: e.target.value})} />
        
        <label>Exchange Fee (%)</label>
        <input type="number" value={form.exchange_fee || ''} step="0.01" onChange={e => setForm({...form, exchange_fee: e.target.value})} />
        
        <button type="submit" disabled={saving}>{saving ? 'Saving...' : 'Save Settings'}</button>
      </form>
    </div>
  )
}

function AdminListingsPage() {
  const [listings, setListings] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/admin/listings').then(setListings).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const approveListing = async (id) => {
    try {
      const updated = await api.put(`/admin/listings/${id}/approve`)
      setListings(prev => prev.map(l => l.id === id ? updated : l))
    } catch (err) {
      alert(err.message)
    }
  }

  const rejectListing = async (id) => {
    try {
      const updated = await api.put(`/admin/listings/${id}/reject`)
      setListings(prev => prev.map(l => l.id === id ? updated : l))
    } catch (err) {
      alert(err.message)
    }
  }

  const deleteListing = async (id) => {
    if (!window.confirm('Delete this listing?')) return
    try {
      await api.delete(`/listings/${id}`)
      setListings(prev => prev.filter(l => l.id !== id))
    } catch (err) {
      alert(err.message)
    }
  }

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>📋 All Listings</h2>
      {listings.length === 0 ? (
        <div className="empty-state">No listings</div>
      ) : (
        <div className="listings-grid">
          {listings.map(listing => (
            <div key={listing.id} className={`listing-card ${listing.status}`}>
              <div className="listing-header">
                <span className={`status-badge ${listing.status}`}>{listing.status}</span>
                <span className="listing-price">${parseFloat(listing.price).toFixed(2)}</span>
              </div>
              <h3>{listing.title}</h3>
              <div className="listing-info">
                <span>🌍 {listing.country || 'N/A'}</span>
                <span>💳 {listing.card_brand || 'N/A'}</span>
              </div>
              <p className="listing-details">{listing.details || 'No details'}</p>
              <div className="listing-seller">By: {listing.seller_name}</div>
              <div className="admin-actions">
                {listing.status === 'pending' && (
                  <>
                    <button className="approve-btn" onClick={() => approveListing(listing.id)}>Approve</button>
                    <button className="reject-btn" onClick={() => rejectListing(listing.id)}>Reject</button>
                  </>
                )}
                <button className="delete-btn" onClick={() => deleteListing(listing.id)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function AdminRefundsPage() {
  const [refunds, setRefunds] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/admin/refunds').then(setRefunds).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const handleRefund = async (id, action) => {
    try {
      await api.put(`/admin/refunds/${id}/${action}`)
      const updated = await api.get('/admin/refunds')
      setRefunds(updated)
      alert(`Refund ${action}d successfully!`)
    } catch (err) {
      alert(err.message)
    }
  }

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>💸 Refund Requests</h2>
      {refunds.length === 0 ? (
        <div className="empty-state">No refund requests</div>
      ) : (
        <div className="refunds-list">
          {refunds.map(r => (
            <div key={r.id} className={`refund-card ${r.status}`}>
              <div className="refund-header">
                <span className={`status-badge ${r.status}`}>{r.status}</span>
                <span className="refund-amount">${parseFloat(r.amount).toFixed(2)}</span>
              </div>
              <div className="refund-info">
                <div>User: {r.username}</div>
                <div>Item: {r.listing_title}</div>
                <div>Reason: {r.reason}</div>
                <div>Date: {new Date(r.created_at).toLocaleDateString()}</div>
              </div>
              {r.status === 'pending' && (
                <div className="admin-actions">
                  <button className="approve-btn" onClick={() => handleRefund(r.id, 'approve')}>Approve</button>
                  <button className="reject-btn" onClick={() => handleRefund(r.id, 'reject')}>Reject</button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function MyRefundsPage() {
  const [refunds, setRefunds] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/refunds/my').then(setRefunds).catch(() => {}).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>💸 My Refund Requests</h2>
      {refunds.length === 0 ? (
        <div className="empty-state">No refund requests</div>
      ) : (
        <div className="refunds-list">
          {refunds.map(r => (
            <div key={r.id} className={`refund-card ${r.status}`}>
              <div className="refund-header">
                <span className={`status-badge ${r.status}`}>{r.status}</span>
                <span className="refund-amount">${parseFloat(r.amount).toFixed(2)}</span>
              </div>
              <div className="refund-info">
                <div>Item: {r.listing_title}</div>
                <div>Reason: {r.reason}</div>
                <div>Date: {new Date(r.created_at).toLocaleDateString()}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function NewsPage() {
  return (
    <div className="page">
      <h2>📰 News</h2>
      <div className="info-box">
        <p>Welcome to VClub! Check back for the latest updates and announcements.</p>
      </div>
    </div>
  )
}

function CartPage() {
  return (
    <div className="page">
      <h2>🛒 Cart CCS/Fullz</h2>
      <div className="empty-state">Your cart is empty</div>
    </div>
  )
}

function OrdersPage() {
  const [orders, setOrders] = useState([])
  const [loading, setLoading] = useState(true)
  const [expandedOrder, setExpandedOrder] = useState(null)
  const [cardDetails, setCardDetails] = useState({})

  useEffect(() => {
    api.get('/orders').then(setOrders).catch(() => {
      api.get('/transactions').then(data => {
        setOrders(data.filter(t => t.type === 'purchase'))
      }).catch(() => {})
    }).finally(() => setLoading(false))
  }, [])

  const toggleCardDetails = async (orderId, listingId) => {
    if (expandedOrder === orderId) {
      setExpandedOrder(null)
      return
    }
    setExpandedOrder(orderId)
    if (!cardDetails[listingId]) {
      try {
        const details = await api.get(`/orders/${listingId}/card-details`)
        setCardDetails(prev => ({ ...prev, [listingId]: details }))
      } catch (err) {
        setCardDetails(prev => ({ ...prev, [listingId]: { error: 'Card details not available' } }))
      }
    }
  }

  if (loading) return <div className="page-loading">Loading...</div>

  return (
    <div className="page">
      <h2>📦 Orders CCS/Fullz</h2>
      {orders.length === 0 ? (
        <div className="empty-state">No orders yet</div>
      ) : (
        <div className="orders-list">
          {orders.map(order => (
            <div key={order.id} className="order-card">
              <div className="order-header" onClick={() => toggleCardDetails(order.id, order.listing_id)}>
                <div className="order-icon">🛒</div>
                <div className="order-info">
                  <div className="order-title">{order.listing_title}</div>
                  <div className="order-date">{new Date(order.created_at).toLocaleDateString()}</div>
                </div>
                <div className="order-amount">-${parseFloat(order.amount).toFixed(2)}</div>
                <div className="order-expand">{expandedOrder === order.id ? '▼' : '▶'}</div>
              </div>
              {expandedOrder === order.id && (
                <div className="card-details-section">
                  {cardDetails[order.listing_id] ? (
                    cardDetails[order.listing_id].error ? (
                      <div className="card-details-error">{cardDetails[order.listing_id].error}</div>
                    ) : (
                      <div className="card-details-content">
                        <div className="card-detail-row">
                          <span className="card-label">Card Number:</span>
                          <span className="card-value">{cardDetails[order.listing_id].card_number}</span>
                        </div>
                        <div className="card-detail-row">
                          <span className="card-label">Expiry:</span>
                          <span className="card-value">{cardDetails[order.listing_id].exp_month}/{cardDetails[order.listing_id].exp_year}</span>
                        </div>
                        <div className="card-detail-row">
                          <span className="card-label">CVV:</span>
                          <span className="card-value">{cardDetails[order.listing_id].cvv}</span>
                        </div>
                        <div className="card-detail-row">
                          <span className="card-label">Brand:</span>
                          <span className="card-value">{cardDetails[order.listing_id].card_brand || 'N/A'}</span>
                        </div>
                        <div className="card-detail-row">
                          <span className="card-label">Type:</span>
                          <span className="card-value">{cardDetails[order.listing_id].card_type || 'N/A'}</span>
                        </div>
                        <div className="card-detail-row">
                          <span className="card-label">Country:</span>
                          <span className="card-value">{cardDetails[order.listing_id].country || 'N/A'}</span>
                        </div>
                        {cardDetails[order.listing_id].details && (
                          <div className="card-detail-row">
                            <span className="card-label">Details:</span>
                            <span className="card-value">{cardDetails[order.listing_id].details}</span>
                          </div>
                        )}
                      </div>
                    )
                  ) : (
                    <div className="card-details-loading">Loading card details...</div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function BinLookupPage() {
  const [bin, setBin] = useState('')
  const [result, setResult] = useState(null)

  const lookup = () => {
    if (bin.length >= 6) {
      setResult({
        bin: bin.slice(0, 6),
        brand: bin.startsWith('4') ? 'Visa' : bin.startsWith('5') ? 'Mastercard' : bin.startsWith('3') ? 'Amex' : 'Unknown',
        type: 'Credit',
        level: 'Classic',
        bank: 'Unknown Bank',
        country: 'USA'
      })
    }
  }

  return (
    <div className="page">
      <h2>🔍 BIN Lookup</h2>
      <div className="sell-form">
        <input type="text" placeholder="Enter BIN (first 6 digits)" value={bin}
               onChange={e => setBin(e.target.value.replace(/\D/g, '').slice(0, 6))} maxLength={6} />
        <button onClick={lookup}>Lookup</button>
      </div>
      {result && (
        <div className="deposit-card" style={{marginTop: '16px'}}>
          <h3>BIN Information</h3>
          <p>BIN: {result.bin}</p>
          <p>Brand: {result.brand}</p>
          <p>Type: {result.type}</p>
          <p>Level: {result.level}</p>
          <p>Bank: {result.bank}</p>
          <p>Country: {result.country}</p>
        </div>
      )}
    </div>
  )
}

function BinPreorderPage() {
  return (
    <div className="page">
      <h2>📋 BIN Preorder</h2>
      <div className="info-box">
        <p>Request specific BINs. Contact support to place a preorder.</p>
      </div>
    </div>
  )
}

function DumpsPage() {
  return (
    <div className="page">
      <h2>💾 Dumps</h2>
      <div className="empty-state">No dumps available</div>
    </div>
  )
}

function ProxySocksPage() {
  return (
    <div className="page">
      <h2>🔒 Proxy/Socks 5</h2>
      <div className="empty-state">No proxies available</div>
    </div>
  )
}

function RentSimPage() {
  return (
    <div className="page">
      <h2>📱 Rent SIM/Receive SMS</h2>
      <div className="empty-state">No SIMs available for rent</div>
    </div>
  )
}

function LotteryPage() {
  return (
    <div className="page">
      <h2>🎰 Lottery</h2>
      <div className="info-box">
        <p>Try your luck! Lottery feature coming soon.</p>
      </div>
    </div>
  )
}

function SsnDobPage() {
  return (
    <div className="page">
      <h2>🆔 SSN/DOB</h2>
      <div className="empty-state">No SSN/DOB data available</div>
    </div>
  )
}

function AccountsPage() {
  return (
    <div className="page">
      <h2>👤 Accounts</h2>
      <div className="empty-state">No accounts available</div>
    </div>
  )
}

function SupportPage() {
  return (
    <div className="page">
      <h2>🎧 Support</h2>
      <div className="info-box">
        <p>Need help? Contact our support team via Telegram or email.</p>
      </div>
      <div className="deposit-card">
        <h3>Contact Methods</h3>
        <p>Telegram: @vclub_support</p>
        <p>Email: support@vclub.shop</p>
      </div>
    </div>
  )
}

function ProfilePage() {
  const { user, logout } = useAuth()
  
  return (
    <div className="page">
      <h2>⚙️ Profile</h2>
      <div className="deposit-card">
        <h3>Account Information</h3>
        <p>Username: {user.username}</p>
        <p>Role: {user.role}</p>
        <p>Balance: ${parseFloat(user.balance || 0).toFixed(2)}</p>
      </div>
      <button className="delete-btn" style={{marginTop: '16px', width: '100%'}} onClick={logout}>
        Logout
      </button>
    </div>
  )
}
