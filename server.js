require('dotenv').config() // safe in production — just skips if no .env file

const express   = require('express')
const cors      = require('cors')
const bcrypt    = require('bcryptjs')
const jwt       = require('jsonwebtoken')
const rateLimit = require('express-rate-limit')
const path      = require('path')
const crypto    = require('crypto')

// Use native fetch (Node 18+) — no node-fetch needed
const fetchFn = globalThis.fetch || require('node-fetch')

const {
  getUser, getUserById, createUser, updateLastLogin, updatePlan,
  countMonthlyGenerations, logGeneration, getPlan,
  getAllUsers, getStats
} = require('./database')

const app  = express()
const PORT = process.env.PORT || 3000
const isProd = process.env.NODE_ENV === 'production'

// ── ENV VALIDATION ─────────────────────────────────────────────────────────────
if (!process.env.GROQ_API_KEY) {
  console.error('ERROR: GROQ_API_KEY is not set')
  process.exit(1)
}
if (!process.env.JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is not set')
  process.exit(1)
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('ERROR: JWT_SECRET must be at least 32 characters')
  process.exit(1)
}

const JWT_SECRET = process.env.JWT_SECRET

// ── TRUST PROXY (required for Railway / reverse proxies) ───────────────────────
app.set('trust proxy', 1)

// ── SECURITY HEADERS ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  res.removeHeader('X-Powered-By')
  next()
})

// ── CORS ───────────────────────────────────────────────────────────────────────
// In production: set ALLOWED_ORIGINS in Railway variables to your domain
// e.g. https://propscribe.up.railway.app,https://propscribe.com
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000', 'http://127.0.0.1:3000']

app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (same-origin, mobile apps, Postman)
    if (!origin) return cb(null, true)
    // In development allow everything
    if (!isProd) return cb(null, true)
    if (allowedOrigins.includes(origin)) return cb(null, true)
    cb(new Error('Not allowed by CORS'))
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))

// ── BODY + STATIC ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '50kb' }))
app.use(express.static(path.join(__dirname, 'public')))

// ── RATE LIMITERS ──────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  // Required for Railway (behind a proxy)
  keyGenerator: (req) => req.ip
})

const genLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many generation requests. Slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip
})

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Too many requests.' },
  keyGenerator: (req) => req.ip
})
app.use(globalLimiter)

// ── HELPERS ────────────────────────────────────────────────────────────────────
function sanitize(str, maxLen) {
  maxLen = maxLen || 500
  if (typeof str !== 'string') return ''
  return str
    .slice(0, maxLen)
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, '')
    .trim()
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'propscribe'
    })
    next()
  } catch (err) {
    const msg = err.name === 'TokenExpiredError'
      ? 'Session expired. Please log in again.'
      : 'Invalid token.'
    res.status(401).json({ error: msg })
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Admin access only.' })
    next()
  })
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '30d',
    algorithm: 'HS256',
    issuer: 'propscribe'
  })
}

// ── SEED ADMIN ─────────────────────────────────────────────────────────────────
async function seedAdmin() {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return
  try {
    const existing = getUser.get(process.env.ADMIN_EMAIL.toLowerCase())
    if (!existing) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12)
      createUser.run(process.env.ADMIN_EMAIL.toLowerCase(), hash, 'Admin', 'agency', 1)
      console.log('Admin account created:', process.env.ADMIN_EMAIL)
    }
  } catch (e) {
    console.error('Admin seed error:', e.message)
  }
}
seedAdmin()

// ── HEALTH CHECK (Railway uses this to confirm app is running) ─────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// ── AUTH ROUTES ────────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const name     = sanitize(req.body.name, 100)
  const email    = sanitize(req.body.email, 200).toLowerCase()
  const password = typeof req.body.password === 'string' ? req.body.password : ''

  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password are required.' })
  if (name.length < 2)
    return res.status(400).json({ error: 'Name must be at least 2 characters.' })
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address.' })
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' })
  if (password.length > 128)
    return res.status(400).json({ error: 'Password too long.' })

  const existing = getUser.get(email)
  if (existing) return res.status(400).json({ error: 'Email already registered.' })

  const hash   = await bcrypt.hash(password, 12)
  const result = createUser.run(email, hash, name, 'free', 0)
  const token  = signToken({ id: result.lastInsertRowid, email, is_admin: 0 })

  res.status(201).json({
    token,
    user: { id: result.lastInsertRowid, email, name, plan: 'free' }
  })
})

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email    = sanitize(req.body.email, 200).toLowerCase()
  const password = typeof req.body.password === 'string' ? req.body.password : ''

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required.' })

  const user = getUser.get(email)
  const dummyHash = '$2a$12$dummyhashtopreventtimingattacksxxxxxxxxxxxxxxxxxxxxxxxxx'
  const valid = user
    ? await bcrypt.compare(password, user.password)
    : await bcrypt.compare(password, dummyHash).then(() => false)

  if (!user || !valid)
    return res.status(401).json({ error: 'Invalid email or password.' })

  updateLastLogin.run(user.id)
  const token = signToken({ id: user.id, email: user.email, is_admin: user.is_admin })

  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, plan: user.plan, is_admin: user.is_admin }
  })
})

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = getUserById.get(req.user.id)
  if (!user) return res.status(404).json({ error: 'User not found.' })

  const plan  = getPlan.get(user.plan)
  const usage = countMonthlyGenerations.get(user.id)

  res.json({
    user: { id: user.id, email: user.email, name: user.name, plan: user.plan, is_admin: user.is_admin },
    usage: { used: usage.count, limit: plan ? plan.monthly_limit : 5, plan }
  })
})

// ── GENERATE ───────────────────────────────────────────────────────────────────
app.post('/api/generate', requireAuth, genLimiter, async (req, res) => {
  const user = getUserById.get(req.user.id)
  if (!user) return res.status(404).json({ error: 'User not found.' })

  const plan  = getPlan.get(user.plan)
  const limit = plan ? plan.monthly_limit : 5
  const usage = countMonthlyGenerations.get(user.id)

  if (usage.count >= limit) {
    return res.status(429).json({
      error: 'Monthly limit reached (' + limit + ' generations). Please upgrade.',
      upgrade: true
    })
  }

  const propType    = sanitize(req.body.propType, 100)
  const listingType = sanitize(req.body.listingType, 100)
  const location    = sanitize(req.body.location, 200)
  const price       = sanitize(req.body.price, 100)
  const size        = sanitize(req.body.size, 200)
  const extra       = sanitize(req.body.extra, 1000)
  const tone        = sanitize(req.body.tone, 50)
  const features    = Array.isArray(req.body.features)
    ? req.body.features.map(f => sanitize(f, 100)).slice(0, 20) : []
  const platforms   = Array.isArray(req.body.platforms)
    ? req.body.platforms.map(p => sanitize(p, 50)).slice(0, 10) : []

  if (!propType || !listingType || !location || !price)
    return res.status(400).json({ error: 'Missing required fields.' })

  const prompt = buildPrompt({ propType, listingType, location, price, size, features, extra, tone, platforms })

  try {
    const response = await fetchFn('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + process.env.GROQ_API_KEY
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 3000,
        messages: [{ role: 'user', content: prompt }]
      })
    })

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}))
      throw new Error(errData.error?.message || 'Groq API error ' + response.status)
    }

    const data       = await response.json()
    const text       = data.choices[0].message.content
    const tokensUsed = data.usage?.total_tokens || 0

    logGeneration.run(user.id, propType + ' ' + listingType, location, platforms.join(','), tokensUsed)

    const newUsage = countMonthlyGenerations.get(user.id)
    res.json({ content: text, usage: { used: newUsage.count, limit } })

  } catch (err) {
    console.error('[GENERATE ERROR]', err.message)
    res.status(500).json({ error: 'Generation failed. Please try again.' })
  }
})

// ── PLANS ──────────────────────────────────────────────────────────────────────
app.get('/api/plans', (req, res) => {
  const { db } = require('./database')
  const plans = db.prepare(
    'SELECT name, monthly_limit, price_naira, description FROM plans ORDER BY monthly_limit'
  ).all()
  res.json(plans)
})

// ── ADMIN ──────────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, (req, res) => res.json(getStats.get()))

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = getAllUsers.all().map(({ password, ...safe }) => safe)
  res.json(users)
})

app.post('/api/admin/set-plan', requireAdmin, (req, res) => {
  const userId = parseInt(req.body.userId, 10)
  const plan   = sanitize(req.body.plan, 20)
  if (!userId || isNaN(userId))
    return res.status(400).json({ error: 'Invalid user ID.' })
  if (!['free', 'starter', 'pro', 'agency'].includes(plan))
    return res.status(400).json({ error: 'Invalid plan.' })
  updatePlan.run(plan, userId)
  res.json({ success: true })
})

// ── 404 API ────────────────────────────────────────────────────────────────────
app.use('/api/*', (req, res) => res.status(404).json({ error: 'Route not found.' }))

// ── SERVE FRONTEND ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// ── GLOBAL ERROR HANDLER ───────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.message)
  res.status(500).json({ error: 'Something went wrong. Please try again.' })
})

// ── START ──────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log('\nPropScribe running on port ' + PORT)
  console.log('Environment: ' + (isProd ? 'production' : 'development') + '\n')
})

// ── PROMPT BUILDER ─────────────────────────────────────────────────────────────
function buildPrompt({ propType, listingType, location, price, size, features, extra, tone, platforms }) {
  const featList     = features.length > 0 ? features.join(', ') : 'Standard features'
  const platformList = platforms || []

  const listingInstructions = {
    'For Sale':      'This property is FOR SALE. Write about ownership, investment value, and buying. Use language like "own", "buy", "purchase", "yours forever". Do NOT mention rent or nightly rates.',
    'For Rent':      'This property is FOR RENT. Write about renting, monthly payments, and tenancy. Use language like "rent", "monthly", "tenant", "move in". Do NOT mention buying or sale price.',
    'Short Let':     'This property is a SHORT LET / SHORTLET. Write about short-term stays, nightly or weekly rates, holiday/business accommodation. Use language like "per night", "short stay", "book now", "available for short let", "weekend getaway". Do NOT mention buying or long-term rent.',
    'Lease':         'This property is available on LEASE. Write about long-term leasing arrangements. Use language like "lease", "long-term", "annual lease". Do NOT mention buying or short stays.',
    'Joint Venture': 'This property is a JOINT VENTURE opportunity. Write about partnership, development potential, and ROI. Use language like "JV", "joint venture", "partner", "develop together".'
  }
  const listingNote = listingInstructions[listingType] || ('This is a ' + listingType + ' listing. Write accordingly.')

  let prompt = 'You are PropScribeAI, an expert Nigerian real estate copywriter. Write compelling, authentic property marketing content that converts.\n\n'
  prompt += 'CRITICAL INSTRUCTION: ' + listingNote + '\n\n'
  prompt += 'PROPERTY DETAILS:\n'
  prompt += '- Type: ' + propType + '\n'
  prompt += '- Listing Type: ' + listingType + ' (MOST IMPORTANT — write ONLY for this listing type)\n'
  prompt += '- Location: ' + location + '\n'
  prompt += '- Price: ' + price + '\n'
  prompt += '- Size/Rooms: ' + (size || 'Not specified') + '\n'
  prompt += '- Features: ' + featList + '\n'
  prompt += '- Extra Info: ' + (extra || 'None') + '\n'
  prompt += '- Tone: ' + (tone || 'Professional') + '\n\n'
  prompt += 'Write the following sections. Use EXACTLY these section headers on their own line:\n\n'
  prompt += '[FULL LISTING]\nWrite a professional full property listing (250-350 words) specifically for a ' + listingType + '. ' + (tone || 'Professional') + ' tone. Include all key details, lifestyle picture, location benefits, and a clear call to action. Authentic to the Nigerian market.\n\n'

  if (platformList.includes('WhatsApp'))
    prompt += '[WHATSAPP]\nWhatsApp broadcast (150-200 words). Attention-grabbing emoji opening. Short paragraphs. Key stats, price, location, top 3 features. End with "DM or call to schedule inspection". Natural emojis.\n\n'
  if (platformList.includes('Instagram'))
    prompt += '[INSTAGRAM]\nInstagram caption (100-150 words). Hook first line. Location, features, price. Line breaks. 25-30 hashtags including #LagosRealEstate #NigeriaProperties.\n\n'
  if (platformList.includes('Facebook'))
    prompt += '[FACEBOOK]\nFacebook post (120-180 words). Conversational. All key details. Engaging question. Call to action. No hashtags.\n\n'
  if (platformList.includes('Twitter'))
    prompt += '[TWITTER]\nTwitter/X post. Max 270 characters. Punchy. Most impressive detail first. 2-3 hashtags.\n\n'
  if (platformList.includes('LinkedIn'))
    prompt += '[LINKEDIN]\nLinkedIn post (150-200 words). Investment angle, ROI, location value. No emojis. Strong CTA. 3-5 professional hashtags.\n\n'

  prompt += '[HEADLINES]\n3 punchy attention-grabbing headline options (one per line, no numbering).\n\n'
  prompt += 'Write ONLY the sections above. No extra text outside the sections.'
  return prompt
}
