require("dotenv").config()
const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const speakeasy = require("speakeasy")
const QRCode = require("qrcode")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const validator = require("validator")
const nodemailer = require("nodemailer")
const crypto = require("crypto")
const { randomUUID } = require("crypto")
const multer = require("multer")
const path = require("path")
const dns = require('dns')
const fs = require('fs')
const cookieParser = require('cookie-parser')
const { fileTypeFromBuffer } = require('file-type')
const sanitize = require('sanitize-filename')
const Sentry = require('@sentry/node')
const sanitizeHtml = require('sanitize-html')
const sharp = require('sharp')
const mongoose = require('mongoose')

// Force IPv4
dns.setDefaultResultOrder('ipv4first')

const app = express()
app.set('trust proxy', 1)

// ✅ إعدادات البيئة
const IS_PRODUCTION = process.env.NODE_ENV === 'production'
const IS_DEVELOPMENT = !IS_PRODUCTION

const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || JWT_SECRET + '_refresh'

// ✅ تهيئة Sentry للمراقبة
if (process.env.SENTRY_DSN && process.env.SENTRY_DSN !== 'your-sentry-dsn') {
    Sentry.init({ dsn: process.env.SENTRY_DSN })
}

// التحقق من المتغيرات البيئية الأساسية
if (!JWT_SECRET) {
    console.error("❌ JWT_SECRET is not defined in .env file")
    throw error
}

// ✅ الاتصال بـ MongoDB
let cached = global.mongoose

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null }
}

async function connectDB() {

    if (cached.conn) {
        return cached.conn
    }

    if (!cached.promise) {
        cached.promise = mongoose.connect(process.env.MONGODB_URI, {
            bufferCommands: false
        })
    }

    try {
        cached.conn = await cached.promise
        console.log("✅ MongoDB connected")
        return cached.conn
    } catch (e) {
        cached.promise = null
        console.error("❌ MongoDB connection error:", e)
        throw e
    }
}
connectDB()

/* ================= تعريف MongoDB Models ================= */

const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password_hash: { type: String, required: true },
    twofa_secret: String,
    refresh_token: String,
    refresh_token_version: { type: Number, default: 0 },
    reset_token: String,
    reset_expires: Date,
    reset_2fa_token: String,
    reset_2fa_expires: Date,
    locked_until: Date,
    last_login: Date,
    last_active: Date
}, { timestamps: true }))


const Profile = mongoose.models.Profile || mongoose.model('Profile', new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: String,
    bio: String,
    career: String,
    phone: String,
    email: String,
    contact_email: String,
    image_url: String,
    background_url: String,
    theme: { type: String, default: 'dark' },
    custom_theme: { type: mongoose.Schema.Types.Mixed }
}, { timestamps: true }))


const Link = mongoose.models.Link || mongoose.model('Link', new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    url: { type: String, required: true },
    sort_order: { type: Number, default: 0 }
}, { timestamps: true }))


const LinkClick = mongoose.models.LinkClick || mongoose.model('LinkClick', new mongoose.Schema({
    link_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Link', required: true },
    clicked_at: { type: Date, default: Date.now }
}))


const ProfileView = mongoose.models.ProfileView || mongoose.model('ProfileView', new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    ip: String,
    viewed_at: { type: Date, default: Date.now }
}))


const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: String,
    ip: String,
    user_agent: String,
    request_id: String
}, { timestamps: { createdAt: 'created_at' } }))


const BlacklistedToken = mongoose.models.BlacklistedToken || mongoose.model('BlacklistedToken', new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    expires_at: { type: Date, required: true }
}))

/* ================= REQUEST ID MIDDLEWARE ================= */
app.use((req, res, next) => {
    const requestId = randomUUID()
    req.requestId = requestId
    res.setHeader("X-Request-ID", requestId)
    // console.log(`📥 [${requestId}] ${req.method} ${req.url} - ${req.ip}`)
    next()
})

/* ================= COOKIE PARSER ================= */
app.use(cookieParser())

// STATIC FILES FIRST
app.use("/admin", express.static(path.join(__dirname, "admin")))
app.use(express.static(path.join(__dirname, "public")))

// ✅ Nonce middleware (لـ CSP فقط)
app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString("base64")
    res.locals.nonce = nonce
    res.setHeader("X-Nonce", nonce)
    next()
})

/* ================= EMAIL SETUP ================= */
console.log("📧 Configuring email with:", process.env.EMAIL_USER)

const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: { rejectUnauthorized: false }
})

transporter.verify((err, success) => {
    if (err) console.log("❌ SMTP ERROR:", err.message)
    else console.log("✅ SMTP ready to send emails from:", process.env.EMAIL_USER)
})

/* ================= RATE LIMITERS ================= */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: { error: "Too many login attempts. Please try again after 15 minutes." },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
})

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: "Too many registration attempts from this IP. Please try again later." },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
})

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many requests. Please slow down." },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
})

const emailLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: "Too many email requests. Please try again later." },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
})

/* ================= FILE UPLOAD ================= */
const uploadDir = path.join(__dirname, "public/uploads")
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true })
    console.log("✅ Created uploads directory:", uploadDir)
} else {
    console.log("✅ Uploads directory exists:", uploadDir)
}

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
        const safeName = sanitize(file.originalname)
        const unique = Date.now() + "-" + Math.round(Math.random() * 1e9)
        cb(null, unique + path.extname(safeName))
    }
})

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp|jfif/
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase())
    const mimetype = allowedTypes.test(file.mimetype)

    if (mimetype && extname) return cb(null, true)
    cb(new Error("Only image files are allowed (jpeg, jpg, png, gif, webp)"))
}

const upload = multer({ 
    storage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024, files: 1 }
})

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Too many upload attempts. Please try again later." },
    keyGenerator: (req) => req.user?.id ? `user_${req.user.id}` : (req.ip || 'unknown'),
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false
})

/* ================= SECURITY MIDDLEWARE ================= */
app.disable("x-powered-by")

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                "default-src": ["'self'"],
                "script-src": [
                    "'self'", 
                    "https://cdn.jsdelivr.net",
                    (req, res) => `'nonce-${res.locals.nonce || ''}'`
                ],
                "style-src": [
                    "'self'", 
                    "'unsafe-inline'",
                    "https://cdnjs.cloudflare.com",
                    "https://fonts.googleapis.com",
                    "https://fonts.gstatic.com"
                ],
                "img-src": ["'self'", "data:", "https:", "https://api.qrserver.com"],
                "connect-src": ["'self'", "https://cdn.jsdelivr.net", "https://api.qrserver.com"],
                "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
                "frame-ancestors": ["'none'"]
            }
        },
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
    })
)

app.use("/api", apiLimiter)
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('X-XSS-Protection', '1; mode=block')
    next()
})

/* ================= SERVE HTML WITH NONCE ================= */
app.get("/admin/dashboard.html", (req, res) => {
    const filePath = path.join(__dirname, 'admin/dashboard.html')
    fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) return res.status(500).send('Error loading page')
        const nonce = res.locals.nonce || ''
        let modifiedHtml = html.replace(/<meta\s+name="csrf-token"\s+content="[^"]*"\s*>/, '')
        modifiedHtml = modifiedHtml.replace(/nonce="[^"]*"/g, `nonce="${nonce}"`)
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
        res.send(modifiedHtml)
    })
})

app.get("/admin/*.html", (req, res) => {
    const filePath = path.join(__dirname, 'admin', path.basename(req.path))
    fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) return res.status(404).send('Page not found')
        const nonce = res.locals.nonce || ''
        let modifiedHtml = html.replace(/<meta\s+name="csrf-token"\s+content="[^"]*"\s*>/, '')
        modifiedHtml = modifiedHtml.replace(/nonce="[^"]*"/g, `nonce="${nonce}"`)
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
        res.send(modifiedHtml)
    })
})

/* ================= PUBLIC PROFILE PAGE WITH NONCE ================= */
app.get("/:username", (req, res, next) => {
    if (req.params.username.startsWith('api/') || req.params.username.startsWith('admin/')) return next()
    const filePath = path.join(__dirname, "public/index.html")
    fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) return res.status(500).send('Error loading page')
        const nonce = res.locals.nonce || ''
        let modifiedHtml = html.replace(/<script nonce="[^"]*">/g, `<script nonce="${nonce}">`)
        modifiedHtml = modifiedHtml.replace(/{{nonce}}/g, nonce)
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
        res.send(modifiedHtml)
    })
})

/* ================= HELPER FUNCTIONS ================= */
function createFingerprint(req) {
    const data = [
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.headers['sec-ch-ua'] || '',
        req.ip || ''
    ].join('|')
    return crypto.createHash('sha256').update(data).digest('hex')
}

async function constantTimeDelay(startTime) {
    const minDelay = 200
    const elapsed = Number(process.hrtime.bigint() - startTime) / 1_000_000
    if (elapsed < minDelay) await new Promise(resolve => setTimeout(resolve, minDelay - elapsed))
}

function generateTokens(userId, fingerprint, version = 0) {
    const csrfToken = crypto.randomBytes(32).toString("hex")
    const accessToken = jwt.sign(
        { id: userId, fingerprint, csrfToken, version, type: 'access' },
        JWT_SECRET,
        { expiresIn: "15m" }
    )
    const refreshToken = jwt.sign(
        { id: userId, version, type: "refresh" },
        REFRESH_TOKEN_SECRET,
        { expiresIn: "7d" }
    )
    return { accessToken, refreshToken, csrfToken }
}

async function isTokenBlacklisted(token) {
    try {
        const result = await BlacklistedToken.findOne({ token })
        return !!result
    } catch (error) {
        console.error("Blacklist check error:", error)
        return false
    }
}

async function detectAttack(req, userId) {
    try {
        const fiveMinsAgo = new Date(Date.now() - 5 * 60 * 1000)
        const attempts = await AuditLog.countDocuments({ user_id: userId, action: 'LOGIN_FAILED', created_at: { $gt: fiveMinsAgo } })
        if (attempts > 10) {
            await User.findByIdAndUpdate(userId, { locked_until: new Date(Date.now() + 60 * 60 * 1000) })
            if (Sentry) Sentry.captureMessage(`🚨 Brute force attack detected on user ${userId} from IP ${req.ip}`)
        }
    } catch (error) {
        console.error("Attack detection error:", error)
    }
}

async function createAuditLog(userId, action, req) {
    try {
        await AuditLog.create({
            user_id: userId,
            action,
            ip: req.ip || req.connection.remoteAddress,
            user_agent: req.get('User-Agent'),
            request_id: req.requestId
        })
    } catch (error) {
        console.error("Audit log error:", error.message)
    }
}

async function auth(req, res, next) {
    const header = req.headers.authorization
    if (!header) return res.status(401).json({ error: "Unauthorized" })

    const token = header.split(" ")[1]

    try {
        if (await isTokenBlacklisted(token)) return res.status(403).json({ error: "Token revoked" })

        const decoded = jwt.verify(token, JWT_SECRET)
        
        const headerCsrf = req.headers["x-csrf-token"]
        if (!headerCsrf || headerCsrf !== decoded.csrfToken) return res.status(403).json({ error: "Invalid CSRF token" })
        
        const currentFingerprint = createFingerprint(req)
        if (decoded.fingerprint && decoded.fingerprint !== currentFingerprint) return res.status(403).json({ error: "Invalid device fingerprint" })

        req.user = decoded
        
        await User.findByIdAndUpdate(decoded.id, { last_active: new Date() }).catch(err => console.error("Failed to update last_active:", err.message))
        
        next()
    } catch (err) {
        if (err.name === 'TokenExpiredError') return res.status(401).json({ error: "Token expired" })
        res.status(403).json({ error: "Invalid token" })
    }
}

const validateUsername = (username) => username && validator.isLength(username, { min: 3, max: 30 }) && validator.matches(username, /^[a-zA-Z0-9_]+$/)
const validatePassword = (password) => password && validator.isLength(password, { min: 8 }) && validator.matches(password, /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
const validateEmail = (email) => email && validator.isEmail(email)

/* ================= REGISTER ================= */
app.post("/api/register", registerLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body

        if (!validateUsername(username)) return res.status(400).json({ error: "Username must be 3-30 characters and contain only letters, numbers, and underscores" })
        if (!validateEmail(email)) return res.status(400).json({ error: "Invalid email format" })
        if (!validatePassword(password)) return res.status(400).json({ error: "Password must be at least 8 characters with uppercase, lowercase, and number" })

        const existingUser = await User.findOne({ $or: [{ username }, { email }] })
        if (existingUser) return res.status(400).json({ error: "Registration failed" })

        const hash = await bcrypt.hash(password, 12)

        const session = await mongoose.startSession()
        session.startTransaction()

        try {
            const user = await User.create([{
                username,
                email,
                password_hash: hash,
                refresh_token_version: 0
            }], { session })

            const userId = user[0]._id

            await Profile.create([{ user_id: userId }], { session })

            const secret = speakeasy.generateSecret({ length: 20, name: `DotMe:${username}` })

            await User.findByIdAndUpdate(userId, { twofa_secret: secret.base32 }, { session })

            await session.commitTransaction()

            const qr = await QRCode.toDataURL(secret.otpauth_url)
            await createAuditLog(userId, 'REGISTER', req)

            res.json({ message: "Registration successful! Scan QR with Google Authenticator", qr })

        } catch (err) {
            await session.abortTransaction()
            throw err
        } finally {
            session.endSession()
        }

    } catch (err) {
        console.error(`❌ [${req.requestId}] Registration error:`, err.message)
        res.status(500).json({ error: "Server error during registration" })
    }
})

/* ================= LOGIN (محمي من Timing Attacks) ================= */
app.post("/api/login", loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body

        if (!username || !password) return res.status(400).json({ error: "Username and password required" })

        const constantTimePassword = "dummy_password_for_timing_" + crypto.randomBytes(4).toString('hex')
        const startTime = process.hrtime.bigint()

        const user = await User.findOne({ username })

        let isValidUser = !!user
        let userForCompare = user

        if (!isValidUser) {
            userForCompare = {
                id: null,
                password_hash: await bcrypt.hash(constantTimePassword, 12),
                twofa_secret: null,
                locked_until: null
            }
        }

        if (userForCompare?.locked_until && new Date(userForCompare.locked_until) > new Date()) {
            const minutesLeft = Math.ceil((new Date(userForCompare.locked_until) - new Date()) / (1000 * 60))
            await constantTimeDelay(startTime)
            return res.status(403).json({ error: `Account locked. Try again in ${minutesLeft} minutes.` })
        }

        const match = await bcrypt.compare(password, userForCompare.password_hash)

        await constantTimeDelay(startTime)

        if (!isValidUser || !match) {
            if (isValidUser) {
                await createAuditLog(user._id, 'LOGIN_FAILED', req)
                await detectAttack(req, user._id)

                const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000)
                const failedAttempts = await AuditLog.countDocuments({ user_id: user._id, action: 'LOGIN_FAILED', created_at: { $gt: fifteenMinsAgo } })
                if (failedAttempts >= 5) await User.findByIdAndUpdate(user._id, { locked_until: new Date(Date.now() + 15 * 60 * 1000) })
            }
            return res.status(403).json({ error: "Invalid credentials" })
        }

        await User.findByIdAndUpdate(user._id, { locked_until: null, last_login: new Date() })

        await createAuditLog(user._id, 'LOGIN_SUCCESS', req)

        if (user.twofa_secret) return res.json({ step: "2fa", userId: user._id })

        const fingerprint = createFingerprint(req)
        const version = user.refresh_token_version || 0
        const { accessToken, refreshToken, csrfToken } = generateTokens(user._id, fingerprint, version)

        await User.findByIdAndUpdate(user._id, { refresh_token: refreshToken })

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        res.json({ token: accessToken, csrfToken, username: user.username })

    } catch (err) {
        console.error(`❌ [${req.requestId}] Login error:`, err.message)
        res.status(500).json({ error: "Server error during login" })
    }
})

/* ================= VERIFY OTP ================= */
app.post("/api/2fa/verify", async (req, res) => {
    try {
        const { userId, code } = req.body

        if (!userId || !code) return res.status(400).json({ error: "User ID and code required" })

        const user = await User.findById(userId)

        if (!user) return res.status(404).json({ error: "User not found" })

        const verified = speakeasy.totp.verify({
            secret: user.twofa_secret,
            encoding: "base32",
            token: code,
            window: 2
        })

        if (!verified) {
            await createAuditLog(userId, '2FA_FAILED', req)
            return res.status(403).json({ error: "Invalid or expired code" })
        }

        await createAuditLog(userId, '2FA_SUCCESS', req)

        const fingerprint = createFingerprint(req)
        const version = user.refresh_token_version || 0
        const { accessToken, refreshToken, csrfToken } = generateTokens(userId, fingerprint, version)

        await User.findByIdAndUpdate(userId, { refresh_token: refreshToken })

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        res.json({ token: accessToken, csrfToken, username: user.username })

    } catch (err) {
        console.error(`❌ [${req.requestId}] 2FA verification error:`, err.message)
        res.status(500).json({ error: "Server error during verification" })
    }
})

/* ================= REFRESH TOKEN ================= */
app.post("/api/refresh-token", async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken
        if (!refreshToken) return res.status(401).json({ error: "No refresh token" })

        // ✅ التحقق من أن التوكن مش مسحوب
        if (await isTokenBlacklisted(refreshToken)) return res.status(403).json({ error: "Token revoked" })

        let decoded
        try {
            decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET)
        } catch (err) {
            return res.status(403).json({ error: "Invalid refresh token" })
        }

        if (decoded.type !== 'refresh') return res.status(403).json({ error: "Invalid token type" })

        const user = await User.findById(decoded.id)

        if (!user) return res.status(403).json({ error: "User not found" })

        if (user.refresh_token !== refreshToken) {
            await createAuditLog(decoded.id, 'REFRESH_TOKEN_MISMATCH', req)
            await User.findByIdAndUpdate(decoded.id, { 
                refresh_token: null, 
                refresh_token_version: (user.refresh_token_version || 0) + 1 
            })
            return res.status(403).json({ error: "Invalid refresh token" })
        }

        if (decoded.version !== user.refresh_token_version) {
            await createAuditLog(decoded.id, 'REFRESH_TOKEN_VERSION_MISMATCH', req)
            return res.status(403).json({ error: "Token version mismatch" })
        }

        // ✅ سحب التوكن القديم (مع التحقق من عدم التكرار)
        if (decoded.exp) {
            try {
                // استخدم updateOne مع upsert: false عشان منضفش duplicate
                await BlacklistedToken.updateOne(
                    { token: refreshToken },
                    { 
                        token: refreshToken, 
                        expires_at: new Date(decoded.exp * 1000) 
                    },
                    { upsert: true } // لو موجود مش هيعمل duplicate
                )
            } catch (e) {
                console.log("Token already blacklisted, continuing...")
            }
        }

        // ✅ إنشاء توكنات جديدة مع نفس رقم الإصدار
        const fingerprint = createFingerprint(req)
        const version = user.refresh_token_version
        const { accessToken, refreshToken: newRefreshToken, csrfToken } = generateTokens(decoded.id, fingerprint, version)

        await User.findByIdAndUpdate(decoded.id, { refresh_token: newRefreshToken })

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        await createAuditLog(decoded.id, 'REFRESH_TOKEN_SUCCESS', req)

        res.json({ token: accessToken, csrfToken })

    } catch (err) {
        console.error(`❌ [${req.requestId}] Refresh token error:`, err.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= LOGOUT ================= */
app.post("/api/logout", auth, async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken
        const accessToken = req.headers.authorization?.split(" ")[1]

        await User.findByIdAndUpdate(req.user.id, { refresh_token: null })

        if (accessToken) {
            const decoded = jwt.decode(accessToken)
            if (decoded && decoded.exp) {
                try {
                    await BlacklistedToken.updateOne(
                        { token: accessToken },
                        { token: accessToken, expires_at: new Date(decoded.exp * 1000) },
                        { upsert: true }
                    )
                } catch (e) {}
            }
        }

        if (refreshToken) {
            const decoded = jwt.decode(refreshToken)
            if (decoded && decoded.exp) {
                try {
                    await BlacklistedToken.updateOne(
                        { token: refreshToken },
                        { token: refreshToken, expires_at: new Date(decoded.exp * 1000) },
                        { upsert: true }
                    )
                } catch (e) {}
            }
        }

        res.clearCookie('refreshToken')
        await createAuditLog(req.user.id, 'LOGOUT', req)
        res.json({ message: "Logged out successfully" })

    } catch (err) {
        console.error(`❌ [${req.requestId}] Logout error:`, err.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= FILE UPLOAD (MIME Validation محسن) ================= */
app.post("/api/upload", 
    auth, 
    uploadLimiter,
    upload.single("image"), 
    async (req, res) => {
    try {
        console.log("=".repeat(50))
        console.log("📸 UPLOAD REQUEST RECEIVED")
        console.log("=".repeat(50))
        
        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" })
        }

        // ✅ التحقق من حجم الملف
        if (req.file.size > 5 * 1024 * 1024) {
            await fs.promises.unlink(req.file.path)
            return res.status(400).json({ error: "File too large. Maximum size is 5MB" })
        }

        // ✅ قراءة الملف
        const fileBuffer = await fs.promises.readFile(req.file.path)
        
        // 1️⃣ التحقق باستخدام file-type
        const type = await fileTypeFromBuffer(fileBuffer)
        
        // 2️⃣ التحقق باستخدام magic numbers يدوياً
        const magicNumbers = {
            'jpg': [0xFF, 0xD8, 0xFF],
            'jpeg': [0xFF, 0xD8, 0xFF],
            'png': [0x89, 0x50, 0x4E, 0x47],
            'gif': [0x47, 0x49, 0x46],
            'webp': [0x52, 0x49, 0x46, 0x46],
        }

        let isValidByMagic = false
        const bufferStart = Array.from(fileBuffer.slice(0, 8))
        
        for (const [format, magic] of Object.entries(magicNumbers)) {
            let match = true
            for (let i = 0; i < magic.length; i++) {
                if (bufferStart[i] !== magic[i]) {
                    match = false
                    break
                }
            }
            if (match) {
                isValidByMagic = true
                break
            }
        }

        // ✅ التحقق من صحة الامتداد
        const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.jfif']
        const fileExt = path.extname(req.file.originalname).toLowerCase()
        
        if (!allowedExtensions.includes(fileExt)) {
            await fs.promises.unlink(req.file.path)
            return res.status(400).json({ error: "Invalid file extension" })
        }

        // ✅ التحقق من تطابق magic numbers مع الامتداد
        if (!isValidByMagic) {
            await fs.promises.unlink(req.file.path)
            return res.status(400).json({ error: "File content does not match extension" })
        }

        // ✅ قائمة MIME types المسموح بها
        const allowedMimeTypes = [
            'image/jpeg', 'image/jpg', 'image/pjpeg',
            'image/png', 'image/x-png',
            'image/gif',
            'image/webp',
            'image/jfif'
        ]

        if (!type || !allowedMimeTypes.includes(type.mime)) {
            console.error("❌ Invalid file type:", type?.mime)
            await fs.promises.unlink(req.file.path)
            return res.status(400).json({ error: "Invalid image type. Allowed: JPEG, PNG, GIF, WEBP" })
        }

        // ✅ التحقق باستخدام sharp (لمنع الملفات التالفة)
        try {
            await sharp(fileBuffer).metadata()
        } catch (sharpError) {
            console.error("❌ Corrupted image:", sharpError.message)
            await fs.promises.unlink(req.file.path)
            return res.status(400).json({ error: "Corrupted or invalid image file" })
        }

        // ✅ فحص إضافي: البحث عن scripts داخل الصورة
        const fileContent = fileBuffer.toString('utf8', 0, Math.min(fileBuffer.length, 1024))
        const suspiciousPatterns = [
            '<?php', '<script', 'javascript:', 'eval(', 'document.cookie',
            '<%', '${', '{{', '<!--', '-->', '<?=', '<!ENTITY',
            'require_once', 'include_once', 'system(', 'exec(',
            'base64_decode', 'str_rot13', 'gzuncompress'
        ]
        
        for (const pattern of suspiciousPatterns) {
            if (fileContent.includes(pattern)) {
                console.error(`❌ Suspicious pattern detected: ${pattern}`)
                await fs.promises.unlink(req.file.path)
                return res.status(400).json({ error: "File contains suspicious content" })
            }
        }

        // ✅ التأكد من أن الملف ليس له امتداد مزدوج
        if (req.file.filename.split('.').length > 2) {
            await fs.promises.unlink(req.file.path)
            return res.status(400).json({ error: "Invalid filename pattern" })
        }

        const url = "/uploads/" + req.file.filename
        await createAuditLog(req.user.id, 'FILE_UPLOAD', req)
        
        console.log("✅ Upload successful:", url)
        console.log("📊 File details:", {
            size: req.file.size,
            type: type.mime,
            extension: fileExt,
            validatedBy: "file-type + magic + sharp"
        })
        
        res.json({ url })
        
    } catch (error) {
        console.error("❌ UPLOAD ERROR:", error.message)
        if (req.file && req.file.path) {
            try { await fs.promises.unlink(req.file.path) } catch (e) {}
        }
        res.status(500).json({ error: "Failed to upload file" })
    }
})

/* ================= PUBLIC PROFILE ================= */
app.get("/api/profile/:username", async (req, res) => {
    try {
        const username = req.params.username

        if (!username || !validateUsername(username)) {
            return res.status(404).json({ error: "User not found" })
        }

        const user = await User.findOne({ username })

        if (!user) {
            await new Promise(resolve => setTimeout(resolve, Math.random() * 200 + 100))
            return res.status(404).json({ error: "User not found" })
        }

        const userId = user._id

        const referer = req.headers.referer || ""
        const isAdminRequest = referer.includes('/admin') || req.headers.authorization
        
        if (!isAdminRequest) {
            await ProfileView.create({
                user_id: userId,
                ip: req.ip || req.connection.remoteAddress
            })
        }

        const profile = await Profile.findOne({ user_id: userId })
        const links = await Link.find({ user_id: userId }).sort({ position: 1 })

        res.json({
            profile: profile || {},
            links: links
        })

    } catch (error) {
        console.error("Profile error:", error.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= ADMIN PROFILE ================= */
app.get("/api/admin/profile", auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({ user_id: req.user.id })
        const links = await Link.find({ user_id: req.user.id }).sort({ position: 1 })
        const user = await User.findById(req.user.id)

        res.json({
            profile: {
                ...(profile ? profile.toObject() : {}),
                username: user?.username
            },
            links: links
        })
    } catch (error) {
        console.error("Admin profile error:", error.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= UPDATE PROFILE ================= */
app.put("/api/profile", auth, async (req, res) => {
    try {
        const { name, bio, career, phone, image_url, background_url, theme } = req.body
        
        const sanitizedData = {
            name: sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} }),
            bio: sanitizeHtml(bio, { allowedTags: [], allowedAttributes: {} }),
            career: sanitizeHtml(career, { allowedTags: [], allowedAttributes: {} }),
            phone: sanitizeHtml(phone, { allowedTags: [], allowedAttributes: {} }),
            image_url: sanitizeHtml(image_url || '', { allowedTags: [], allowedAttributes: {} }),
            background_url: sanitizeHtml(background_url || '', { allowedTags: [], allowedAttributes: {} }),
            theme: sanitizeHtml(theme || 'default', { allowedTags: [], allowedAttributes: {} })
        }

        await Profile.findOneAndUpdate(
            { user_id: req.user.id },
            { 
                name: sanitizedData.name,
                bio: sanitizedData.bio,
                career: sanitizedData.career,
                phone: sanitizedData.phone,
                image_url: sanitizedData.image_url,
                background_url: sanitizedData.background_url,
                theme: sanitizedData.theme,
                updated_at: new Date()
            },
            { upsert: true }
        )

        await createAuditLog(req.user.id, 'PROFILE_UPDATE', req)
        res.json({ message: "Profile updated successfully" })
    } catch (error) {
        console.error("Profile update error:", error.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= FORGOT PASSWORD ================= */
app.post("/api/forgot-password", emailLimiter, async (req, res) => {
    try {
        const { email } = req.body

        if (!validateEmail(email)) {
            return res.status(400).json({ error: "Valid email required" })
        }

        const user = await User.findOne({ email })

        let message = "If the email exists, a reset link was sent."

        if (user) {
            const rawToken = crypto.randomBytes(32).toString("hex")
            const hashedToken = crypto.createHash("sha256").update(rawToken).digest("hex")

            user.reset_token = hashedToken
            user.reset_expires = new Date(Date.now() + 60 * 60 * 1000) // 1 hour
            await user.save()

            const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`
            const link = `${baseUrl}/reset.html?token=${rawToken}`

            await transporter.sendMail({
                from: `"DotMe" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: "Password Reset Request",
                html: `
                <div style="font-family: Arial; padding: 20px; background: #f5f5f5;">
                    <h2 style="color: #4CAF50;">Password Reset Request</h2>
                    <p>Click the button below to reset your password:</p>
                    <a href="${link}" style="display: inline-block; padding: 12px 24px; background: #4CAF50; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">Reset Password</a>
                    <p>This link will expire in 1 hour.</p>
                    <hr>
                    <p style="color: #777; font-size: 12px;">If you didn't request this, ignore this email.</p>
                </div>
                `
            })

            await createAuditLog(user._id, 'PASSWORD_RESET_REQUEST', req)
        }

        res.json({ message })

    } catch (e) {
        console.error("Forgot password error:", e.message)
        res.status(500).json({ error: "Server error processing request" })
    }
})

/* ================= SERVE FORGOT PASSWORD PAGE WITH NONCE ================= */
app.get("/forgot.html", (req, res) => {
    const filePath = path.join(__dirname, 'public/forgot.html')
    fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) {
            console.error("Error reading forgot.html:", err)
            return res.status(500).send('Error loading page')
        }
        
        const nonce = res.locals.nonce || ''
        
        let modifiedHtml = html.replace(
            /<meta\s+name="csrf-token"\s+content="[^"]*"\s*>/,
            ''
        )
        
        modifiedHtml = modifiedHtml.replace(
            /nonce="[^"]*"/g,
            `nonce="${nonce}"`
        )
        
        res.send(modifiedHtml)
    })
})

/* ================= SERVE CANT-REACH-OTP PAGE WITH NONCE ================= */
app.get("/cant-reach-otp.html", (req, res) => {
    const filePath = path.join(__dirname, 'public/cant-reach-otp.html')
    fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) {
            console.error("Error reading cant-reach-otp.html:", err)
            return res.status(500).send('Error loading page')
        }
        
        const nonce = res.locals.nonce || ''
        
        let modifiedHtml = html.replace(
            /<meta\s+name="csrf-token"\s+content="[^"]*"\s*>/,
            ''
        )
        
        modifiedHtml = modifiedHtml.replace(
            /nonce="[^"]*"/g,
            `nonce="${nonce}"`
        )
        
        res.send(modifiedHtml)
    })
})

/* ================= SERVE RESET-2FA PAGE WITH NONCE ================= */
app.get("/reset-2fa.html", (req, res) => {
    const filePath = path.join(__dirname, 'public/reset-2fa.html')
    fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) {
            console.error("Error reading reset-2fa.html:", err)
            return res.status(500).send('Error loading page')
        }
        
        const nonce = res.locals.nonce || ''
        
        let modifiedHtml = html.replace(
            /<meta\s+name="csrf-token"\s+content="[^"]*"\s*>/,
            ''
        )
        
        modifiedHtml = modifiedHtml.replace(
            /nonce="[^"]*"/g,
            `nonce="${nonce}"`
        )
        
        res.send(modifiedHtml)
    })
})

// ================= THEMES ENDPOINTS =================

// جلب الثيمات المتاحة
app.get("/api/admin/themes", auth, async (req, res) => {
    try {
        const themes = [
            // Free Themes
            { id: 1, name: '🌑 Dark Modern', preview: 'linear-gradient(135deg, #0f172a, #020617)', class: 'dark', is_premium: false },
            { id: 2, name: '☀️ Light Clean', preview: 'linear-gradient(135deg, #ffffff, #f8fafc)', class: 'light', is_premium: false },
            { id: 3, name: '📱 Minimal', preview: '#fafafa', class: 'minimal', is_premium: false },
            
            // Premium Themes
            { id: 4, name: '🌈 Aurora Borealis', preview: 'radial-gradient(circle at 30% 30%, #ff0080, #7928ca, #00c6ff)', class: 'aurora', is_premium: true },
            { id: 5, name: '💿 Neon Cyberpunk', preview: '#030014', class: 'neon', is_premium: true },
            { id: 6, name: '🥂 Glassmorphism', preview: 'url(https://images.unsplash.com/photo-1519681393784-d120267933ba?w=500)', class: 'glass', is_premium: true },
            { id: 7, name: '🌅 Sunset Vibes', preview: 'linear-gradient(135deg, #ff6b6b, #feca57, #ff9f43)', class: 'sunset', is_premium: true },
            { id: 8, name: '⚡ Ocean Deep', preview: 'linear-gradient(135deg, #00b4db, #0083b0, #005aa7)', class: 'ocean', is_premium: true },
            { id: 9, name: '🌿 Forest', preview: 'linear-gradient(135deg, #134e5e, #71b280)', class: 'forest', is_premium: true },
            { id: 10, name: '🍂 Autumn', preview: 'linear-gradient(135deg, #f12711, #f5af19)', class: 'autumn', is_premium: true },
            { id: 11, name: '💜 Lavender', preview: 'linear-gradient(135deg, #baabf9, #d8b5ff)', class: 'lavender', is_premium: true },
            { id: 12, name: '🎮 Retro Game', preview: 'linear-gradient(135deg, #654ea3, #eaafc8)', class: 'retro', is_premium: true },
            { id: 13, name: '🌌 Midnight', preview: 'linear-gradient(135deg, #141e30, #243b55)', class: 'midnight', is_premium: true },
            { id: 14, name: '🍊 Citrus', preview: 'linear-gradient(135deg, #fdc830, #f37335)', class: 'citrus', is_premium: true }
        ];
        
        res.json(themes);
        
    } catch (error) {
        console.error("Themes error:", error);
        res.status(500).json({ error: "Failed to load themes" });
    }
});

// اختيار ثيم
app.post("/api/admin/select-theme", auth, async (req, res) => {
    try {
        const { theme } = req.body;
        
        if (!theme) {
            return res.status(400).json({ error: "Theme is required" });
        }
        
        // ✅ كل الثيمات متاحة (بدون Premium)
        const allowedThemes = [
            'dark', 'light', 'minimal', 'aurora', 'neon', 'glass', 
            'sunset', 'ocean', 'forest', 'autumn', 'lavender', 
            'retro', 'midnight', 'citrus'
        ];
        
        if (!allowedThemes.includes(theme)) {
            return res.status(400).json({ error: "Invalid theme" });
        }
        
        await Profile.findOneAndUpdate(
            { user_id: req.user.id },
            { theme: theme },
            { upsert: true }
        );
        
        await createAuditLog(req.user.id, 'THEME_CHANGED', req);
        res.json({ success: true, message: "Theme updated successfully" });
        
    } catch (error) {
        console.error("Select theme error:", error);
        res.status(500).json({ error: "Failed to select theme" });
    }
});

// حفظ التخصيصات المخصصة
app.post("/api/admin/save-theme", auth, async (req, res) => {
    try {
        const themeData = req.body;
        
        if (!themeData) {
            return res.status(400).json({ error: "Theme data is required" });
        }
        
        await Profile.findOneAndUpdate(
            { user_id: req.user.id },
            { custom_theme: themeData },
            { upsert: true }
        );
        
        await createAuditLog(req.user.id, 'CUSTOM_THEME_SAVED', req);
        res.json({ success: true, message: "Custom theme saved successfully" });
        
    } catch (error) {
        console.error("Save theme error:", error);
        res.status(500).json({ error: "Failed to save theme" });
    }
});

// استرجاع التخصيصات المخصصة
app.get("/api/admin/custom-theme", auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({ user_id: req.user.id });
        
        res.json({ 
            custom_theme: profile?.custom_theme || null 
        });
        
    } catch (error) {
        console.error("Get custom theme error:", error);
        res.status(500).json({ error: "Failed to get custom theme" });
    }
});

// ================= GET USER THEME =================
app.get("/api/profile/:username/theme", async (req, res) => {
    try {
        const username = req.params.username;
        
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        
        const profile = await Profile.findOne({ user_id: user._id });
        
        res.json({
            theme: profile?.theme || "dark",
            custom_theme: profile?.custom_theme || null
        });
        
    } catch (error) {
        console.error("Theme error:", error);
        res.status(500).json({ error: "Failed to load theme" });
    }
});

// ================= DRAG & DROP ENDPOINT =================
app.post("/api/links/reorder", auth, async (req, res) => {
    try {
        const { order } = req.body;
        
        console.log("Received order:", order);
        
        if (!order || !Array.isArray(order)) {
            return res.status(400).json({ error: "Invalid order data" });
        }
        
        for (const item of order) {
            if (!item.id || typeof item.order !== 'number') {
                throw new Error("Invalid order item");
            }
            
            const link = await Link.findOne({ _id: item.id, user_id: req.user.id });
            
            if (!link) {
                throw new Error(`Link ${item.id} not found or unauthorized`);
            }
            
            link.sort_order = item.order;
            await link.save();
        }
        
        await createAuditLog(req.user.id, 'LINKS_REORDERED', req);
        res.json({ success: true, message: "Links reordered successfully" });
        
    } catch (error) {
        console.error("Reorder error:", error);
        res.status(500).json({ error: error.message || "Failed to reorder links" });
    }
});

/* ================= SERVE RESET PAGE WITH NONCE ================= */
app.get("/reset.html", (req, res) => {
    const filePath = path.join(__dirname, 'public/reset.html')
    fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) {
            console.error("Error reading reset.html:", err)
            return res.status(500).send('Error loading page')
        }
        
        const nonce = res.locals.nonce || ''
        
        let modifiedHtml = html.replace(
            /<meta\s+name="csrf-token"\s+content="[^"]*"\s*>/,
            ''
        )
        
        modifiedHtml = modifiedHtml.replace(
            /nonce="[^"]*"/g,
            `nonce="${nonce}"`
        )
        
        modifiedHtml = modifiedHtml.replace(
            'nonce="{{nonce}}"',
            `nonce="${nonce}"`
        )
        
        res.send(modifiedHtml)
    })
})

/* ================= RESET PASSWORD ================= */
app.post("/api/reset-password", async (req, res) => {
    try {
        const { token, password } = req.body

        if (!token || !password) {
            return res.status(400).json({ error: "Token and password required" })
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ 
                error: "Password must be at least 8 characters with uppercase, lowercase, and number" 
            })
        }

        const hashedToken = crypto.createHash("sha256").update(token).digest("hex")
        const user = await User.findOne({ 
            reset_token: hashedToken,
            reset_expires: { $gt: new Date() }
        })

        if (!user) {
            return res.status(400).json({ error: "Invalid or expired token" })
        }

        const hash = await bcrypt.hash(password, 12)
        
        user.password_hash = hash
        user.reset_token = null
        user.reset_expires = null
        await user.save()

        await createAuditLog(user._id, 'PASSWORD_RESET_SUCCESS', req)
        res.json({ message: "Password updated successfully" })

    } catch (e) {
        console.error("Reset password error:", e.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= RESET 2FA ================= */
app.post("/api/reset-2fa", emailLimiter, async (req, res) => {
    try {
        const { email } = req.body

        if (!validateEmail(email)) {
            return res.status(400).json({ error: "Valid email required" })
        }

        const user = await User.findOne({ email })

        let message = "If the email exists, a reset link will be sent."

        if (user) {
            const rawToken = crypto.randomBytes(32).toString("hex")
            const hashedToken = crypto.createHash("sha256").update(rawToken).digest("hex")

            user.reset_2fa_token = hashedToken
            user.reset_2fa_expires = new Date(Date.now() + 60 * 60 * 1000)
            await user.save()

            const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`
            const link = `${baseUrl}/reset-2fa.html?token=${rawToken}`

            await transporter.sendMail({
                from: `"DotMe" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: "Reset Two-Factor Authentication",
                html: `
                <div style="font-family: Arial; padding: 20px; background: #f5f5f5;">
                    <h2 style="color: #4CAF50;">Reset Two-Factor Authentication</h2>
                    <p>Click the link below to generate a new QR code:</p>
                    <a href="${link}" style="display: inline-block; padding: 12px 24px; background: #4CAF50; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0;">Reset 2FA</a>
                    <p>This link will expire in 1 hour.</p>
                </div>
                `
            })

            await createAuditLog(user._id, '2FA_RESET_REQUEST', req)
        }

        res.json({ message })

    } catch (e) {
        console.error("Reset 2FA error:", e.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= GENERATE NEW QR ================= */
app.post("/api/new-2fa", async (req, res) => {
    try {
        const { token } = req.body

        if (!token) {
            return res.status(400).json({ error: "Token required" })
        }

        const hashedToken = crypto.createHash("sha256").update(token).digest("hex")

        const user = await User.findOne({ 
            reset_2fa_token: hashedToken,
            reset_2fa_expires: { $gt: new Date() }
        })

        if (!user) {
            return res.status(400).json({ error: "Invalid or expired token" })
        }

        const secret = speakeasy.generateSecret({
            length: 20,
            name: "DotMe:" + user.username
        })

        user.twofa_secret = secret.base32
        user.reset_2fa_token = null
        user.reset_2fa_expires = null
        await user.save()

        await createAuditLog(user._id, '2FA_RESET_COMPLETE', req)

        const qr = await QRCode.toDataURL(secret.otpauth_url)
        res.json({ qr })

    } catch (e) {
        console.error("New 2FA error:", e.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= LINKS ================= */
app.post("/api/link", auth, async (req, res) => {
    try {
        let { name, url } = req.body

        if (!name || !url) {
            return res.status(400).json({ error: "Name and URL required" })
        }

        name = sanitizeHtml(name, { 
            allowedTags: [], 
            allowedAttributes: {} 
        }).trim()

        if (name.length === 0 || name.length > 100) {
            return res.status(400).json({ error: "Invalid link name" })
        }

        const urlLower = url.toLowerCase()
        if (urlLower.startsWith('javascript:') || 
            urlLower.startsWith('data:') ||
            urlLower.startsWith('vbscript:') ||
            urlLower.startsWith('file:')) {
            return res.status(400).json({ error: "Invalid URL protocol" })
        }

        if (!validator.isURL(url, { 
            protocols: ['http', 'https'], 
            require_protocol: true,
            require_valid_protocol: true
        })) {
            return res.status(400).json({ error: "Invalid URL - must be http:// or https://" })
        }

        const linkCount = await Link.countDocuments({ user_id: req.user.id })

        if (linkCount >= 23) {
            return res.status(400).json({ error: "Maximum 23 links allowed" })
        }

        const link = await Link.create({
            user_id: req.user.id,
            name: name,
            url: url
        })

        await createAuditLog(req.user.id, 'LINK_ADD', req)
        res.json({ 
            message: "Link added successfully",
            linkId: link._id 
        })

    } catch (error) {
        console.error("Add link error:", error.message)
        res.status(500).json({ error: "Server error" })
    }
})

app.delete("/api/link/:id", auth, async (req, res) => {
    try {
        const id = req.params.id

        const result = await Link.deleteOne({ _id: id, user_id: req.user.id })

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "Link not found" })
        }

        await createAuditLog(req.user.id, 'LINK_DELETE', req)
        res.json({ message: "Link deleted successfully" })

    } catch (error) {
        console.error("Delete link error:", error.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= CLICK TRACKING ================= */
app.post("/api/link/:id/click", async (req, res) => {
    try {
        const linkId = req.params.id

        const link = await Link.findById(linkId)

        if (!link) {
            return res.status(404).json({ error: "Link not found" })
        }

        await LinkClick.create({ link_id: linkId })
        
        res.json({ success: true })
    } catch (error) {
        console.error("Click tracking error:", error.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= DASHBOARD ================= */
app.get("/api/dashboard", auth, async (req, res) => {
    try {
        const userId = req.user.id

        const [viewsCount, linksCount, clicksCount] = await Promise.all([
            ProfileView.countDocuments({ user_id: userId }),
            Link.countDocuments({ user_id: userId }),
            LinkClick.countDocuments({ link_id: { $in: (await Link.find({ user_id: userId }).select('_id')).map(l => l._id) } })
        ])

        res.json({
            views: viewsCount,
            links: linksCount,
            clicks: clicksCount
        })

    } catch (error) {
        console.error("Dashboard error:", error.message)
        res.status(500).json({ error: "Server error" })
    }
})

/* ================= CHECK USERNAME ================= */
app.get("/api/check-username/:username", async (req, res) => {
    try {
        const username = req.params.username

        await new Promise(resolve => setTimeout(resolve, Math.random() * 200 + 100))

        if (!validateUsername(username)) {
            return res.json({ 
                available: false,
                message: "Username check completed"
            })
        }

        const user = await User.findOne({ username })

        res.json({ 
            available: !user,
            message: "Username check completed"
        })

    } catch (error) {
        console.error("Check username error:", error.message)
        res.status(500).json({ 
            available: false,
            message: "Username check failed"
        })
    }
})

/* ================= HEALTH CHECK ================= */
app.get("/api/health", async (req, res) => {
    try {
        const startTime = Date.now()
        await mongoose.connection.db.admin().ping()
        const dbLatency = Date.now() - startTime

        res.json({
            status: "OK",
            uptime: process.uptime(),
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development',
            database: {
                connected: true,
                latency: `${dbLatency}ms`
            },
            requestId: req.requestId
        })
    } catch (err) {
        console.error("Health check failed:", err.message)
        res.status(500).json({
            status: "ERROR",
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development',
            database: {
                connected: false,
                error: err.message
            },
            requestId: req.requestId
        })
    }
})

/* ================= ERROR HANDLING ================= */
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: "File too large. Maximum size is 5MB" })
        }
        return res.status(400).json({ error: error.message })
    }
    next(error)
})

app.use((req, res) => {
    res.status(404).json({ 
        error: "Route not found",
        requestId: req.requestId 
    })
})

app.use((err, req, res, next) => {
    const errorResponse = IS_PRODUCTION 
        ? { error: "Internal server error" }
        : { 
            error: err.message,
            stack: err.stack,
            requestId: req.requestId
        }

    if (IS_DEVELOPMENT) {
        console.error({
            error: err.message,
            stack: err.stack,
            requestId: req.requestId
        })
    }
    
    if (Sentry) {
        Sentry.captureException(err)
    }
    
    res.status(500).json(errorResponse)
})

/* ================= SERVER ================= */
if (require.main === module) {
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log("\n" + "=".repeat(60))
        console.log("🚀 DotMe Server (MongoDB Edition)")
        console.log("=".repeat(60))
        console.log(`📡 Port: ${PORT}`)
        console.log(`🌍 URL: http://localhost:${PORT}`)
        console.log(`🌍 Network: http://${getLocalIP()}:${PORT}`)
        console.log("=".repeat(60) + "\n")
    })
}

function getLocalIP() {
    const nets = require('os').networkInterfaces()
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) return net.address
        }
    }
    return '192.168.1.10'
}

process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server')
    mongoose.connection.close()
    process.exit(0)
})

module.exports = app