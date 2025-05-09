{\rtf1\ansi\ansicpg1252\cocoartf2822
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fmodern\fcharset0 Courier;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;}
{\*\expandedcolortbl;;\cssrgb\c0\c0\c0;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\deftab720
\pard\pardeftab720\partightenfactor0

\f0\fs26\fsmilli13333 \cf0 \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 const express = require('express');\
const AWS = require('aws-sdk');\
const crypto = require('crypto');\
const bitcoin = require('bitcoinjs-lib');\
const axios = require('axios');\
const jwt = require('jsonwebtoken');\
const fs = require('fs');\
\
const app = express();\
app.use(express.json());\
\
// Configure AWS SES (for sending emails)\
AWS.config.update(\{ region: 'us-east-1' \});\
const ses = new AWS.SES();\
\
// Temporary storage for tokens and uploads\
const tokenStore = \{\};\
const UPLOAD_DIR = './uploads';\
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);\
\
const SESSION_SECRET = 'your-secret-key';\
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes\
\
// Middleware to verify session\
const verifySession = (req, res, next) => \{\
    const token = req.headers['authorization'];\
    if (!token) return res.status(401).json(\{ error: 'No session token' \});\
\
    jwt.verify(token, SESSION_SECRET, (err, decoded) => \{\
        if (err) return res.status(401).json(\{ error: 'Invalid or expired session' \});\
        req.user = decoded;\
        next();\
    \});\
\};\
\
// Middleware to enforce role-based access\
const restrictTo = (...roles) => (req, res, next) => \{\
    if (!roles.includes(req.user.role)) \{\
        return res.status(403).json(\{ error: 'Access denied' \});\
    \}\
    next();\
\};\
\
// Authentication: Send magic link\
app.post('/auth/request', (req, res) => \{\
    const \{ email \} = req.body;\
    const token = crypto.randomBytes(16).toString('hex');\
    const expiration = Date.now() + 10 * 60 * 1000; // 10 minutes\
\
    tokenStore[email] = \{ token, expiration \};\
\
    const magicLink = `https://arkova.com/auth/verify?email=$\{email\}&token=$\{token\}`;\
    const params = \{\
        Source: 'no-reply@arkova.com',\
        Destination: \{ ToAddresses: [email] \},\
        Message: \{\
            Subject: \{ Data: 'Arkova Admin Portal - Login Link' \},\
            Body: \{\
                Html: \{ Data: `Click here to log in: <a href="$\{magicLink\}">Login</a>. This link expires in 10 minutes.` \}\
            \}\
        \}\
    \};\
\
    ses.sendEmail(params, (err) => \{\
        if (err) return res.status(500).json(\{ error: 'Failed to send email' \});\
        res.json(\{ message: 'Magic link sent' \});\
    \});\
\});\
\
// Authentication: Verify token and create session\
app.get('/auth/verify', (req, res) => \{\
    const \{ email, token \} = req.query;\
    const stored = tokenStore[email];\
\
    if (!stored || stored.token !== token || Date.now() > stored.expiration) \{\
        return res.status(401).json(\{ error: 'Invalid or expired token' \});\
    \}\
\
    const role = email === 'admin@arkova.com' ? 'admin' : 'user'; // Simplified role assignment\
    const sessionToken = jwt.sign(\{ email, role \}, SESSION_SECRET, \{ expiresIn: '30m' \});\
    console.log(`User $\{email\} logged in at $\{new Date().toISOString()\}`);\
    delete tokenStore[email];\
\
    res.json(\{ sessionToken \});\
\});\
\
// Session renewal\
app.post('/auth/renew', verifySession, (req, res) => \{\
    const \{ email \} = req.user;\
    const newToken = jwt.sign(\{ email \}, SESSION_SECRET, \{ expiresIn: '30m' \});\
    res.json(\{ sessionToken: newToken \});\
\});\
\
// Document upload and processing\
app.post('/upload', verifySession, async (req, res) => \{\
    const \{ file, docType, customerId, uploaderId \} = req.body; // Using multer for file upload in production\
    const filePath = `$\{UPLOAD_DIR\}/$\{Date.now()\}-$\{file.name\}`;\
    fs.writeFileSync(filePath, file); // Simplified file saving\
\
    const fileBuffer = fs.readFileSync(filePath);\
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');\
\
    const inscriptionResponse = await axios.post('https://ordinal-api.com/inscribe', \{\
        data: hash,\
        method: 'OP_RETURN'\
    \});\
    const inscriptionId = inscriptionResponse.data.id;\
\
    const \{ address, privateKey \} = bitcoin.payments.p2tr(\{ network: bitcoin.networks.bitcoin \}).address;\
    const encryptedPrivateKey = crypto.createCipher('aes-256-cbc', 'secret').update(privateKey, 'utf8', 'hex');\
\
    const psbt = new bitcoin.Psbt(\{ network: bitcoin.networks.bitcoin \});\
    psbt.addOutput(\{ address, value: 1000 \}); // Simplified\
\
    const metadata = \{\
        docType,\
        customerId,\
        uploaderId,\
        timestamp: new Date().toISOString(),\
        hash,\
        inscriptionId,\
        wallet: \{ address, encryptedPrivateKey \},\
        status: 'pending'\
    \};\
    console.log('Metadata:', metadata);\
\
    fs.unlinkSync(filePath);\
\
    res.json(\{ message: 'Document uploaded and processing started', inscriptionId \});\
\});\
\
// Status endpoint for dashboard\
app.get('/status', verifySession, (req, res) => \{\
    const statuses = [\
        \{ docType: 'certificate', customerId: '123', hash: 'abc123', inscriptionId: 'xyz', status: 'pending' \}\
    ];\
    res.json(statuses);\
\});\
\
app.listen(3000, () => console.log('Server running on port 3000'));\
}