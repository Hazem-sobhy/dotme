require('dotenv').config()
const nodemailer = require('nodemailer')
const dns = require('dns')

// Force IPv4
dns.setDefaultResultOrder('ipv4first')

console.log('📧 Testing with Gmail SMTP')

const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,  // غيرنا إلى 587
    secure: false, // false للـ 587
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false,
        ciphers: 'SSLv3'
    },
    requireTLS: true
})

async function sendTest() {
    try {
        const info = await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: 'Test Email',
            text: 'Hello from Taplink!'
        })
        console.log('✅ Email sent:', info.messageId)
    } catch (err) {
        console.log('❌ Error:', err.message)
    }
}

sendTest()