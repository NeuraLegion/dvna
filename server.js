var express = require('express')
var app = express()
var session = require('express-session')

// Ensure Express can detect HTTPS when running behind a reverse proxy/load balancer.
// This is required so secure cookies are only issued over trusted TLS connections.
app.set('trust proxy', 1)

var sessionCookie = {
	httpOnly: true,
	sameSite: 'lax'
}

// Only set the Secure flag when the request is served over HTTPS.
// In production, the app should be behind TLS and the cookie will be sent only over secure channels.
if (process.env.NODE_ENV === 'production') {
	sessionCookie.secure = true
}

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me',
	resave: false,
	saveUninitialized: false,
	cookie: sessionCookie
}))

module.exports = app
