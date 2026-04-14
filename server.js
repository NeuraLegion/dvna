var express = require('express')
var app = express()
var session = require('express-session')

// Trust reverse proxy headers so secure cookies work correctly behind TLS terminators.
app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: true,
		httpOnly: true,
		sameSite: 'lax'
	}
}))
