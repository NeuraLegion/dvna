var express = require('express')
var session = require('express-session')
var config = require('./config/server')

var app = express()

// Trust the first proxy hop when deployed behind a reverse proxy or load balancer.
// This allows Express/session to correctly detect HTTPS requests via X-Forwarded-Proto.
app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		// Require Secure cookies in production and whenever HTTPS cookie mode is enabled.
		// Keep development usable on plain HTTP when explicitly not running in production.
		secure: config.cookieSecure === true,
		path: '/'
	}
}))

module.exports = app
