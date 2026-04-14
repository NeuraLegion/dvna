var express = require('express')
var session = require('express-session')
var path = require('path')

var app = express()

// Trust the reverse proxy so req.secure reflects the original HTTPS request
app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET || 'dvanonsecret',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production' || process.env.HTTPS === 'true',
		sameSite: 'lax',
		path: '/'
	}
}))

// existing app setup continues below...
module.exports = app
