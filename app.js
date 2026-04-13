var express = require('express')
var session = require('express-session')
var serverConfig = require('./config/server')

var app = express()

app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production' || serverConfig.cookieSecure === true,
		sameSite: 'lax'
	}
}))

module.exports = app
