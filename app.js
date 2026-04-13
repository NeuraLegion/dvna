var express = require('express')
var session = require('express-session')
var config = require('./config/server')

var app = express()

app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: config.cookieSecure === true
	}
}))

module.exports = app
