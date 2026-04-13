var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var session = require('express-session')
var config = require('./config/server')
var app = express()

app.use(cookieParser())

app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: config.cookieSecure === true,
		path: '/'
	}
}))

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
