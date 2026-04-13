var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var passport = require('passport')

var app = express()

// If the app is deployed behind a reverse proxy / load balancer, Express must
// trust the proxy so req.secure and secure cookies work correctly.
app.set('trust proxy', 1)

app.use(session({
	secret: 'keyboard cat',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production'
	}
}))

app.use(passport.initialize())
app.use(passport.session())

module.exports = app
