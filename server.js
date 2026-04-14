var express = require('express')
var path = require('path')
var session = require('express-session')

var app = express()
var isProduction = process.env.NODE_ENV === 'production'

app.set('trust proxy', true)

app.use(session({
	secret: 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		secure: isProduction,
		httpOnly: true,
		sameSite: 'lax'
	}
}))

module.exports = app
