var express = require('express')
var path = require('path')
var session = require('express-session')

var app = express()
var isProduction = process.env.NODE_ENV === 'production'

app.set('trust proxy', 1)

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

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')

	var origin = req.headers.origin
	var trustedOrigins = [
		'http://localhost:9090',
		'https://localhost:9090'
	]

	if (origin && trustedOrigins.indexOf(origin) !== -1) {
		res.setHeader('Access-Control-Allow-Origin', origin)
		res.setHeader('Access-Control-Allow-Credentials', 'true')
		res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
		res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
	}

	res.setHeader('Vary', 'Origin')

	var isSecureRequest = req.secure || req.headers['x-forwarded-proto'] === 'https'
	if (isSecureRequest) {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}

	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")

	if (req.method === 'OPTIONS') {
		return res.sendStatus(204)
	}

	next()
})

module.exports = app
