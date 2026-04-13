var express = require('express')
var session = require('express-session')
var passport = require('passport')
var router = require('./routes')
var serverConfig = require('./config/server')

var app = express()

function isHttpsRequest(req) {
	if (req.secure) {
		return true
	}

	var forwardedProto = req.get('x-forwarded-proto')
	if (typeof forwardedProto !== 'string') {
		return false
	}

	return forwardedProto.split(',')[0].trim().toLowerCase() === 'https'
}

function getSessionCookieOptions(req) {
	return {
		httpOnly: true,
		sameSite: 'lax',
		secure: isHttpsRequest(req)
	}
}

app.set('trust proxy', 1)

app.use(function (req, res, next) {
	var originalSetHeader = res.setHeader.bind(res)

	res.setHeader = function (name, value) {
		if (typeof name === 'string' && name.toLowerCase() === 'set-cookie' && isHttpsRequest(req)) {
			var cookies = Array.isArray(value) ? value : [value]

			value = cookies.map(function (cookie) {
				if (typeof cookie !== 'string') {
					return cookie
				}

				var attributes = cookie.split(';').map(function (part) {
					return part.trim()
				})

				var hasSecure = attributes.some(function (attribute) {
					return attribute.toLowerCase() === 'secure'
				})

				return hasSecure ? cookie : cookie + '; Secure'
			})
		}

		return originalSetHeader(name, value)
	}

	next()
})

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: true
	}
}))

app.use(passport.initialize())
app.use(passport.session())
app.use('/', router(passport))

module.exports = app
