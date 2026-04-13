var express = require('express')
var session = require('express-session')
var RedisStore = require('connect-redis')(session)
var serverConfig = require('./config/server')

var app = express()

function isSecureRequest(req) {
	if (req.secure) {
		return true
	}

	var forwardedProto = req.get('X-Forwarded-Proto')
	if (!forwardedProto) {
		return false
	}

	return forwardedProto.split(',')[0].trim().toLowerCase() === 'https'
}

function buildSessionCookieOptions(req) {
	var secureCookie = isSecureRequest(req)

	return {
		httpOnly: true,
		secure: secureCookie,
		sameSite: 'lax'
	}
}

// Ensure Express respects proxy headers so req.secure works correctly when TLS is terminated upstream.
app.set('trust proxy', 1)

var store = new RedisStore({
	url: serverConfig.redisUrl
})

app.use(function (req, res, next) {
	req.sessionCookieOptions = buildSessionCookieOptions(req)
	next()
})

app.use(session({
	secret: serverConfig.sessionSecret,
	resave: false,
	saveUninitialized: false,
	store: store,
	proxy: true,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'lax'
	}
}))

app.use(function (req, res, next) {
	if (req.session && req.session.cookie && req.sessionCookieOptions) {
		req.session.cookie.secure = req.sessionCookieOptions.secure
		req.session.cookie.httpOnly = true
		req.session.cookie.sameSite = 'lax'
	}
	next()
})

module.exports = app
