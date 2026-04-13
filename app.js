var express = require('express')
var session = require('express-session')

var app = express()

app.set('trust proxy', 1)

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

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: true
	}
}))

app.use(function (req, res, next) {
	if (req.session && req.session.cookie && !isSecureRequest(req)) {
		res.clearCookie('connect.sid', {
			httpOnly: true,
			sameSite: 'lax',
			secure: false
		})
	}

	next()
})

module.exports = app
