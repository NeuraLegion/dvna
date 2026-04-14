var express = require('express')
var path = require('path')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var isProduction = process.env.NODE_ENV === 'production'
var isHttps = function (req) {
	return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

var app = express()

app.set('trust proxy', 1)

app.use(function (req, res, next) {
	var requestIsHttps = isHttps(req)

	res.cookie = (function (origCookie) {
		return function (name, value, options) {
			options = options || {}
			if (options.secure === undefined) {
				options.secure = requestIsHttps || isProduction
			}
			return origCookie.call(this, name, value, options)
		}
	})(res.cookie)

	next()
})

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: true,
		httpOnly: true,
		sameSite: 'lax'
	}
}))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
