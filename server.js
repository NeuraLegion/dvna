var express = require('express')
var app = express()
var config = require('./config/server')

// Ensure any cookies set by session/auth middleware are protected when the
// app is served over HTTPS. This is intentionally global so downstream
// middleware that relies on res.cookie/session inherits the secure default.
app.use(function (req, res, next) {
	var isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https'

	if (isHttps) {
		res.cookie = (function (origCookie) {
			return function (name, value, options) {
				options = options || {}
				if (options.secure === undefined) {
					options.secure = true
				}
				return origCookie.call(this, name, value, options)
			}
		})(res.cookie)
	}

	next()
})

module.exports = app
