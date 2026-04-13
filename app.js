var express = require('express')
var app = express()

// Trust the first proxy so req.secure reflects the original client scheme
// when TLS is terminated upstream (load balancer / reverse proxy).
app.set('trust proxy', 1)

// Enforce security headers globally so every route, including /app/ping,
// returns HSTS when the app is served over HTTPS.
app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')

	if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}

	next()
})

module.exports = app
