var express = require('express')
var app = express()

app.set('trust proxy', true)

app.use(function (req, res, next) {
	if ((req.secure || req.headers['x-forwarded-proto'] === 'https') && !res.getHeader('Strict-Transport-Security')) {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}

	return next()
})

module.exports = app
