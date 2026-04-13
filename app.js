var express = require('express')
var app = express()

var allowedOrigins = (process.env.CORS_ORIGIN || '')
	.split(',')
	.map(function (origin) {
		return origin.trim()
	})
	.filter(function (origin) {
		return origin.length > 0
	})

function isAllowedOrigin(origin) {
	if (!origin) {
		return false
	}

	return allowedOrigins.indexOf(origin) !== -1
}

app.use(function (req, res, next) {
	var origin = req.get('Origin')

	if (isAllowedOrigin(origin)) {
		res.setHeader('Access-Control-Allow-Origin', origin)
		res.setHeader('Vary', 'Origin')
		res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS')
		res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
		res.setHeader('Access-Control-Allow-Credentials', 'true')
	}

	if (req.method === 'OPTIONS') {
		return res.sendStatus(204)
	}

	next()
})

module.exports = app
