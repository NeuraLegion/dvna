var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var helmet = require('helmet')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(helmet({
	hsts: {
		maxAge: 31536000,
		includeSubDomains: true,
		preload: false
	}
}))

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	if (req.secure || req.get('x-forwarded-proto') === 'https') {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}
	next()
})

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

module.exports = app
