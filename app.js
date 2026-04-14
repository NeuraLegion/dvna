var express = require('express')
var path = require('path')
var app = express()

app.use(function (req, res, next) {
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	next()
})

app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Referrer-Policy', 'same-origin')
	next()
})

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

module.exports = app
