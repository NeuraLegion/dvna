var express = require('express')
var path = require('path')
var fs = require('fs')
var flash = require('connect-flash')
var session = require('express-session')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var fileUpload = require('express-fileupload')
var csrf = require('csurf')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	if (!res.getHeader('Content-Security-Policy')) {
		res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; font-src 'self' data: https://maxcdn.bootstrapcdn.com")
	}
	next()
})

app.use(cookieParser())
app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production'
	}
}))
app.use(flash())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(fileUpload())

app.use(function (req, res, next) {
	res.locals.messages = req.flash()
	next()
})

app.use('/', require('./routes'))

module.exports = app
