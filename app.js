var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var config = require('./config')
var pkg = require('./package.json')

var app = express()

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(function (req, res, next) {
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use(session({
	secret: config.sessionSecret,
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'lax'
	}
}))

app.locals.appName = pkg.name
app.locals.appVersion = pkg.version

module.exports = app
