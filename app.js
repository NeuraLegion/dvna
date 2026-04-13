var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var helmet = require('helmet')

var routes = require('./routes/main')
var config = require('./config/server')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
	secret: config.sessionSecret,
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: config.cookieSecure === true
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com")

	if (config.cookieSecure === true) {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}

	next()
})

app.use('/', routes(passport))

app.use(function (req, res, next) {
	res.status(404).render('404')
})

module.exports = app
