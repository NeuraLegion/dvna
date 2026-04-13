var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('express-flash')
var passport = require('passport')
var routes = require('./routes/main')
var config = require('./config/server')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Anti-clickjacking protection for all responses
app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
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

app.use('/', routes(passport))

app.use(function (req, res, next) {
	res.status(404).send('404')
})

module.exports = app
