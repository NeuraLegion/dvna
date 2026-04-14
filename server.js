var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')
var helmet = require('helmet')

var app = express()

app.use(helmet())
app.use(helmet.hsts({
	maxAge: 31536000,
	includeSubDomains: true,
	preload: true
}))

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
	secret: 'dvna-secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: true
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

module.exports = app
