var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var app = express()

// If the app is deployed behind a reverse proxy / load balancer, trust it so
// Express can correctly detect HTTPS and apply secure cookies.
app.set('trust proxy', 1)

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: true,
		httpOnly: true,
		sameSite: 'lax'
	}
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
