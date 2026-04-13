var express = require('express')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var path = require('path')
var config = require('./config/server')

var app = express()

app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: config.cookieSecure === true,
		path: '/'
	}
}))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(function (req, res, next) {
	res.locals.secureCookies = config.cookieSecure === true
	next()
})

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
