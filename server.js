var express = require('express')
var session = require('express-session')
var passport = require('passport')
var path = require('path')
var flash = require('connect-flash')

var app = express()

app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET || 'change_this_session_secret',
	resave: false,
	saveUninitialized: false,
	proxy: true,
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

app.use('/', require('./routes/main')(passport))

module.exports = app
