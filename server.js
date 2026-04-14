var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var expressValidator = require('express-validator')

var app = express()

app.set('trust proxy', 1)

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(expressValidator())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: true,
		httpOnly: true,
		sameSite: 'lax'
	}
}))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', require('./routes/main')(passport))

module.exports = app
