var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')

var indexRouter = require('./routes/main')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())

app.set('trust proxy', 1)

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'lax'
	}
}))

app.use(express.static(path.join(__dirname, 'public')))
app.use('/', indexRouter())

module.exports = app
