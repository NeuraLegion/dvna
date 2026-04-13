var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var config = require('./config/server')

var routes = require('./routes/main')
var authHandler = require('./core/authHandler')

var app = express()

app.set('trust proxy', 1)
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(session({
	secret: process.env.SESSION_SECRET || 'change_this_session_secret',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: config.cookieSecure === true
	}
}))

app.use(flash())
app.use(express.static(path.join(__dirname, 'public')))
app.use('/', routes(require('passport')))

module.exports = app
