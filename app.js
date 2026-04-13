var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var serverConfig = require('./config/server')

var app = express()

// If the app is deployed behind a reverse proxy / load balancer, trust it so
// Express can correctly recognize HTTPS and still issue Secure cookies.
app.set('trust proxy', 1)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: 'dvanonsecret',
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

app.use(require('./routes/main')(passport))

module.exports = app
