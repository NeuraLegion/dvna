var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var passport = require('passport')
var flash = require('connect-flash')
var session = require('express-session')
var helmet = require('helmet')

var routes = require('./routes/main')

var app = express()

// Trust reverse proxy headers so req.secure reflects the original HTTPS request
app.set('trust proxy', 1)

// Set HSTS globally for all HTTPS responses
app.use(function (req, res, next) {
	if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}
	next()
})

app.use(helmet())
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: 'keyboard cat',
	resave: false,
	secure: false,
	saveUninitialized: true
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', routes(passport))

module.exports = app
