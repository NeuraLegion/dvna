var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var helmet = require('helmet')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: process.env.SESSION_SECRET || 'dvna-secret',
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(helmet.noSniff())
app.use(helmet.xssFilter())
app.use(helmet.hidePoweredBy())
app.use(helmet.frameguard({ action: 'sameorigin' }))
app.use(helmet.contentSecurityPolicy({
	directives: {
		defaultSrc: ["'self'"],
		scriptSrc: ["'self'", 'https://maxcdn.bootstrapcdn.com', 'https://cdnjs.cloudflare.com'],
		styleSrc: ["'self'", "'unsafe-inline'", 'https://maxcdn.bootstrapcdn.com'],
		imgSrc: ["'self'", 'data:'],
		fontSrc: ["'self'", 'https://maxcdn.bootstrapcdn.com'],
		objectSrc: ["'none'"],
		baseUri: ["'self'"],
		frameAncestors: ["'self'"]
	}
}))

app.use(function (req, res, next) {
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	next()
})

app.use(express.static(path.join(__dirname, 'public')))
app.use('/', require('./routes/main')(passport))

module.exports = app
