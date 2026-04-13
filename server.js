var express = require('express')
var app = express()
var path = require('path')
var favicon = require('serve-favicon')
var flash = require('connect-flash')
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var passport = require('passport')
var MongoStore = require('connect-mongo')(session)

var config = require('./config/config')
var dbConfig = config.db

require('./config/passport')(passport)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'img', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: config.session.secret,
	resave: false,
	saveUninitialized: false,
	store: new MongoStore({
		host: dbConfig.host,
		port: dbConfig.port,
		db: dbConfig.database,
		autoReconnect: true
	})
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	next()
})

app.use('/', require('./routes/main')(passport))

app.use(function (req, res, next) {
	res.status(404).render('404')
})

module.exports = app
