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

var index = require('./routes/index')
var main = require('./routes/main')
var user = require('./routes/user')
var api = require('./routes/api')

var app = express()

// Global security headers for all responses
app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

app.use(helmet({
	contentSecurityPolicy: false,
	noSniff: true
}))

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
	secret: 'dvanonsecret',
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use('/', index(passport))
app.use('/', main(passport))
app.use('/user', user(passport))
app.use('/api', api(passport))

module.exports = app
