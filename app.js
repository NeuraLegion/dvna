var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var helmet = require('helmet')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Ensure the header is set for every response, including redirects and rendered views.
app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

// Helmet's noSniff middleware remains as a defense-in-depth layer.
app.use(helmet.noSniff())

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: process.env.SESSION_SECRET || 'dvna-secret',
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static(path.join(__dirname, 'public')))
app.use('/', require('./routes/main')(passport))

module.exports = app
