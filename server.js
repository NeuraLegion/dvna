var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')
var expressLayouts = require('express-ejs-layouts')
var helmet = require('helmet')

var app = express()

// Security headers
app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})
app.use(helmet.noSniff())

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))
app.use(expressLayouts)

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: 'dvna-secret',
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static(path.join(__dirname, 'public')))

app.use('/', require('./routes/main')(passport))

module.exports = app
