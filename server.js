var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var morgan = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var expressLayouts = require('express-ejs-layouts')

var app = express()
var isProduction = process.env.NODE_ENV === 'production'

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.set('trust proxy', isProduction)

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(morgan('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(expressLayouts)
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	proxy: isProduction,
	cookie: {
		secure: isProduction,
		httpOnly: true,
		sameSite: 'lax'
	}
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

require('./core/passport')(passport)
app.use('/', require('./routes/main')(passport))

app.use(function (req, res, next) {
	res.status(404).send('404')
})

module.exports = app
