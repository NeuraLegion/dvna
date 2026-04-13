var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var fileUpload = require('express-fileupload')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var helmet = require('helmet')

var index = require('./routes/index')
var appRoutes = require('./routes/app')
var authRoutes = require('./routes/auth')
var learnRoutes = require('./routes/learn')
var apiRoutes = require('./routes/api')
var serverConfig = require('./config/server')

var app = express()

app.use(helmet())
app.use(helmet.noSniff())
app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(fileUpload())
app.use(session({
	secret: serverConfig.sessionSecret,
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static(path.join(__dirname, 'public')))

app.use('/', index())
app.use('/app', appRoutes())
app.use('/auth', authRoutes())
app.use('/learn', learnRoutes())
app.use('/api', apiRoutes())

module.exports = app
