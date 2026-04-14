var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('./config/passport')
var routes = require('./routes/main')
var serverConfig = require('./config/server')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.set('trust proxy', serverConfig.session && serverConfig.session.proxy ? 1 : false)

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session(serverConfig.session))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())
app.use('/', routes(passport))

module.exports = app
