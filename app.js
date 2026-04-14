var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var mainRoutes = require('./routes/main')(passport)
var serverConfig = require('./config/server')

var app = express()

app.set('trust proxy', true)

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session(serverConfig.session))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', mainRoutes)

module.exports = app
