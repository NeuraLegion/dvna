var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var nunjucks = require('nunjucks')
var helmet = require('helmet')
var serverConfig = require('./config/server')

var app = express()

app.set('trust proxy', serverConfig.session.proxy ? 1 : 0)
app.set('env', process.env.NODE_ENV || 'development')

app.use(helmet())
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(session({
    secret: serverConfig.session.secret,
    resave: serverConfig.session.resave,
    saveUninitialized: serverConfig.session.saveUninitialized,
    proxy: serverConfig.session.proxy,
    cookie: serverConfig.session.cookie
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

module.exports = app
