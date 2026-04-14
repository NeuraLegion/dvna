var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var config = require('./config/server')
var routes = require('./routes/main')
var appRoutes = require('./routes/app')

var app = express()

app.set('port', config.port)
app.set('host', config.listen)
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(function (req, res, next) {
    if (req.method === 'OPTIONS') {
        return res.status(405).send('Method Not Allowed')
    }
    next()
})

app.use('/', routes(passport))
app.use('/app', appRoutes())

app.use(function (req, res, next) {
    var err = new Error('Not Found')
    err.status = 404
    next(err)
})

if (app.get('env') === 'development') {
    app.use(function (err, req, res, next) {
        res.status(err.status || 500)
        res.render('error', {
            message: err.message,
            error: err
        })
    })
}

app.use(function (err, req, res, next) {
    res.status(err.status || 500)
    res.render('error', {
        message: err.message,
        error: {}
    })
})

app.listen(app.get('port'), app.get('host'), function () {
    console.log('Server listening on ' + app.get('host') + ':' + app.get('port'))
})

module.exports = app
