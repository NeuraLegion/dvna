var express = require('express')
var helmet = require('helmet')
var path = require('path')

var app = express()

// Defense-in-depth: ensure clickjacking protection on every response,
// including any routes that may bypass the app router.
app.use(function (req, res, next) {
    if (!res.getHeader('X-Frame-Options')) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    }
    next()
})

app.use(helmet())

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

module.exports = app
