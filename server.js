var express = require('express')
var session = require('express-session')
var path = require('path')
var app = express()

app.set('trust proxy', 1)

// Security headers must be applied globally so every response path includes them.
// HSTS should only be sent when the request is served over HTTPS.
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')

    var isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https'
    if (isSecure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
})

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// existing middleware / route setup continues below
module.exports = app