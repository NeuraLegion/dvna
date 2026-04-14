var express = require('express')
var app = express()

function isTrustedOrigin(origin) {
    var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (value) {
        return value.trim()
    }).filter(Boolean)

    return allowedOrigins.indexOf(origin) !== -1
}

app.use(function (req, res, next) {
    var origin = req.headers.origin

    if (origin && isTrustedOrigin(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin)
        res.setHeader('Vary', 'Origin')
        res.setHeader('Access-Control-Allow-Credentials', 'true')
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    }

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204)
    }

    next()
})

module.exports = app
