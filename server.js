var express = require('express')
var app = express()
var path = require('path')
var corsOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
    return origin.trim()
}).filter(Boolean)

app.use(function (req, res, next) {
    var requestOrigin = req.headers.origin

    if (requestOrigin && corsOrigins.indexOf(requestOrigin) !== -1) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin)
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

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

module.exports = app
