const express = require('express')
const path = require('path')
const logger = require('morgan')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const session = require('express-session')

const app = express()

// If the app is deployed behind a reverse proxy (for TLS termination), ensure Express
// can determine the original protocol so secure cookies are only set over HTTPS.
app.set('trust proxy', 1)

const sessionCookieConfig = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production'
}

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_session_secret',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: sessionCookieConfig
}))

// Enforce secure session cookies at the middleware layer for HTTPS requests.
// This avoids sending a session cookie without the Secure flag when the app is
// accessed directly over HTTP during testing, while keeping the cookie protected
// in production behind HTTPS.
app.use((req, res, next) => {
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    req.session.cookie.secure = true
  }
  next()
})

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
