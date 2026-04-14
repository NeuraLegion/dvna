module.exports = function isHttpsRequest(req) {
    if (!req) {
        return false
    }

    if (req.secure) {
        return true
    }

    var forwardedProto = req.headers && req.headers['x-forwarded-proto']
    if (typeof forwardedProto === 'string' && forwardedProto.split(',')[0].trim().toLowerCase() === 'https') {
        return true
    }

    return false
}
