const jwt = require('jsonwebtoken')
const config = require('../config')

module.exports = (req, res, next) => {
  const token = req.body.token || req.query.token || (req.headers.authorization.split(' ')[1])
  // decode token
  if (token) {
    // verifies secret and checks exp
    jwt.verify(token, config.get('jwtSecret'), function (err, decoded) {
      if (err) {
        return res.status(401).json({ "message": 'Unauthorized access.' });
      }
      req.decoded = decoded;
      next();
    });
  } else {
    // if there is no token
    // return an error
    return res.status(403).send({
      message: 'No token provided.'
    });
  }
}