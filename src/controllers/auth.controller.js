'use strict'

const User = require('../models/user.model')
const jwt = require('jsonwebtoken')
const config = require('../config')
const httpStatus = require('http-status')
const fs = require('fs')

exports.register = async (req, res, next) => {
  try {
    const user = new User(req.body)
    if (req.body.avatar) {
      user.avatar.data = fs.readFileSync(req.body.avatar)
      user.avatar.contentType = 'image/png'
    }
    const savedUser = await user.save()
    res.status(httpStatus.CREATED)
    res.send(savedUser.transform())
  } catch (error) {
    return next(User.checkDuplicateEmailError(error))
  }
}

exports.login = async (req, res, next) => {
  try {
    const user = await User.findAndGenerateToken(req.body)
    const payload = {sub: user.id}
    const token = jwt.sign(payload, config.secret)
    return res.json({ message: 'OK', token: token })
  } catch (error) {
    next(error)
  }
}
