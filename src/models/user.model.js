'use strict'
const mongoose = require('mongoose')
const bcrypt = require('bcrypt-nodejs')
const httpStatus = require('http-status')
const APIError = require('../utils/APIError')
const Schema = mongoose.Schema

const roles = [
  'user', 'admin'
]

const userSchema = new Schema({
  email: {type: String, required: true, unique: true, lowercase: true},
  username: {type: String, required: true, unique: true, lowercase: true, minlength: 6, maxlength: 64},
  password: {type: String, required: true, minlength: 4, maxlength: 128},
  name: {type: String, required: true, maxlength: 64},
  gender: {type: String, default: 'Others', enum: ['Male', 'Female', 'Others']},
  avatar: {data: Buffer, contentType: String},
  follow: [{type: Schema.Types.ObjectId, ref: 'Business'}],
  review: [{type: Schema.Types.ObjectId, refPath: 'Review'}],
  onModel: {type: String, enum: ['BlogPost', 'Product']},
  following: [{type: Schema.Types.ObjectId, ref: 'User'}],
  followers: [{type: Schema.Types.ObjectId, ref: 'User'}],
  role: {type: String, default: 'user', enum: roles}
}, {
  timestamps: true
})

userSchema.pre('save', async function save (next) {
  try {
    if (!this.isModified('password')) {
      return next()
    }

    this.password = bcrypt.hashSync(this.password)

    return next()
  } catch (error) {
    return next(error)
  }
})

userSchema.method({
  transform () {
    const transformed = {}
    const fields = ['id', 'name', 'email', 'createdAt', 'role']

    fields.forEach((field) => {
      transformed[field] = this[field]
    })

    return transformed
  },

  passwordMatches (password) {
    return bcrypt.compareSync(password, this.password)
  }
})

userSchema.statics = {
  roles,

  checkDuplicateEmailError (err) {
    if (err.code === 11000) {
      var error = new Error('Email already taken')
      error.errors = [{
        field: 'email',
        location: 'body',
        messages: ['Email already taken']
      }]
      error.status = httpStatus.CONFLICT
      return error
    }

    return err
  },

  async findAndGenerateToken (payload) {
    const { email, password } = payload
    if (!email) throw new APIError('Email must be provided for login')

    const user = await this.findOne({ email }).exec()
    if (!user) throw new APIError(`No user associated with ${email}`, httpStatus.NOT_FOUND)

    const passwordOK = await user.passwordMatches(password)

    if (!passwordOK) throw new APIError(`Password mismatch`, httpStatus.UNAUTHORIZED)

    return user
  }
}

module.exports = mongoose.model('User', userSchema)
