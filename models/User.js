const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const { JsonWebTokenError } = require('jsonwebtoken');
const saltRounds=10

const userSchema=mongoose.Schema({

    name:{
        type:String,
        maxlength:50,
    },
    email:{
        type:String,
        trim:true,
        unique:1
    },
    password:{
        type:String,
        minlength:5
    },
    lastname:{
        type:String,
        maxlength:50
    },
    role:{
        type:Number,
        default:0
    },
    image:String,
    token:{
        type:String,
    },
    tokenExp:{
        type:Number
    }
})


userSchema.pre('save', function(next){
    //비밀버호 암호화
    var user=this;

    if(user.isModified('password')){
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if(err) return next(err)
            bcrypt.hash(user.password, salt, function(err, hash) {
                // Store hash in your password DB.
                if(err) return next(err)
                user.password=hash
                next()
            });
        });
    }else {
        next()
    }
})

userSchema.methods.comparePassword=function(plainPassword, cb){
    //plainPassword 123123 암호화된 
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err),
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken=function(cb){
    //jsonwebtoken이용해서 토큰 생성하기
    var user=this;
    var token=jwt.sign(user._id.toHexString(), 'secretToken')
    // user.id+'secretToken'=token

    user.token=token
    user.save(function(err, user){
        if(err) return cb(err)
        cb(null, user)
    })
}


const User=mongoose.model('User', userSchema)
module.exports={User}
