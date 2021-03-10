const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
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


app.post('/login', (req, res) => {
    //요청된 이메일을 데이터베이스에서 있는지 찾는다.
    User.findOne({email : req.body.email}, (err, user) => {
        if(!user){
            return res.json({
                loginSuccess:false,
                message: "제공된 이메일에 해당하는 유저가 없습니다."
            })
        }
    })

    //요청된 이메일이 데이터 베이스에 있다면 비밀번호가 맞는 비밀번호 인지 확인.

    //비밀번호 까지 맞다면 토큰을 생성하기
})


const User=mongoose.model('User', userSchema)
module.exports={User}
