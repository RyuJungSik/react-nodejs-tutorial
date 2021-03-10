const express = require("express");
const app = express();
const port=5000
const bodyParser=require('body-parser');
const {User}=require("./models/User");

const config=require('./config/key');

app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());

const mongoose=require('mongoose')
mongoose.connect(config.mongoURI, {
  userNewUrlParser:true, useUnifiedTopology:true, useCreateIndex:true, useFindAndModify:false
}).then(()=>console.log('mongodb connected...'))
.catch(err=>console.log(err))


app.get('/', (req, res)=>res.send('Hello World! @@@@@@@@'))

app.post('/register', (req, res)=>{
  //회원갑입할때 가조연 데이터를 client에서 가져오면 그것들을 데이터베이스에 넣어준다.
  const user=new User(req.body)
  user.save((err, userInfo)=>{
    if(err) return res.json({success:false, err})
    return res.status(200).json({
      success:true
    })
  })
})



app.listen(port, () => {
  console.log("listen on 8080");
});






