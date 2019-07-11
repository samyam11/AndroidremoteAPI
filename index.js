/*
Restful services by NodeJS
author: SamyamDhakal
*/

var crypto = require('crypto');
var uuid = require('uuid');
var express = require('express');
var mysql = require('mysql');
var bodyParser = require('body-parser');


//connect to Mysql

var con = mysql.createConnection ({
     host:'localhost',
     user:'root',
     password:'',
     database:'remote'
});




//password util
var genRandomString= function(length){
  return crypto.randomBytes(Math.ceil(length/2))
  .toString('hex') /*convert to hexa format */
  .slice(0,length); /*return required number of character */
};


var sha512 = function(user_password,salt){
  var hash = crypto.createHmac('sha512', salt); //use sha512
  hash.update(user_password);
  var value = hash.digest('hex');
  return {
    salt:salt,
    passwordHash:value
  };

 };

function saltHashPassword(userPassword){
  var salt = genRandomString(16); // generate random string
  var passwordData = sha512(userPassword,salt);
  return passwordData;
}

function checkHashPassword(userPassword,salt){
  var passwordData = sha512(userPassword,salt);
  return passwordData;
}







var app=express();
app.use(bodyParser.json());//accept json params
app.use(bodyParser.urlencoded({extended: true}));

 
app.post('/register/',(req,res,next)=>{

  var post_data = req.body;
  var uid = uuid.v4();
  var plaint_password = post_data.password;
  var hash_data = saltHashPassword(plaint_password);
  var password = hash_data.passwordHash;
  var salt = hash_data.salt;

  var name = post_data.name;
  var email = post_data.email;

  con.query('SELECT * FROM user where email=?',[email],function(err,result,fields){
           con.on('error',function(err){
           console.log('[MySQL ERROR]', err);
           });

           if(result && result.length)
    res.json('User already exists!!');
  else{

    con.query('INSERT INTO `user`(`unique_id`, `name`, `email`, `encrypted_password`, `salt`, `created_at`, `updated_at`)' + 
      'VALUES (?,?,?,?,?,NOW(),NOW())',[uid,name,email,password,salt],function(err,result,fields){
          con.on('error',function(err){
           console.log('[MySQL ERROR]', err);
           res.json('Register error:',err);
           });
          res.json('Register Successful');
      })

  }
  });

})


app.post('/login/',(req,res,next)=>{

  var post_data = req.body;
  var user_password = post_data.password;
  var email = post_data.email;

  con.query('SELECT * FROM user where email=?',[email],function(err,result,fields){
           con.on('error',function(err){
           console.log('[MySQL ERROR]', err);
           });

           if(result && result.length){
        var salt = result[0].salt; // get salt of result if account exists
        var encrypted_password = result[0].encrypted_password;
        var hashed_password = checkHashPassword(user_password,salt).passwordHash;
            if (encrypted_password == hashed_password)
              res.end(JSON.stringify(result[0])) // if password is true, return all info 

            else
              res.end(JSON.stringify('Wrong password'));
    }
  else{

    res.json("User not exists!!!");

  }
  });

  

})


// app.get("/",(req,res,next)=> {
//     console.log('Password: 123456');
//  var encrypt = saltHashPassword("123456");
//  console.log('Encrypt: '+encrypt.passwordHash);
//  console.log('Salt: '+encrypt.salt);
// })

// start server
app.listen(3000,()=> {
  console.log('restful running on port 3000');
});