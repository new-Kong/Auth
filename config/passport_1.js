//jshint esversion:6

const passport = require("passport");
const bcrypt = require("bcrypt");
const localStrategy = require("passport-local").Strategy;
const User = require("../models/user.js");


//session can only save 1 identity of user eg. user-id, user-email, user-fullname, so use passport.serializeUser to save into session
passport.serializeUser((user,done) => {
  done(null,user.id);
});

//Go into User model and retrieve user info
passport.deserializeUser((id,done) => {
    User.findById(id, (err, user) => {
      done(err,user);
    });
});

//login

passport.use("local.login", new localStrategy({
  usernameField:"email",  // if username used to authenticate, then type username instead of email
  passwordField:"password",
  passReqToCallback:true  //pass all info in this session into a callback (req,email,password,done)
}, (req,email,password,done) =>{
  User.findOne({"email":email},(err,user) => {  //to find databse whether the email is existed or not

    if(!user){
      return done(null, false, {message:"That email is not registered, please kindly sign up!"});

    }
try{
      bcrypt.compare(password,user.password, (err,result) => {

        if (result == true) {
         return done(null, user);
        } else {
         return done(null, false, {message:"Password is incorrect, please try again"});

        }

      });

    }catch(e){
      return done(e);
    }

  });
}));
