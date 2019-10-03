//jshint esversion:8

const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const {check, validationResult} = require("express-validator");

const app = express();

const User = require("./models/user.js");
 require("./config/passport_1.js");

app.set("view engine", "ejs");

app.use(express.urlencoded({extended:false}));
app.use(express.static("public"));
app.use(flash());
app.use(session({
  secret:"secret",
  resave:false,
  saveUninitialized:false

}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));


mongoose.connect("mongodb://localhost:27017/loginme", {useNewUrlParser:true}).
then(() => console.log("MongoDB Connected")).
catch(err => console.log(err));

// app.use(function(req, res, next){
//     res.locals.success_messages = req.flash('success_messages');
//     res.locals.error_messages = req.flash('error_messages');
//     next();
// });


app.route("/")

.get(checkAuthenticated,(req, res) => {
  res.render("index.ejs", {name:req.user.name, title:"Home Page"});
});

app.route("/login")

.get(checknotAuthenticated, (req, res) => {
  res.render("login.ejs", {title:"Login Page"});
})

.post(checknotAuthenticated, passport.authenticate("local.login",{
  successRedirect:"/",
  failureRedirect:"/login",
  failureFlash:true
}));

app.route("/register")

.get(checknotAuthenticated, async (req, res) => {
  res.render("register.ejs", {title:"Register Page"});
})

.post(checknotAuthenticated, [
  check("name").not().isEmpty().withMessage("Fullname is required!"),
  check("name").isLength({min:5}).withMessage( "Fullname must not be less than 5!"),
  check("email").not().isEmpty().withMessage("Email is required!"),
  check("email").isEmail().withMessage("Email is invalid!"),
  check("password").not().isEmpty().withMessage("Password is required"),
  check("password").isLength({min:5}).withMessage("Password must not be less than 5 characters"),
  check("password").matches('[0-9]').withMessage('Password must contain at least 1 number.'),
  check("password").matches('[a-z]').withMessage('Password must contain at least 1 lowercase letter.'),
  check("password").matches('[A-Z]').withMessage('Password must contain at least 1 uppercase letter.')
], async (req,res) => {

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
     res.status(422).json({ errors: errors.array() });
}else{
    try{

         const hashedPassword = await bcrypt.hash(req.body.password, 10);

             const newUser = new User({
             name: req.body.name,
             email: req.body.email,
             password: hashedPassword
           });

          newUser.save();
        return res.redirect("/login");
    }catch(err){
      return  res.redirect("/register");
    }
}
});

app.listen(3000, () => {
  console.log("Success on port 3000");
});


function checkAuthenticated(req,res,next){
   if(req.isAuthenticated()){
     return next();
   }else{
     return res.redirect("/login");
   }
}

function checknotAuthenticated(req,res,next){
   if(req.isAuthenticated()){
     return res.redirect("/");
   }else{
     return next();
   }
}

app.delete("/logout", (req, res) => {
  req.logOut();
  return res.redirect("/login");
});
