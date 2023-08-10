require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRound = 10;
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

/////////////////////////////////SESSION PACKAGE AREA///////////////////////////////
app.use(session({
    secret: "Our little secret.",
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());
////////////////////////////////SESSION PACKAGE AREA ENDS HERE//////////////////////

mongoose.connect("mongodb://127.0.0.1:27017/userDB")
        .then(()=>console.log("MongoDB connected"))
        .catch((err=>console.log("MongoDB error",err)));

const userSchema = new mongoose.Schema( {
    email:String,
    password:String,
    googleId:String,
    secret:String
});
/////////////////////////local-mongoose-plugins///////////////
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
////////////////////////END///////////////////////////////////
// const secret =process.env.SECRET;
// userSchema.plugin(encrypt,{secret:secret, encryptedFields:["password"]});

const User = new mongoose.model("User", userSchema);
////////////////////////serializing and deserializing///////////////
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
//////////////////////////END/////////////////////////////////////
/////////////////////////Google-Auth/////////////////////////////
passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/google/secrets",
    passReqToCallback   : true,
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(request, accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
////////////////////////END////////////////////////////////////
app.get('/', (req,res)=>{
    res.render('home');
});
app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));
app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
       
}));
app.get('/login', (req,res)=>{
    res.render('login');
});

app.get('/register', (req,res)=>{
    res.render('register');
});

app.get("/secrets", (req,res)=>{
    User.find({"secret":{$ne:null}})
    .then(function (foundUsers) {
      res.render("secrets",{usersWithSecrets:foundUsers});
      })
    .catch(function (err) {
      console.log(err);
      })
});
app.get("/submit", (req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", (req,res)=>{
    const submittedSecret = req.body.secret;
User.findById(req.user.id)
.then(foundUser => {
    if (foundUser) {
      foundUser.secret = req.body.secret;
      return foundUser.save();
    }
    return null;
  })
  .then(() => {
    res.redirect("/secrets");
  })
  .catch(err => {
    console.log(err);
  });


});

app.get("/logout", (req,res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});
app.post('/register', (req,res)=>{
User.register({username:req.body.username}, req.body.password, function(err, user){
    if(err){
        console.log(err);
        res.redirect("/register");
    }else{
        passport.authenticate("local")(req,res, function(){
            res.redirect("/secrets");
        });
    }
});
 });


app.post("/login", (req,res)=>{
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });

    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(3000, ()=>{
    console.log("Server is running on port 3000")
});