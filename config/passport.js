const User = require('../models/user')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt

//up above is expect this syntax Authorization Bearer <token> that we pass in postman

const options = {
  jwtFromRequest:ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey:'secretkey'
}

const jwtStra = new jwtStrategy(options,(test,done)=>{
  User.findOne({_id:test._id})
  .then((user)=>{
    if(user){ 
      return done(null,user)
    }
    else{
      return done(null,false)
    }
  }).catch(err=>done(err,null))
});


//local strategy
const local = new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    session:false
},
    function(username, password, done){
        User.findOne({email:username},function (err,user){
            if(err) { return done(err); }
            if(!user) {return done(null,false,{message:'Incorrect email.'})}
            if(!user.comparePassword(password))
            {
                return done(null, false, { message: 'Incorrect password.' });
            }
            
            return done(null,user)
        })
    }
)
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
   
passport.deserializeUser(function(id, done) {
    User.findById(id, function (err, user) {
      done(err, user);
    });
  });

module.exports = (passport)=>{
  // passport.use(local)
  passport.use(jwtStra)
}