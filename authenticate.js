var passport = require("passport");
var LocalStrategy = require("passport-local").Strategy;
var User = require("./models/user");

var JwtStrategy = require("passport-jwt").Strategy;
var ExtractJwt = require("passport-jwt").ExtractJwt;
var jwt = require("jsonwebtoken"); // used to create, sign, and verify tokens
var FacebookTokenStrategy = require("passport-facebook-token");
var config = require("./config.js");

passport.use(new LocalStrategy(User.authenticate()));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function (user) {
  return jwt.sign(user, config.secretKey, { expiresIn: 3600 });
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const user = await User.findById(jwt_payload._id);
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);

exports.facebookPassport = passport.use(
  new FacebookTokenStrategy(
    {
      clientID: config.facebook.clientId,
      clientSecret: config.facebook.clientSecret,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const existingUser = await User.findOne({ facebookId: profile.id });
        if (existingUser) {
          return done(null, existingUser);
        }

        const newUser = new User({
          username: profile.displayName,
          facebookId: profile.id,
          firstname: profile.name.givenName,
          lastname: profile.name.familyName,
        });

        try {
          const savedUser = await newUser.save();
          return done(null, savedUser);
        } catch (err) {
          return done(err, false);
        }
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

exports.verifyUser = passport.authenticate("jwt", { session: false });
