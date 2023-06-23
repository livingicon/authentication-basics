// app.js

require('dotenv').config();
const bcrypt = require('bcryptjs'); // sanitize passwords
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const mongoDb = process.env.DB_CONN;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

// passport authentication functions
// 1. below used when we use the passport.authenticate() function
passport.use(
  new LocalStrategy(async(username, password, done) => { // takes a username/password
    try {
      const user = await User.findOne({ username: username }); // tries to find the user in the db
      if (!user) { // if no user match
        return done(null, false, { message: "Incorrect username" });
      };
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user)
        } else {
          // passwords do not match!
          return done(null, false, { message: "Incorrect password" })
        }
      })
    } catch(err) {
      return done(err);
    };
  })
);
// These both create a cookie stored in the user's browser that makes sure
// the user is logged in and stays logged in as they move around the app
// they just check to see that the data we need is in the db
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch(err) {
    done(err);
  };
});

// INITIALIZE
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize()); // initializes/instantiates passport
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
// gives me access to the currentUser variable anywhere in the app
// won't have to manually pass it to all the controllers that need it
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

// ROUTES
app.get("/", (req, res) => {
  // send the user object to the view like this:
  res.render("index", { user: req.user });
});
// logout
app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

// RENDER VIEWS
// this creates the user from the sign-up form above
app.post("/sign-up", async (req, res, next) => {
  try {
    // uses bcryptjs.hash to sanitize password
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      const user = new User({ // creates user
        username: req.body.username,
        password: hashedPassword // sanitized password
      });
      const result = await user.save(); // once sanitized user created, saved to db
      res.redirect("/"); // and redirected back to homepage
    });
  } catch {
    return next(err);
  }
});
// when our homepage form is entered the passport.authenticate() is called
// it runs the passport.use() to check if in the database
// then it runs the serialize/deserialize for the session cookie
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);

app.listen(3000, () => console.log("app listening on port 3000!"));