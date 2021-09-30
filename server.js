
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
  }
  const saltRounds=10
  const express = require('express')
  const app = express()
  const bcrypt = require('bcrypt')
  const passport = require('passport')
  const flash = require('express-flash')
  const session = require('express-session')
  const mysql = require("mysql")
  const dotenv = require('dotenv')
  const bodyParser=require('body-parser')
  
  dotenv.config({path:'./.env'});
  
  const initializePassport = require('./passport-config')
  initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
  )
  
// datbase connection
  const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database:'login-page',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  
  });
  
  db.connect ( (error) => {
    if(error){
      console.log(error)
    }else {
      console.log("my sql connected...")
    }
  })
  
 
  const users = []
  
  app.set('view-engine', 'ejs')
  app.use(express.urlencoded({ extended: true }))
  app.use(flash())
  app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  }))
  app.use(passport.initialize()) 
  app.use(passport.session())
  app.use('/public',express.static('public'));

  
  app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
  })
  app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
  })
  

  app.post("/register", (req, res) => {
    console.log(req.body);
    const email = req.body.email;
    const password = req.body.password;
  
    bcrypt.hash(password, saltRounds,(err, hash) => {
      if (err) {
        console.log(err);
      }
  
      db.query(
        "INSERT INTO users (email, password) VALUES (?,?)",
        [email, hash],
        (err, result) => {
          console.log(err);
        }
      );
    });
    res.redirect('/login');
  });

  app.get("/login.ejs", (req, res) => {
    console.log(req.body);
    if (req.session.user) {
      res.send({ loggedIn: true, user: req.session.user });
    } else {
      res.send({ loggedIn: false });
    }
  });
  
  app.post("/login.ejs", (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
  
    db.query(
      "SELECT * FROM users WHERE email = ?;",
      email,
      (err, result) => {
        if (err) {
          res.send({ err: err });
        }
  
        if (result.length > 0) {
          bcrypt.compare(password, result[0].password, (error, response) => {
            if (response) {
              req.session.user = result;
              console.log(req.session.user);
              res.send(result);
            } else {
              res.send({ message: "Wrong username/password combination!" });
            }
          });
        } else {
          res.send({ message: "User doesn't exist" });
        }
      } 
    );
  });
  app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
  })
  
  app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }))
  
  app.get('/password', checkNotAuthenticated, (req, res) => {
    res.render('password.ejs')
  })
  
  app.post('/password', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }))
  app.post('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
  })
  
  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next()
    }
  
    res.redirect('/login')
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect('/')
    }
    next()
  }
  
  app.listen(3000)