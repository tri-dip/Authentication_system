import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import { dirname } from "path";
import { fileURLToPath } from "url";
import env from "dotenv";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import { v4 as uuidv4 } from "uuid";
import nodemailer from "nodemailer";


env.config();
const app = express();
const saltRounds = parseInt(process.env.SALTROUNDS);
const __dirname = dirname(fileURLToPath(import.meta.url));


const db = new pg.Client({
  user: process.env.USER_NAME,
  host: process.env.HOST_NAME,
  database: process.env.DB_NAME,
  password: process.env.USER_PASS,
  port: process.env.DB_PORT
});
db.connect();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: process.env.SECRET_CODE,
  resave: false,
  saveUninitialized: false,
  cookie:{
    maxAge: 1000*60*60*24,
  }
}));
app.use(passport.initialize());
app.use(passport.session());



function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}


function sendVerificationEmail(email, token) {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  const link = `http://localhost:3000/verify?token=${token}`;
  const mailOptions = {
    from: `\"MyApp Team\" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Verify your email for MyApp",
    html: `<p>Verify your email: <a href="${link}">Click here</a></p>`
  };
  transporter.sendMail(mailOptions, (err) => {
    if (err) console.error("Email error:", err);
  });
}


function sendResetMail(email) {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  const link = `http://localhost:3000/setpass`;
  const mailOptions = {
    from: `\"MyApp Team\" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Set your password for MyApp",
    html: `<p>Set password: <a href="${link}">Click here</a></p>
          <p>Or login with <a href="/login">google</a></p>`
  };
  transporter.sendMail(mailOptions, (err) => {
    if (err) console.error("Email error:", err);
  });
}


function sendforgetpassmail(email, token) {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  const link = `http://localhost:3000/resetpass?token=${token}`;
  const mailOptions = {
    from: `\"MyApp Team\" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Reset your password",
    html: `<p>Enter a new password: <a href="${link}">Click here</a></p>`
  };
  transporter.sendMail(mailOptions, (err) => {
    if (err) console.error("Email error:", err);
  });
}


app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/html/main.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/html/login.html");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/home", ensureAuthenticated, (req, res) => {
  res.sendFile(__dirname + "/public/html/homepage.html");
});

app.get("/setpass", ensureAuthenticated, (req, res) => {
  if (req.user.password !== "google") return res.redirect("/login");
  res.sendFile(__dirname + "/public/html/setpass.html");
});

app.get("/auth/google/home", passport.authenticate("google", {
  successRedirect: "/home",
  failureRedirect: "/login",
}));

app.post("/register", async (req, res) => {
  const mail_id = req.body.email;
  const password = req.body.password;
  if (!mail_id || !password) return res.send(`<h2>Email and Password are required.</h2><a href="/">Go back</a>`);
  if (!password || password.length < 6) return res.send("Password must be at least 6 characters.");
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(mail_id)) return res.send(`<h2>Invalid email format.</h2><a href="/">Try again</a>`);

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const token = uuidv4();
  const expiry = new Date(Date.now() + 1000 * 60 * 60);

  await db.query("INSERT INTO users (mail_id, password, verified, verification_token, token_expires) VALUES ($1, $2, $3, $4, $5)",
    [mail_id, hashedPassword, false, token, expiry]);

  sendVerificationEmail(mail_id, token);
  res.send("Signup successful. Check your email to verify.");
});

app.get("/verify", async (req, res) => {
  const token = req.query.token;
  try {
    const result = await db.query("SELECT * FROM users WHERE verification_token = $1", [token]);
    if (result.rows.length === 0) return res.send("Invalid or expired token");

    const user = result.rows[0];
    if (user.verified) return res.send(`User already verified. <a href="/login">Login</a>`);
    if (new Date(user.token_expires) < new Date()) {
      await db.query("DELETE FROM users WHERE id = $1", [user.id]);
      return res.send(`Token expired. <a href="/register">Sign Up again</a>`);
    }

    await db.query("UPDATE users SET verified = true, verification_token = NULL, token_expires = NULL WHERE id = $1", [user.id]);
    const updatedUser = await db.query("SELECT * FROM users WHERE id = $1", [user.id]);

    req.login(updatedUser.rows[0], (err) => {
      if (err) return res.send("Verification succeeded but auto-login failed.");
      res.redirect("/home");
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal server error.");
  }
});

app.post("/setpass", async (req, res) => {
  const password = req.body.setpassword;
  if (!password || password.length < 6) return res.send("Password must be at least 6 characters.");
  try {
    const hashpass = await bcrypt.hash(password, saltRounds);
    await db.query("UPDATE users SET password = $1 WHERE id = $2", [hashpass, req.user.id]);
    res.sendFile(__dirname + "/public/html/login2.html");
  } catch (err) {
    console.log(err);
    res.send("Error in setting password");
  }
});

app.post("/login", (req, res, next) => {
  const {email,password} = req.body;
  if (!email || !password) return res.send(`<h2>Email and Password are required.</h2><a href="/login">Go back</a>`);
  if (!password || password.length < 6) return res.send("Password must be at least 6 characters.");
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      if (info && info.message === "User not found, Try Signing-Up") return res.redirect("/");
      return res.send(info.message)
    }
    req.login(user, (err) => {
      if (err) return res.send(err);
      return res.redirect("/home");
    });
  })(req, res, next);
});

passport.use("local", new Strategy(
  { usernameField: "email" },
  async (email, password, cb) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE mail_id = $1", [email]);
      if (result.rows.length === 0) return cb(null, false, { message: "User not found, Try Signing-Up" });

      const user = result.rows[0];
      if (user.password === "google"){
        sendResetMail(email);
        return cb(null, false, { message: "Use Google Sign-In for this account" });
      } 

      bcrypt.compare(password, user.password, (err, valid) => {
        if (err) return cb(err);
        if (valid) return cb(null, user);
        return cb(null, false, { message: "Invalid password" });
      });
    } catch (err) {
      return cb(err);
    }
  }
));

passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/home",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
  if (!profile._json.email_verified) return cb(null, false, { message: "Unverified Google account" });
  try {
    const result = await db.query("SELECT * FROM users WHERE mail_id = $1", [profile.email]);
    if (result.rows.length > 0) return cb(null, result.rows[0]);

    const newUser = await db.query(
      "INSERT INTO users (mail_id, password, verified) VALUES ($1, $2, $3) RETURNING *",
      [profile.email, process.env.DEFAULT_PASS, true]
    );
    sendResetMail(profile.email);
    return cb(null, newUser.rows[0]);
  } catch (err) {
    return cb(err);
  }
}));

app.get("/forgetpass",(req,res)=>{
  res.sendFile(__dirname + "/public/html/forgetpass.html");
})
app.post("/reset-pass",async (req,res)=>{
  const email = req.body.email;
  const token = uuidv4();
  const expires = new Date(Date.now() + 1000*60*60);

  const result = await db.query("SELECT * FROM users WHERE mail_id = $1",[email]);

  if(result.rows.length===0) return res.send("No user found");
  await db.query("UPDATE users SET reset_token = $1 , reset_token_expires = $2 WHERE mail_id = $3",[token,expires,email]);
  sendforgetpassmail(email,token);
  res.send("Password reset link send check your mail");
})
app.get("/resetpass",async (req,res)=>{
  const token = req.query.token;
  try{
    const result = await db.query("SELECT * FROM users WHERE reset_token=$1",[token]);
    const user = result.rows[0];
    const email = user.mail_id;
    if (new Date(user.reset_token_expires) < new Date()) {
      await db.query("UPDATE users SET reset_token = $1 , reset_token_expires = $2 WHERE mail_id = $3",["null","null",email]);
      return res.redirect("/");
    }
    return res.redirect(`/newpassword?token=${token}`);
  }
  catch(err){
    res.send(err);
  }
})
app.get("/newpassword",(req,res)=>{
  res.sendFile(__dirname + "/public/html/newpassword.html")
})
app.post("/newpass", async (req, res) => {
  const token = req.body.token;
  const newpassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE reset_token = $1", [token]);
    
    if (result.rows.length === 0) {
      return res.send("Invalid or expired token.");
    }

    const user = result.rows[0];
    const hashedPassword = await bcrypt.hash(newpassword, saltRounds);

    await db.query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2",
      [hashedPassword, user.id]
    );

    res.send("Password has been reset successfully. <a href='/login'>Login</a>");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});


passport.serializeUser((user, cb) => cb(null, user.id));

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

app.listen(3000, "0.0.0.0", () => {
  console.log("Server running on http://localhost:3000");
});
