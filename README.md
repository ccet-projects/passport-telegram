# Как использовать

```js
const passport = require('passport');
const express = require('express');

const TelegramStrategy = require('passport-telegram').Strategy;

passport.use(new TelegramStrategy({ botToken: '...', passReqToCallback: true }, (req, data, done) => {
  req.user = {
    name: data.username,
    firstName: data.first_name,
    lastName: data.lastName,
    avatar: data.photo_url,
  };
  done(null, data);
}));

const app = express();

app.use('/login', passport.authenticate('telegram'), (req, res) => {
  res.send(`Вы вошли как ${req.user.firstName}`);
});
```