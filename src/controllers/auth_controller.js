const { validationResult } = require('express-validator');
const passport = require('passport');
const User = require('../models/user_model');
require('../config/passport_local')(passport);

const loginFormunuGoster = (req, res, next) => {
  res.render('login', { layout: './layout/auth_layout' });
};

const login = (req, res, next) => {
  const hatalar = validationResult(req);

  req.flash('email', req.body.email);
  req.flash('sifre', req.body.sifre);

  if (!hatalar.isEmpty()) {
    req.flash('validation_error', hatalar.array());

    res.redirect('/login');
  } else {
    passport.authenticate('local', {
      successRedirect: '/yonetim',
      failureRedirect: '/login',
      failureFlash: true,
    })(req, res, next);
  }

  // res.render('login', { layout: './layout/auth_layout' });
};

const registerFormunuGoster = (req, res, next) => {
  res.render('register', { layout: './layout/auth_layout' });
};

const register = async (req, res, next) => {
  const hatalar = validationResult(req);

  if (!hatalar.isEmpty()) {
    req.flash('validation_error', hatalar.array());
    req.flash('email', req.body.email);
    req.flash('ad', req.body.ad);
    req.flash('soyad', req.body.soyad);
    req.flash('sifre', req.body.sifre);
    req.flash('resifre', req.body.resifre);
    res.redirect('/register');
  } else {
    try {
      const _user = await User.findOne({ email: req.body.email });

      if (_user) {
        req.flash('validation_error', [{ msg: 'Bu mail kullanımda' }]);
        req.flash('email', req.body.email);
        req.flash('ad', req.body.ad);
        req.flash('soyad', req.body.soyad);
        req.flash('sifre', req.body.sifre);
        req.flash('resifre', req.body.resifre);
        res.redirect('/register');
      } else {
        const newUser = new User({
          ad: req.body.ad,
          soyad: req.body.soyad,
          email: req.body.email,
          sifre: req.body.sifre,
        });

        await newUser.save();
        console.log('Kullanıcı kaydedildi');

        req.flash('success_message', [{ msg: 'Giriş yapabilirsiniz' }]);
        res.redirect('/login');
      }
    } catch (error) {}
  }
};

const forgotPasswordFormunuGoster = (req, res, next) => {
  res.render('forgot_password', {
    layout: './layout/auth_layout',
  });
};
const forgotPassword = (req, res, next) => {
  console.log(req.body);
  res.render('forgot_password', { layout: './layout/auth_layout' });
};

const logout = (req, res, next) => {
  req.logout();
  req.session.destroy((error) => {
    res.clearCookie('connect.sid');
    //req.flash('success_message', [{ msg: 'Başarıyla çıkış yapıldı' }]);  // bunun yerine render kullanıyorum çünkü bu session a ihtiyaç
    //duyuyor ama ben yukarda session u siliyorum. o yüzden altta render res.render kullanacağız
    res.render('login', {
      layout: './layout/auth_layout.ejs',
      succes_message: [{ msg: 'Başarıyla çıkış yapıldı' }],
    });
    // res.redirect('/login');
  });
};

module.exports = {
  loginFormunuGoster,
  registerFormunuGoster,
  forgotPasswordFormunuGoster,
  register,
  login,
  forgotPassword,
  logout,
};
