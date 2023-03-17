const { validationResult } = require('express-validator');
const passport = require('passport');
const User = require('../models/user_model');
require('../config/passport_local')(passport);
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { urlencoded } = require('express');

const loginFormunuGoster = (req, res, next) => {
  res.render('login', { layout: './layout/auth_layout', title: 'Giriş Yap' });
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
  res.render('register', { layout: './layout/auth_layout', title: 'Kayıt Ol' });
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

      if (_user && _user.emailAktif == true) {
        req.flash('validation_error', [{ msg: 'Bu mail kullanımda' }]);
        req.flash('email', req.body.email);
        req.flash('ad', req.body.ad);
        req.flash('soyad', req.body.soyad);
        req.flash('sifre', req.body.sifre);
        req.flash('resifre', req.body.resifre);
        res.redirect('/register');
      } else if ((_user && _user.emailAktif == false) || _user == null) {
        if (_user) {
          await User.findByIdAndRemove({ _id: _user._id });
        }

        const newUser = new User({
          ad: req.body.ad,
          soyad: req.body.soyad,
          email: req.body.email,
          sifre: await bcrypt.hash(req.body.sifre, 10),
        });

        await newUser.save();
        console.log('Kullanıcı kaydedildi');

        // jwt işlemleri
        const jwtBilgileri = {
          id: newUser.id,
          mail: newUser.email,
        };

        const jwtToken = jwt.sign(jwtBilgileri, process.env.CONFIRM_MAIL_JWT_SECRET, {
          expiresIn: '1d',
        });
        console.log(jwtToken);

        //mail gonderme islemleri
        const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;
        console.log('gidilecek url : ' + url);
        let transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_APP_SIFRE,
          },
        });

        await transporter.sendMail(
          {
            from: 'Nodejs Uygulaması <info@nodejskursu.com',
            to: newUser.email,

            subject: 'Email Onaylama',

            text: 'Emailinizi onaylamak için lütfen şu linki tıklayın: ' + url,
          },
          (error, info) => {
            if (error) {
              console.log(error);
            }
            console.log('Mail gonderildi');
            console.log(info);
            transporter.close();
          }
        );
        req.flash('success_message', [{ msg: 'Lütfen mail kutunuzu kontrol edin' }]);
        res.redirect('/login');
      }
    } catch (error) {}
  }
};

const forgotPasswordFormunuGoster = (req, res, next) => {
  res.render('forgot_password', {
    layout: './layout/auth_layout',
    title: 'Şifremi Unuttum',
  });
};
const forgotPassword = async (req, res, next) => {
  const hatalar = validationResult(req);

  if (!hatalar.isEmpty()) {
    req.flash('validation_error', hatalar.array());
    req.flash('email', req.body.email);

    res.redirect('/forgot-password');
  }
  // aşağıdaki else çalışıyorsa kullanıcı düzgün bir mail girmiştir
  else {
    try {
      const _user = await User.findOne({
        email: req.body.email,
        emailAktif: true,
      });

      if (_user) {
        //kullanıcıya şifre sıfırlama maili atılabilir
        const jwtBilgileri = {
          id: _user._id,
          mail: _user.mail,
        };
        const secret = process.env.RESET_PASSWORD_SECRET + '-' + _user.sifre;

        const jwtToken = jwt.sign(jwtBilgileri, secret, {
          expiresIn: '1d',
        });

        const url = process.env.WEB_SITE_URL + 'reset-password/' + _user._id + '/' + jwtToken;

        let transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_APP_SIFRE,
          },
        });

        await transporter.sendMail(
          {
            from: 'Nodejs Uygulaması <info@nodejskursu.com',
            to: _user.email,

            subject: 'Şifre Güncelleme',
            text: 'Şifrenizi güncellemek için lütfen şu linki tıklayın: ' + url,
          },
          (error, info) => {
            if (error) {
              console.log(error);
            }
            console.log('Mail gonderildi');
            console.log(info);
            transporter.close();
          }
        );
        req.flash('success_message', [{ msg: 'Lütfen mail kutunuzu kontrol edin' }]);
        res.redirect('/login');
      } else {
        req.flash('validation_error', [{ msg: 'Bu mail kayıtlı değil veya kullanıcı pasif' }]);
        req.flash('email', req.body.email);
        res.redirect('forgot-password');
      }

      // jwt işlemleri

      //mail gonderme islemleri
    } catch {}
  }

  //res.render('forgot_password', { layout: './layout/auth_layout' });
};

const logout = (req, res, next) => {
  req.logout();
  req.session.destroy((error) => {
    res.clearCookie('connect.sid');
    //req.flash('success_message', [{ msg: 'Başarıyla çıkış yapıldı' }]);  // bunun yerine render kullanıyorum çünkü bu session a ihtiyaç
    //duyuyor ama ben yukarda session u siliyorum. o yüzden altta render res.render kullanacağız
    res.render('login', {
      layout: './layout/auth_layout.ejs',
      title: 'Giriş Yap',
      succes_message: [{ msg: 'Başarıyla çıkış yapıldı' }],
    });
    // res.redirect('/login');
  });
};
const verifyMail = (req, res, next) => {
  const token = req.query.id;
  if (token) {
    try {
      jwt.verify(token, process.env.CONFIRM_MAIL_JWT_SECRET, async (e, decoded) => {
        if (e) {
          req.flash('error', 'Kod hatalı ve ya süresi geçmiş');
          res.redirect('/login');
        } else {
          const tokenınIcındekiIDDegeri = decoded.id;
          const sonuc = await User.findByIdAndUpdate(tokenınIcındekiIDDegeri, { emailAktif: true });

          if (sonuc) {
            req.flash('success_message', [{ msg: 'Başarıyla mail onaylandı' }]);
            res.redirect('/login');
          } else {
            req.flash('error', 'Lütfen tekrar kullanıcı oluşturun');
            res.redirect('/login');
          }
        }
      });
    } catch (error) {}
  } else {
    req.flash('error', 'Token yok veya geçersiz');
    res.redirect('/login');
  }
};
const yeniSifreyiKaydet = async (req, res, next) => {
  const hatalar = validationResult(req);
  if (!hatalar.isEmpty()) {
    req.flash('validation_error', hatalar.array());
    req.flash('email', req.body.sifre);
    req.flash('email', req.body.resifre);

    console.log('formdan gelen değerler');
    console.log(req.body);

    res.redirect('/reset-password/' + req.body.id + '/' + req.body.token);
  } else {
    const _bulunanUser = await User.findOne({
      _id: req.body.id,
      emailAktif: true,
    });

    const secret = process.env.RESET_PASSWORD_SECRET + '-' + _bulunanUser.sifre;
    try {
      jwt.verify(req.body.token, secret, async (e, decoded) => {
        if (e) {
          req.flash('error', 'Kod hatalı ve ya süresi geçmiş');
          res.redirect('/forgot-password');
        } else {
          const hashedPassword = await bcrypt.hash(req.body.sifre, 10);
          const sonuc = await User.findByIdAndUpdate(req.body.id, {
            sifre: hashedPassword,
          });

          if (sonuc) {
            req.flash('success_message', [{ msg: 'Başarıyla şifre güncellendi' }]);
            res.redirect('/login');
          } else {
            req.flash('error', 'Lütfen tekrar şifre sıfırlama adımlarını yapın');
            res.redirect('/login');
          }
        }
      });
    } catch (error) {}
  }
};
const yeniSifreFormuGoster = async (req, res, next) => {
  const linktekiID = req.params.id;
  const linktekiToken = req.params.token;

  if (linktekiID && linktekiToken) {
    const _bulunanUser = await User.findOne({ _id: linktekiID });

    const secret = process.env.RESET_PASSWORD_SECRET + '-' + _bulunanUser.sifre;
    try {
      jwt.verify(linktekiToken, secret, async (e, decoded) => {
        if (e) {
          req.flash('error', 'Kod hatalı ve ya süresi geçmiş');
          res.redirect('/forgot-password');
        } else {
          res.render('new_password', {
            id: linktekiID,
            token: linktekiToken,
            layout: './layout/auth_layout.ejs',
            title: 'Şifre Güncelleme',
          });
          // const tokenınIcındekiIDDegeri = decoded.id;
          // const sonuc = await User.findByIdAndUpdate(tokenınIcındekiIDDegeri, {
          //   emailAktif: true,
          // });

          // if (sonuc) {
          //   req.flash('success_message', [{ msg: 'Başarıyla mail onaylandı' }]);
          //   res.redirect('/login');
          // } else {
          //   req.flash('error', 'Lütfen tekrar kullanıcı oluşturun');
          //   res.redirect('/login');
          // }
        }
      });
    } catch (error) {}
  } else {
    req.flash('validation_error', [{ msg: 'Lütfen maildeki linki tıklayın. Token bulunamadı.' }]);

    res.redirect('forgot-password');
  }
};
module.exports = {
  loginFormunuGoster,
  registerFormunuGoster,
  forgotPasswordFormunuGoster,
  register,
  login,
  forgotPassword,
  logout,
  verifyMail,
  yeniSifreFormuGoster,
  yeniSifreyiKaydet,
};
