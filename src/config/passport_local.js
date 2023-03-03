const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user_model');

module.exports = function (passport) {
  const options = {
    usernameField: 'email',
    passwordField: 'sifre',
  };

  passport.use(
    new LocalStrategy(options, async (email, sifre, done) => {
      try {
        const _bulunanUser = await User.findOne({ email: email });

        if (!_bulunanUser) {
          return done(null, false, { message: 'User bulunamadı' });
        }
        if (_bulunanUser.sifre !== sifre) {
          return done(null, false, { message: 'Şifre hatalı' });
        } else {
          return done(null, _bulunanUser);
        }
      } catch (error) {
        return done(error);
      }
    })
  );

  passport.serializeUser(function (user, done) {
    console.log('sessiona kaydedildi' + user.id);
    done(null, user.id);
  });

  passport.deserializeUser(function (id, done) {
    // console.log('sessiona kaydedilen id veritabanında arandı ve bulundu');
    User.findById(id, function (err, user) {
      const yeniUser = {
        id: user.id,
        email: user.email,
        ad: user.ad,
        soyad: user.soyad,
      };
      done(err, yeniUser); //komple user ı göndersek şifreleri falanda geliyor. bu şekilde istediğimiz alanları gönderebiliriz
    });
  });
};
