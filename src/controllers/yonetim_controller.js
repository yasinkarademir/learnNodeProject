const User = require('../models/user_model');
const anaSayfayiGoster = function (req, res, next) {
  res.render('index', { layout: './layout/yonetim_layout', title: 'Yönetim Paneli Anasayfa' });
};
const profilSayfasiniGoster = function (req, res, next) {
  res.render('profil', { user: req.user, layout: './layout/yonetim_layout', title: 'Profil Sayfası' });
};
const profilGuncelle = async function (req, res, next) {
  const guncelBilgiler = {
    ad: req.body.ad,
    soyad: req.body.soyad,
  };

  try {
    if (req.file) {
      guncelBilgiler.avatar = req.file.filename;
    }
    const sonuc = await User.findByIdAndUpdate(req.user.id, guncelBilgiler);

    if (sonuc) {
      res.redirect('/yonetim/profil');
    }
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  anaSayfayiGoster,
  profilSayfasiniGoster,
  profilGuncelle,
};
