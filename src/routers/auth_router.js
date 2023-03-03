const router = require('express').Router();
const authController = require('../controllers/auth_controller');
const validatorMiddleware = require('../middlewares/validation_middleware');
const authMiddleware = require('../middlewares/auth_middleware');

router.get(
  '/login',
  authMiddleware.oturumAcilmamis,
  authController.loginFormunuGoster
);
router.post(
  '/login',
  authMiddleware.oturumAcilmamis,
  validatorMiddleware.validateLogin(),
  authController.login
);

router.get(
  '/register',
  authMiddleware.oturumAcilmamis,
  authController.registerFormunuGoster
);
router.post(
  '/register',
  authMiddleware.oturumAcilmamis,
  validatorMiddleware.validateNewUser(),
  authController.register
);

router.get(
  '/forgot-password',
  authMiddleware.oturumAcilmamis,
  authController.forgotPasswordFormunuGoster
);
router.post(
  '/forgot-password',
  authMiddleware.oturumAcilmamis,
  authController.forgotPassword
);

router.get('/logout', authMiddleware.oturumAcilmis, authController.logout);

module.exports = router;
