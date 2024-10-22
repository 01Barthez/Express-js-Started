import usersControllers from '@src/controllers/users-controllers';
import authUser from '@src/middleware/authUser';
// import upload from "@src/middleware/upload-file";
import { validate, validator } from '@src/services/validator/validator';
import ROUTES from '@src/utils/mocks/mocks-routes';
import { Router } from 'express';

const user: Router = Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - name
 *         - email
 *         - password
 *       properties:
 *         name:
 *           type: string
 *           description: name of user
 *         email:
 *           type: string
 *           description: email of user
 *         password:
 *           type: string
 *           description: password of user
 * 
 *    UserConnexion: 
 *      type: objet
 *      required: 
 *        - email
 *        - password
 *      properties:
 *        email: 
 *          type: string
 *          description: email of user
 *          exemple: exemple@gmail.com
 *        password: 
 *          type: string
 *          description: "password of user"
 *
 *
 *
 *
 * 
*/


//? Inscription of new user
/**
 * @swagger
 * /signup
 * post:
 *   summary: "Signup user"
 *   description: "Enter information to sign user"
 *   tags: [Users]
 *   requestBody:
 *     required: true
 *     content:
 *       application/json
 *       schema:
 *         #ref: #/compoments/schema/User
 *   responses:
 *     201:
 *       description: "registration completed !"
 *     400:
 *       description: "Error when creating new user !"
 */
user.post(
    ROUTES.USER.INSCRIPTION,
    validator.validateUser,
    validate,
    // upload.single('image'),
    usersControllers.inscription
);

//? Connexion of user
/**
 * @swagger
 * /login
 * post:
 *   summary: "Login user"
 *   description: "Enter information to login user"
 *   tags: [Users]
 *   requestBody:
 *     required: true
 *     content:
 *       application/json
 *       schema:
 *         #ref: #/compoments/schema/User
 *   responses:
 *     201:
 *       description: "registration completed !"
 *     400:
 *       description: "Error when creating new user !"
 */
user.post(
    ROUTES.USER.CONNEXION,
    validator.validateEmail,
    validate,
    usersControllers.connexion
);

//? Deconnexion of user

user.post(
    ROUTES.USER.DECONNEXION,
    authUser,
    usersControllers.deconnexion
);

//? consultation of user
/**
 * @swagger
 * /profile/{userID}
 * get:
 *   summary: 'Get user By ID'
 *   description: 'Get user passing his ID'
 *   tags: [Users]
 *   responses:
 *     200:
 *       description: "List of user"
 *       content:
 *         application/json:
 *           schema:
 *             type: array
 *             items:
 *               $ref: '#/compoments/schemas/User
 *     400:
 *       description: "User not found"
 */
user.get(
    ROUTES.USER.GET_USER,
    usersControllers.consultuser
);

//? update user
/**
 * @swagger
 * /profile
 * put:
 *     summary: "update the user profile"
 *     description: "Update the user profile"
 *     responses:
 *         200:
 *             description: "User update"
 *
 *
 *
 */
user.put(
    ROUTES.USER.UPDATE_USER,
    authUser,
    // validator.validateUser,
    // validate,
    // upload.single('image'),
    usersControllers.updateUserData
);

//? Delete user
user.delete(
    ROUTES.USER.DELETE_USER,
    authUser,
    usersControllers.deleteUser
);

//? changepassword
user.put(
    ROUTES.USER.CHANGE_PASSSWORD,
    authUser,
    validator.validatePWDs,
    validate,
    usersControllers.changePassword
);

//? reset password
user.put(
    ROUTES.USER.RESET_PASSSWORD,
    validator.validatenewPWD,
    validate,
    usersControllers.resetPassword
);

//? verifyOTP
user.put(
    ROUTES.USER.VERIFY_OTP,
    validator.validateOTP,
    validate,
    usersControllers.verifyOtp
);

//? resendOTP
user.get(
    ROUTES.USER.RESEND_OTP,
    validator.validateEmail,
    validate,
    usersControllers.resendOTP
);

export default user;
