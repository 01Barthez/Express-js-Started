import { envs } from "@src/core/config/env";
import log from "@src/core/config/logger";
import prisma from "@src/core/config/prismaClient";
import { HttpCode } from "@src/core/constant";
import { customRequest } from "@src/core/interfaces/interfaces";
import { comparePassword, hashText } from "@src/functions/crypt-password";
import generateSimpleOTP from "@src/functions/generate-otp";
import userToken from "@src/services/jwt/jwt-functions";
import sendMail from "@src/services/mail/sendMail/send-mail";
import exceptions from "@src/utils/errors/exceptions";
import { Request, Response } from "express";

const usersControllers = {
    // function for inscription of user
    inscription: async (req: Request, res: Response) => {
        try {
            // fetch data from body to create new user
            const { name, email, password } = req.body;
            if (!name || !email || !password) return exceptions.badRequest(res, "All fields are mandatory !");

            // Check if user ever exist
            const userAlreadyExist = await prisma.user.findUnique({ where: { email } })
            if (userAlreadyExist) return exceptions.conflict(res, "Email is ever used !");

            const hashPassword = await hashText(password);
            if (!hashPassword) return exceptions.badRequest(res, "error trying to crypt password !");

            const otp = generateSimpleOTP();
            const now = new Date();
            const expireOTP = new Date(now.getTime() + 10 * 60)

            const newUser = await prisma.user.create({
                data: {
                    name,
                    email,
                    password: hashPassword,
                    otp: {
                        code: otp,
                        expire_at: expireOTP
                    },
                }
            });
            if (!newUser) return exceptions.badRequest(res, "Error when creating new user !");

            sendMail(
                newUser.email, // Receiver Email
                'Welcome to blog *****', // Subjet
                'otp', // Template
                { // Template Data
                    date: now,
                    name: newUser.name,
                    otp: otp,
                }
            )

            // Return success message
            res
                .status(HttpCode.CREATED)
                .json({ msg: "registration completed !" })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // function for connexion of user
    connexion: async (req: Request, res: Response) => {
        try {
            // fetch data from body
            const { email, password } = req.body;

            // check if user exist
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) return exceptions.notFound(res, "user not exist !");

            // Check if it's correct password
            const isPassword = await comparePassword(password, user.password);
            if (!isPassword) return exceptions.unauthorized(res, "incorrect password !");

            // Save access token and refresh token
            user.password = "";

            const accessToken = userToken.accessToken(user);
            const refreshToken = userToken.refreshToken(user);

            res.setHeader('authorization', `Bearer ${accessToken}`);
            res.cookie(
                `refresh_key`,
                refreshToken,
                {
                    httpOnly: envs.JWT_COOKIE_HTTP_STATUS,
                    secure: envs.JWT_COOKIE_SECURITY,
                    maxAge: envs.JWT_COOKIE_DURATION
                }
            );

            // Return success message
            res
                .status(HttpCode.OK)
                .json({ msg: "user connected !" })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // function for deconnexion of user 
    deconnexion: async (req: customRequest, res: Response) => {
        try {
            // fetch employeID from authentication
            const userID = req.user?.user_id;
            if (!userID) return exceptions.unauthorized(res, "authentication error !");

            // Check if user user exist
            const user = await prisma.user.findUnique({ where: { user_id: userID } })
            if (!user) return exceptions.badRequest(res, "user not found !");

            // invalid access and refresh token
            res.setHeader('authorization', `Bearer `);
            res.clearCookie(
                `refresh_key`,
                {
                    secure: envs.JWT_COOKIE_SECURITY,
                    httpOnly: envs.JWT_COOKIE_HTTP_STATUS,
                    sameSite: "strict"
                }
            )

            // Return success message
            res
                .status(HttpCode.OK)
                .json({ msg: "user disconnected !" })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // function to consult users
    consultuser: async (req: Request, res: Response) => {
        try {
            const { userID } = req.params

            // check if user exist
            const user = await prisma.user.findUnique({ where: { user_id: userID } });
            if (!user) return exceptions.badRequest(res, "user not found !");

            const infoUser = {
                name: user.name,
                email: user.email,
            }

            // Return success message
            res
                .status(HttpCode.OK)
                .json({ msg: infoUser })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // function to update user 
    updateUserData: async (req: customRequest, res: Response) => {
        try {
            // fetch employeID from authentication
            const userID = req.user?.user_id;
            if (!userID) return exceptions.unauthorized(res, "authentication error !");

            // Check if user user exist
            const user = await prisma.user.findUnique({ where: { user_id: userID } })
            if (!user) return exceptions.badRequest(res, "user not found !");

            // fetch data from body
            const { name, email } = req.body;

            // Vérifier si le nouvel email est déjà utilisé par un autre utilisateur
            if (email && email !== user.email) {
                const emailExists = await prisma.user.findUnique({
                    where: { email },
                    select: { user_id: true } // On récupère uniquement l'ID pour voir si un utilisateur existe
                });

                if (emailExists) {
                    return exceptions.conflict(res, "Email already in use by another user!");
                }
            }

            const updateuser = await prisma.user.update({
                where: { user_id: userID },
                data: { name, email },
                select: { name: true, email: true }
            });
            if (!updateuser) return exceptions.badRequest(res, "error when update user !");

            // Return success message
            res
                .status(HttpCode.CREATED)
                .json({ msg: `${user.name} has been modified successfuly. It's become:`, updateuser })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // function to delete user 
    deleteUser: async (req: customRequest, res: Response) => {
        try {
            // fetch UserID from authentication
            const userID = req.user?.user_id;
            if (!userID) {
                log.warn("Authentication error: No userID found in request")
                return exceptions.unauthorized(res, "authentication error !");
            }

            // Check if user exists
            const user = await prisma.user.findUnique({ where: { user_id: userID } })
            if (!user) {
                log.warn(`user not found: is it the userID is correct ? userID: ${userID}`);
                return exceptions.notFound(res, "user not found !");
            }

            // Delete the user
            const deleteUser = await prisma.user.delete({
                where: {
                    user_id: userID
                }
            });

            // remove access token and clear refresh tooken in cookie for security... 
            res.setHeader('authorization', ``);
            res.removeHeader('authorization');
            res.clearCookie(
                `refresh_key`,
                {
                    secure: envs.JWT_COOKIE_SECURITY,
                    httpOnly: envs.JWT_COOKIE_HTTP_STATUS,
                    sameSite: "strict"
                }
            )
            log.info(`access token remove and refresh token clear for userID: ${userID}`)

            // Return success message
            res
                .status(HttpCode.OK)
                .json({ msg: `${deleteUser.name} has been successfuly deleted!` })
        } catch (error) {
            log.error(`Error when deleting user!`)
            return exceptions.serverError(res, error);
        }
    },

    // Reset Password
    changePassword: async (req: Request, res: Response) => {
        try {
            const { email, oldPassword, newpassword } = req.body;

            // check if user exist
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) return exceptions.notFound(res, "user not exist !");

            if (!(await comparePassword(oldPassword, user.password))) return exceptions.badRequest(res, "Incorrect password !");

            const hashPassword = await hashText(newpassword);
            if (!hashPassword) return exceptions.badRequest(res, "error trying to crypt password !");

            await prisma.user.update({
                where: { email },
                data: {
                    password: hashPassword,
                }
            });

            // Return success message
            res
                .status(HttpCode.OK)
                .json({ msg: `password successfully changed!` })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // Reset Password
    resetPassword: async (req: Request, res: Response) => {
        try {
            const { email, newpassword } = req.body;

            // check if user exist
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) return exceptions.notFound(res, "user not exist !");

            const hashPassword = await hashText(newpassword);
            if (!hashPassword) return exceptions.badRequest(res, "error trying to crypt password !");

            await prisma.user.update({
                where: { email },
                data: {
                    password: hashPassword,
                }
            });

            // Return success message
            res
                .status(HttpCode.OK)
                .json({ msg: `password successfully changed!` })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // Verified OTP
    verifyOtp: async (req: Request, res: Response) => {
        try {
            const { email, otp } = req.body;

            // check if user exist
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) return exceptions.notFound(res, "user not exist !");


            // Check if otp have ever expired
            const now = new Date();
            if (user.otp && user.otp.expire_at > now) return exceptions.unauthorized(res, 'Your token have ever expired !');

            // Check if he was ever verified
            if (user.verified === true) return exceptions.unauthorized(res, 'Your have ever sign in !');

            // Check if it's the correct otp
            if (user.otp !== otp) return exceptions.unauthorized(res, 'Incorect token !');

            // Invalid status
            await prisma.user.update({
                where: {
                    email
                },
                data: {
                    verified: true,
                }
            });

            res.status(HttpCode.OK).json({ msg: "Otp verified !" });

        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // Resend OTP to the USER
    resendOTP: async (req: Request, res: Response) => {
        try {
            const { email } = req.body;

            // check if user exist
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) return exceptions.notFound(res, "user not exist !");

            const otp = generateSimpleOTP();
            const now = new Date();
            const expireOTP = new Date(now.getTime() + 10 * 60)

            const newUser = await prisma.user.update({
                where: {
                    email
                },
                data: {
                    otp: {
                        code: otp,
                        expire_at: expireOTP
                    }
                }
            });
            if (!newUser) return exceptions.notFound(res, "Error when creating generate otp !");

            sendMail(
                newUser.email, // Receiver Email
                'Welcome to blog universe', // Subjet
                'otp', // Template
                { // Template Data
                    date: now,
                    name: newUser.name,
                    otp: otp,
                }
            )

            // Return success message
            res
                .status(HttpCode.CREATED)
                .json({ msg: "OTP regenerer !" })
        } catch (error) {
            return exceptions.serverError(res, error);
        }
    },

    // Fonction qui va se charger de supprimer tous les otp mis a null a minuit tous les jours
    DeleteUNVERIFIED: async () => {
        try {
            await prisma.user.deleteMany({ where: { verified: false } });
        } catch (error) {
            log.error('Failed to delete unverified users:', {
                message: error instanceof Error ? error.message : "Unknown error occurred",
            });
            throw new Error(error instanceof Error ? error.message : "Unknow error occured");
        }
    }
}
export default usersControllers;