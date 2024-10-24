import jwt from "jsonwebtoken"
import { readFileSync } from "fs";
import { envs } from "../../core/config/env";
import { IUser } from '../../core/interfaces/interfaces';
import log from "@src/core/config/logger";

// Download all The keys at the beginin of our program
const privateKey = readFileSync(envs.JWT_PRIVATE_KEY as string, "utf-8");
const publicKey = readFileSync(envs.JWT_PUBLIC_KEY as string, "utf-8");
const RefreshprivateKey = readFileSync(envs.JWT_REFRESH_PRIVATE_KEY as string, "utf-8");
const RefreshpublicKey = readFileSync(envs.JWT_REFRESH_PUBLIC_KEY as string, "utf-8");

const userToken = {
    accessToken: (payload: IUser) => {
        const signOption = {
            algorithm: envs.JWT_ALGORITHM as jwt.Algorithm,
            expiresIn: envs.JWT_ACCESS_EXPIRES_IN as string
        } 
        return jwt.sign(payload, privateKey, signOption) as string;
    },

    verifyAccessToken: (token: string) => {
        try {
            return jwt.verify(token, publicKey) as IUser;
        } catch (error) {
            log.error(`Invalide access token: ${error}`)
            throw new Error(`Failed to verify access token`);;
        }
    },

    decodeAccessToken: (token: string) => {
        try {
            return jwt.decode(token) as IUser;
        } catch (error) {
            log.error(`Invalide access token: ${error}`)
            throw new Error(`Failed to decode access token`);;
        }
    },


    // REFRESH TOKEN ET SES FONCTIONS
        refreshToken: (payload: IUser) => {
        const signOption = {
            algorithm: envs.JWT_ALGORITHM as jwt.Algorithm,
            expiresIn: envs.JWT_REFRESH_EXPIRES_IN as string
        };

        return jwt.sign(payload, RefreshprivateKey, signOption);
    },

    verifyRefreshToken: (refreshToken: string) => {
        try {
            return jwt.verify(refreshToken, RefreshpublicKey) as IUser;
        } catch (error) {
            log.error(`token invalide: ${error}`);
            throw new Error(`Failed to verify refresh token`);;
        }
    },

    decodeRefreshToken: (refreshToken: string) => {
        try {
            return jwt.decode(refreshToken) as IUser;
        } catch (error) {
            log.error(`token invalide: ${error}`);
            throw new Error(`Failed to decode refresh token`);;
        }
    },
};

export default userToken;