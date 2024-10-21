import { Request } from "express";

export interface IUser {
    user_id: string;
    name: string;
    email: string;
    password: string;
    otp?: Otp
    verified: boolean
    role: RoleUser
}

export interface IObjet {
    objet_id: string;
    title: string;
    content: string;
    slug: string
    createdAt: Date;
}

export interface customRequest extends Request {
    user?: IUser;
}

export interface Otp {
    code: string
    expire_at: Date
}

export enum RoleUser {
    admin = "admin",
    user = "user",
}