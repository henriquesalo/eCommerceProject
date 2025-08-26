import sendEmail from "../config/sendEmail.js";
import UserModel from "../models/user.model.js";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import generatedAccessToken from "../utils/generatedAccessToken.js";
import generatedRefreshToken from "../utils/generatedRefreshToken.js";
import uploadImageCloudinary from "../utils/uploadImageCloudinary.js";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";

dotenv.config();

export async function registerUserController(req, res) {
    try {
        const { name, email, password } = req.body;
        if(!name || !email || !password) {
            return res.status(400).json({ 
                message: "TODOS ESSES CAMPOS SÃO OBRIGATORIOS", 
                error: true,
                success: false
            })
        }

        const user = await UserModel.findOne({email});
        
        if(user) {
            return res.json({
                message: "EMAIL JÁ EXISTE",
                error: true,
                success: false
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);

        const payload = {
            name,
            email,
            password : hashPassword
        };

        const newUser = new UserModel(payload);
        const save = await newUser.save();

        const VerifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?token=${save?._id}`;

        const verifyEmail = await sendEmail({
            sendTo: email,
            subject: "Verifique seu email",
            html: verifyEmailTemplate({
                name,
                url: VerifyEmailUrl,
            })
        });

        return res.json({
            message: "USUARIO CADASTRADO COM SUCESSO",
            error: false,
            success: true,
            data: save,
        });

    } catch (error) {
        return res.status(500).json({ 
            message: error.message || error,
            error : true,
            success : false
        });
    }
}

export async function verifyEmailController(req, res) {
    try {
        const { code } = req.body;
        const user = await UserModel.findOne({ _id: code });

        if(!user) {
            return res.status(400).json({
                message: "TOKEN DE USUARIO NAO ENCONTRADO OU INVALIDO", 
                error: true,
                success: false
            });
        }

        const updateUser = await UserModel.findOne(
            { _id: code },
            { verify_email: true},
        );
        return res.json({
            message: "EMAIL VERIFICADO COM SUCESSO",
            success: true,
            error: false,
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false,
        });
    }
}

export async function loginController(req, res) {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "EMAIL E SENHA SÃO OBRIGATORIOS",
                error: true,
                success: false
            });
        }

        const user = await UserModel.findOne({ email });

        if (!user) {
            return res.status(404).json({
                message: "ESTE USUARIO NAO EXISTE",
                error: true,
                success: false
            });
        }

        if (user.status !== "Active") {
            return res.status(401).json({
                message: "ENTRE EM CONTATO COM O ADMINISTRADOR",
                error: true,
                success: false
            });
        }

        const checkPassword = await bcrypt.compare(password, user.password);

        if (!checkPassword) {
            return res.status(401).json({
                message: "SENHA INCORRETA, TENTE NOVAMENTE",
                error: true,
                success: false
            });
        }

        const accessToken = await generatedAccessToken(user._id);
        const refreshToken = await generatedRefreshToken(user._id);

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: "None",
        };

        res.cookie("accessToken", accessToken, cookieOptions);
        res.cookie("refreshToken", refreshToken, cookieOptions);

        return res.json({
            message: "LOGIN REALIZADO COM SUCESSO",
            error: false,
            success: true,
            data: {
                accessToken,
                refreshToken
            },
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

export async function logoutController(req, res) {
    try {
        const userid = req.userId

        const cookiesOption = {
            httpOnly: true,
            secure: true,
            sameSite: "None",
        }
        res.clearCookie("accessToken", cookiesOption);
        res.clearCookie("refreshToken", cookiesOption);

        const removeRefreshToken = await UserModel.findByIdAndUpdate(userid, { refresh_token: "" });

        return res.json({
            message: "LOGOUT REALIZADO COM SUCESSO",
            error: false,
            success: true
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

export async function uploadAvatar(req, res) {
    try {
        const userId = req.userId;
        const image = req.file;
        
        const upload = await uploadImageCloudinary(image);

        const updateUser = await UserModel.findByIdAndUpdate(
            userId,
            { avatar: upload.url },
        );

        return res.json({
            message: "CARREGANDO PERFIL",
            error: false,
            success: true,
            data: {
                _id: userId,
                avatar: upload.url
            }
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}

export async function updateUserDetails(req, res) {
    try {
        const userId = req.userId;
        const { name, email, mobile, password } = req.body;

        let hashPassword = "";

        if(password) {
            const salt = await bcrypt.genSalt(10);
            hashPassword = await bcrypt.hash(password, salt);
        }

        const updateUser = await UserModel.updateOne({_id: userId},{
            ...(name && { name : name}),
            ...(email && { email : email }),
            ...(mobile && { mobile : mobile }),
            ...(password && { password : hashPassword })
        });

        return res.json({
            message: "DADOS DO USUÁRIO ATUALIZADOS COM SUCESSO",
            error: false,
            success: true,
            data: updateUser
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        });
    }
}