import jwt from 'jsonwebtoken';

const auth = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken || req?.headers?.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "PROVIDENCIE SEU TOKEN DE ACESSO",
                error: true,
                success: false
            });
        }

        const decode = await jwt.verify(token, process.env.SECRET_KEY_ACCESS_TOKEN);

        if(!decode) {
            return res.status(401).json({
                message: "ACESSO NAO AUTORIZADO",
                error: true,
                success: false
            });
        }

        req.userId = decode.id;
        next();
    } catch (error) {
        return res.status(500).json({
            message: "VOCE NAO ESTA LOGADO NO SISTEMA",
            error: true,
            success: false
        });
    }
}

export default auth;