const jwt = require("jsonwebtoken");
const cfg = require("../config/cfg");

const HTTP_UNAUTHORIZED = 401;

const verificarToken = (req, res, next) => {
    const token = req.headers.token;

    if (!token) {
        return res.status(HTTP_UNAUTHORIZED).send({ message: "Não autorizado" });
    }

    jwt.verify(token, cfg.jwt_secret, (error, result) => {
        if (error) {
            return res.status(HTTP_UNAUTHORIZED).send({ message: `Token inválido -> ${error}` });
        }

        req.userData = {
            id: result.id,
            user: result.nomeusuario,
            email: result.email,
        };

        next();
    });
};

module.exports = verificarToken;
