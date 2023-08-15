const express = require("express");
const bcrypt = require("bcrypt");
const Usuario = require("../model/usuario");
const criarToken = require("../utils/criarToken");
const verificarToken = require("../middleware/verificarToken");

const route = express.Router();

route.get("/", async (req, res) => {
    try {
        const dados = await Usuario.find();
        res.status(200).send({ message: "Dados recuperados com sucesso", payload: dados });
    } catch (error) {
        res.status(500).send({ message: `Erro ao processar dados -> ${error}` });
    }
});

route.post("/cadastro", async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.senha, 10);
        req.body.senha = hashedPassword;

        const dados = new Usuario(req.body);
        const result = await dados.save();

        res.status(201).send({ message: "Cadastro realizado com sucesso", payload: result });
    } catch (error) {
        res.status(500).send({ message: `Erro ao cadastrar -> ${error}` });
    }
});

route.post("/login", async (req, res) => {
    try {
        const result = await Usuario.findOne({ nomeusuario: req.body.nomeusuario });

        if (!result) {
            return res.status(400).send({ message: "Usuário não localizado" });
        }

        const same = await bcrypt.compare(req.body.senha, result.senha);
        if (!same) {
            return res.status(400).send({ message: "Senha inválida" });
        }

        const token = criarToken(result._id, result.usuario, result.email);
        res.status(200).send({
            message: "Autenticado",
            idusuario: result._id,
            token: token,
        });
    } catch (error) {
        res.status(500).send({ message: `Erro ao realizar login -> ${error}` });
    }
});

route.put("/atualizar-senha", verificarToken, async (req, res) => {
    try {
        const usuario = req.data.id;

        if (!req.body.senha) {
            return res.status(400).send({ message: "Nova senha não informada" });
        }

        const hashedPassword = await bcrypt.hash(req.body.senha, 10);
        req.body.senha = hashedPassword;

        const dados = await Usuario.findByIdAndUpdate(
            usuario,
            { senha: req.body.senha },
            { new: true }
        );

        if (!dados) {
            return res.status(400).send({ message: "Não foi possível atualizar a senha" });
        }

        res.status(202).send({ message: "Senha atualizada com sucesso", payload: dados });
    } catch (error) {
        res.status(500).send({ message: `Erro ao atualizar senha -> ${error}` });
    }
});

module.exports = route;
