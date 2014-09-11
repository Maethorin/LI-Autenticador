# -*- coding: utf-8 -*-

import mox
from autenticacao_api import configuracao
from autenticacao_api.autenticador import extrai_chaves, chaves_validas


class TestRetornaChaves(mox.MoxTestBase):
    def test_obtendo_chaves_com_chave_api_apenas(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa"}
        chaves = extrai_chaves(["chave_api"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa"})

    def test_obtendo_chaves_com_chave_loja_apenas(self):
        header = {"AUTHORIZATION": "chave_loja a-chave-loja-e-essa"}
        chaves = extrai_chaves(["chave_loja"], header)
        chaves.should.be.equal({"chave_loja": "a-chave-loja-e-essa"})

    def test_obtendo_chaves_com_chave_usuario_apenas(self):
        header = {"AUTHORIZATION": "chave_usuario a-chave-usuario-e-essa"}
        chaves = extrai_chaves(["chave_usuario"], header)
        chaves.should.be.equal({"chave_usuario": "a-chave-usuario-e-essa"})

    def test_obtendo_chaves_com_chave_api_e_chave_loja(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_loja a-chave-loja-e-essa"}
        chaves = extrai_chaves(["chave_api", "chave_loja"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa", "chave_loja": "a-chave-loja-e-essa"})

    def test_obtendo_chaves_com_chave_api_e_chave_usuario(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_usuario a-chave-usuario-e-essa"}
        chaves = extrai_chaves(["chave_api", "chave_usuario"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa", "chave_usuario": "a-chave-usuario-e-essa"})

    def test_obtendo_chaves_com_tudo(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_loja a-chave-loja-e-essa chave_usuario a-chave-usuario-e-essa"}
        chaves = extrai_chaves(["chave_api", "chave_loja", "chave_usuario"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa", "chave_loja": "a-chave-loja-e-essa", "chave_usuario": "a-chave-usuario-e-essa"})


class TestComparaChaves(mox.MoxTestBase):
    def test_chaves_nao_possui_todos_os_itens(self):
        configuracao.define_valor("teste-1", "valor-teste-1")
        configuracao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-1"}
        chaves_validas(chaves).should.be.false

    def test_chaves_corretas(self):
        configuracao.define_valor("teste-1", "valor-teste-1")
        configuracao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-1", "teste-2": "valor-teste-2"}
        chaves_validas(chaves).should.be.true

    def test_chaves_incorretas_de_primeira(self):
        configuracao.define_valor("teste-1", "valor-teste-1")
        configuracao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-0", "teste-2": "valor-teste-2"}
        chaves_validas(chaves).should.be.false

    def test_chaves_incorretas_de_segunda(self):
        configuracao.define_valor("teste-1", "valor-teste-1")
        configuracao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-1", "teste-2": "valor-teste-0"}
        chaves_validas(chaves).should.be.false
