# -*- coding: utf-8 -*-

import unittest
from mock import patch
from py_inspector import verificadores

from autenticacao_api import autenticador


class TestBase(unittest.TestCase):
    def setUp(self):
        super(TestBase, self).setUp()
        self.autenticacao = autenticador.Autenticacao()


class ValidandoPython(unittest.TestCase, verificadores.TestValidacaoPython):
    def test_valida_pep8_em_autenticador(self):
        arquivo = autenticador.__file__.replace('pyc', 'py')
        self.validacao_pep8([arquivo])

    def test_valida_pylint_em_autenticador(self):
        arquivo = autenticador.__file__.replace('pyc', 'py')
        self.validacao_pylint([arquivo])


class ImportandoModulo(unittest.TestCase):
    def test_deve_ter_um_hook_para_criar_uma_instancia(self):
        import autenticacao_api
        autenticacao_api.autenticacao().should.be.a(autenticador.Autenticacao)


class TestRetornaChaves(TestBase):
    def test_obtendo_chaves_com_chave_api_apenas(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_api"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa"})

    def test_obtendo_chaves_com_chave_loja_apenas(self):
        header = {"AUTHORIZATION": "chave_loja a-chave-loja-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_loja"], header)
        chaves.should.be.equal({"chave_loja": "a-chave-loja-e-essa"})

    def test_obtendo_chaves_com_chave_usuario_apenas(self):
        header = {"AUTHORIZATION": "chave_usuario a-chave-usuario-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_usuario"], header)
        chaves.should.be.equal({"chave_usuario": "a-chave-usuario-e-essa"})

    def test_obtendo_chaves_com_chave_api_e_chave_loja(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_loja a-chave-loja-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_api", "chave_loja"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa", "chave_loja": "a-chave-loja-e-essa"})

    def test_obtendo_chaves_com_chave_api_e_chave_usuario(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_usuario a-chave-usuario-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_api", "chave_usuario"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa", "chave_usuario": "a-chave-usuario-e-essa"})

    def test_obtendo_chaves_com_tudo(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_loja a-chave-loja-e-essa chave_usuario a-chave-usuario-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_api", "chave_loja", "chave_usuario"], header)
        chaves.should.be.equal({"chave_api": "a-chave-api-e-essa", "chave_loja": "a-chave-loja-e-essa", "chave_usuario": "a-chave-usuario-e-essa"})

    def test_retorna_none_se_nao_tiver_authorization_no_header(self):
        header = {}
        chaves = self.autenticacao.extrai_chaves(["chave_api", "chave_loja", "chave_usuario"], header)
        chaves.should.be.equal(None)

    def test_retorna_none_se_authorization_no_header_for_none(self):
        header = {"AUTHORIZATION": None}
        chaves = self.autenticacao.extrai_chaves(["chave_api", "chave_loja", "chave_usuario"], header)
        chaves.should.be.equal(None)

    def test_retorna_none_se_authorization_no_header_for_vazio(self):
        header = {"AUTHORIZATION": ''}
        chaves = self.autenticacao.extrai_chaves(["chave_api", "chave_loja", "chave_usuario"], header)
        chaves.should.be.equal(None)

    def test_retorna_none_se_chaves_no_authorization_for_menor_que_passado(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_usuario a-chave-usuario-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_api", "chave_loja", "chave_usuario"], header)
        chaves.should.be.equal(None)

    def test_retorna_none_se_chaves_no_authorization_for_maior_que_passado(self):
        header = {"AUTHORIZATION": "chave_api a-chave-api-e-essa chave_usuario a-chave-usuario-e-essa"}
        chaves = self.autenticacao.extrai_chaves(["chave_api"], header)
        chaves.should.be.equal(None)


class TestComparaChaves(TestBase):
    def test_define_chave(self):
        self.autenticacao.valores.should.be.empty
        self.autenticacao.define_valor('ZAS', 'Valor Zas')
        self.autenticacao.valores.should.be.equal({'ZAS': 'Valor Zas'})

    def test_chaves_nao_possui_todos_os_itens(self):
        self.autenticacao.define_valor("teste-1", "valor-teste-1")
        self.autenticacao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-1"}
        self.autenticacao.chaves_validas(chaves).should.be.false

    def test_chaves_corretas(self):
        self.autenticacao.define_valor("teste-1", "valor-teste-1")
        self.autenticacao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-1", "teste-2": "valor-teste-2"}
        self.autenticacao.chaves_validas(chaves).should.be.true

    def test_chaves_incorretas_de_primeira(self):
        self.autenticacao.define_valor("teste-1", "valor-teste-1")
        self.autenticacao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-0", "teste-2": "valor-teste-2"}
        self.autenticacao.chaves_validas(chaves).should.be.false

    def test_chaves_incorretas_de_segunda(self):
        self.autenticacao.define_valor("teste-1", "valor-teste-1")
        self.autenticacao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-1", "teste-2": "valor-teste-0"}
        self.autenticacao.chaves_validas(chaves).should.be.false


class RequestMock(object):
    headers = {"AUTHORIZATION": "chave_api a-chave-api-eh-essa"}


class RequestMockSemAuthorization(object):
    headers = {}


class TestUsandoDecorator(TestBase):
    @patch("autenticacao_api.autenticador.request", RequestMock)
    def test_deve_chamar_metodo_se_chaves_for_correto(self):
        assertiva = {'chamado': False}
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-essa')
        @self.autenticacao.requerido
        def requer_autenticacao(assertiva_passada):
            assertiva_passada['chamado'] = True
        requer_autenticacao(assertiva)
        assertiva['chamado'].should.be.truthy

    @patch("autenticacao_api.autenticador.request", RequestMock)
    def test_deve_retornar_401_se_nao_for_chave_valida(self):
        assertiva = {'nao_chamado': True}
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')
        @self.autenticacao.requerido
        def requer_autenticacao(assertiva_passada):
            assertiva_passada['nao_chamado'] = False
        assertiva['nao_chamado'].should.be.truthy
        requer_autenticacao(assertiva).should.be.equal(({'metadados': {'versao': '0.0.1', 'resultado': 'nao_autorizado', 'api': 'Autenticador'}, 'nao_autorizado': {'mensagem': u'Voc\xea n\xe3o est\xe1 autorizado a acessar essa url.'}}, 401))

    @patch("autenticacao_api.autenticador.request", RequestMockSemAuthorization)
    def test_deve_retornar_400_se_nao_tiver_chave_no_header(self):
        assertiva = {'nao_chamado': True}
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')
        @self.autenticacao.requerido
        def requer_autenticacao(assertiva_passada):
            assertiva_passada['nao_chamado'] = False
        assertiva['nao_chamado'].should.be.truthy
        requer_autenticacao(assertiva).should.be.equal(({'metadados': {'versao': '0.0.1', 'resultado': 'request_invalido', 'api': 'Autenticador'}, 'request_invalido': {'mensagem': u'Adicione um cabe\xe7alho Authorization com chave_api para acessar essa api. Ex.: Authorization: chave_api XXXXXXXX-YYYY-ZZZZ-AAAA-BBBBBBBBBBBB'}}, 400))
