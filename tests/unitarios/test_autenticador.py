# -*- coding: utf-8 -*-

import unittest
from mock import patch
from py_inspector import verificadores

from autenticacao_api import autenticador
from tests.unitarios import base


class TestBase(unittest.TestCase):
    def setUp(self):
        super(TestBase, self).setUp()
        self.autenticacao = autenticador.Autenticacao()


class ValidandoPython(base.ValidandoPython):
    def test_valida_pep8_em_cadastro(self):
        arquivo = autenticador.__file__.replace("pyc", "py")
        self.validacao_pep8([arquivo])

    def test_valida_pylint_em_cadastro(self):
        arquivo = autenticador.__file__.replace("pyc", "py")
        self.validacao_pylint([arquivo])


class ImportandoModulo(unittest.TestCase):
    def test_deve_ter_um_hook_para_criar_uma_instancia(self):
        import autenticacao_api
        autenticacao_api.autenticacao().should.be.a(autenticador.Autenticacao)

    def test_deve_poder_passar_o_nome_da_api(self):
        import autenticacao_api
        autenticacao = autenticacao_api.autenticacao('api_teste')
        autenticacao.nome_api.should.be.equal('api_teste')

    def test_deve_poder_passar_a_versao_da_api(self):
        import autenticacao_api
        autenticacao = autenticacao_api.autenticacao(versao_api='1.01')
        autenticacao.versao_api.should.be.equal('1.01')


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

    def test_define_chave_como_lista(self):
        self.autenticacao.valores.should.be.empty
        self.autenticacao.define_valor('ZAS', ['Valor 1', 'Valor 2', 'Valor 3'])
        self.autenticacao.valores.should.be.equal({'ZAS':  ['Valor 1', 'Valor 2', 'Valor 3']})

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

    def test_chaves_corretas_como_lista_1(self):
        self.autenticacao.define_valor('teste-1', ['valor-teste-1', 'valor-teste-2', 'valor-teste-3'])
        self.autenticacao.define_valor("teste-2", "valor-teste-4")
        chaves = {"teste-1": "valor-teste-1", "teste-2": "valor-teste-4"}
        self.autenticacao.chaves_validas(chaves).should.be.true

    def test_chaves_corretas_como_lista_2(self):
        self.autenticacao.define_valor('teste-1', ['valor-teste-1', 'valor-teste-2', 'valor-teste-3'])
        self.autenticacao.define_valor("teste-2", "valor-teste-4")
        chaves = {"teste-1": "valor-teste-3", "teste-2": "valor-teste-4"}
        self.autenticacao.chaves_validas(chaves).should.be.true

    def test_chaves_incorretas_de_primeira(self):
        self.autenticacao.define_valor("teste-1", "valor-teste-1")
        self.autenticacao.define_valor("teste-2", "valor-teste-2")
        chaves = {"teste-1": "valor-teste-0", "teste-2": "valor-teste-2"}
        self.autenticacao.chaves_validas(chaves).should.be.false

    def test_chaves_incorretas_como_lista(self):
        self.autenticacao.define_valor('teste-1', ['valor-teste-1', 'valor-teste-2', 'valor-teste-3'])
        self.autenticacao.define_valor("teste-2", "valor-teste-4")
        chaves = {"teste-1": "valor-teste-0", "teste-2": "valor-teste-4"}
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
    @patch("autenticacao_api.autenticador.make_response")
    def test_deve_retornar_401_se_nao_for_chave_valida(self, response_mock):
        response_mock.return_value = 'ERRO 401'
        assertiva = {'nao_chamado': True}
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')

        @self.autenticacao.requerido
        def requer_autenticacao(assertiva_passada):
            assertiva_passada['nao_chamado'] = False

        requer_autenticacao(assertiva).should.be.equal('ERRO 401')
        response_mock.assert_called_with(
            '{"metadados": {"versao": "0.0.1", "resultado": "nao_autorizado", "api": "Autenticador"}, "nao_autorizado": {"mensagem": "Voc\\u00ea n\\u00e3o est\\u00e1 autorizado a acessar essa url."}}',
            401,
            {'Content-Type': 'text/json; charset=utf-8'}
        )
        assertiva['nao_chamado'].should.be.truthy

    @patch("autenticacao_api.autenticador.request", RequestMockSemAuthorization)
    @patch("autenticacao_api.autenticador.make_response")
    def test_deve_retornar_400_se_nao_tiver_chave_no_header(self, response_mock):
        response_mock.return_value = 'ERRO 400'
        assertiva = {'nao_chamado': True}
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')

        @self.autenticacao.requerido
        def requer_autenticacao(assertiva_passada):
            assertiva_passada['nao_chamado'] = False
        requer_autenticacao(assertiva).should.be.equal('ERRO 400')
        assertiva['nao_chamado'].should.be.truthy
        response_mock.assert_called_with(
            '{"metadados": {"versao": "0.0.1", "resultado": "request_invalido", "api": "Autenticador"}, "request_invalido": {"mensagem": "Adicione um cabe\\u00e7alho Authorization com chave_api para acessar essa api. Ex.: Authorization: chave_api XXXXXXXX-YYYY-ZZZZ-AAAA-BBBBBBBBBBBB"}}',
            400,
            {'Content-Type': 'text/json; charset=utf-8'}
        )

    @patch("autenticacao_api.autenticador.request", RequestMock)
    @patch("autenticacao_api.autenticador.make_response")
    def test_deve_retornar_401_com_nome_api_se_for_passado(self, response_mock):
        response_mock.return_value = 'ERRO 401'
        self.autenticacao = autenticador.Autenticacao('api-teste')
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')

        @self.autenticacao.requerido
        def requer_autenticacao():
            pass

        requer_autenticacao().should.be.equal('ERRO 401')
        response_mock.assert_called_with(
            '{"metadados": {"versao": "0.0.1", "resultado": "nao_autorizado", "api": "api-teste"}, "nao_autorizado": {"mensagem": "Voc\\u00ea n\\u00e3o est\\u00e1 autorizado a acessar essa url."}}',
            401,
            {'Content-Type': 'text/json; charset=utf-8'}
        )

    @patch("autenticacao_api.autenticador.request", RequestMockSemAuthorization)
    @patch("autenticacao_api.autenticador.make_response")
    def test_deve_retornar_400_com_nome_api_se_for_passado(self, response_mock):
        response_mock.return_value = 'ERRO 400'
        self.autenticacao = autenticador.Autenticacao('api-teste')
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')

        @self.autenticacao.requerido
        def requer_autenticacao():
            pass
        requer_autenticacao().should.be.equal('ERRO 400')
        response_mock.assert_called_with(
            '{"metadados": {"versao": "0.0.1", "resultado": "request_invalido", "api": "api-teste"}, "request_invalido": {"mensagem": "Adicione um cabe\\u00e7alho Authorization com chave_api para acessar essa api. Ex.: Authorization: chave_api XXXXXXXX-YYYY-ZZZZ-AAAA-BBBBBBBBBBBB"}}',
            400,
            {'Content-Type': 'text/json; charset=utf-8'}
        )

    @patch("autenticacao_api.autenticador.request", RequestMock)
    @patch("autenticacao_api.autenticador.make_response")
    def test_deve_retornar_401_com_versao_api_se_for_passado(self, response_mock):
        response_mock.return_value = 'ERRO 401'
        self.autenticacao = autenticador.Autenticacao(versao_api='0.1')
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')

        @self.autenticacao.requerido
        def requer_autenticacao():
            pass

        requer_autenticacao().should.be.equal('ERRO 401')
        response_mock.assert_called_with(
            '{"metadados": {"versao": "0.1", "resultado": "nao_autorizado", "api": "Autenticador"}, "nao_autorizado": {"mensagem": "Voc\\u00ea n\\u00e3o est\\u00e1 autorizado a acessar essa url."}}',
            401,
            {'Content-Type': 'text/json; charset=utf-8'}
        )

    @patch("autenticacao_api.autenticador.request", RequestMockSemAuthorization)
    @patch("autenticacao_api.autenticador.make_response")
    def test_deve_retornar_400_com_versao_api_se_for_passado(self, response_mock):
        response_mock.return_value = 'ERRO 400'
        self.autenticacao = autenticador.Autenticacao(versao_api='0.1')
        self.autenticacao.define_valor('chave_api', 'a-chave-api-eh-outra')

        @self.autenticacao.requerido
        def requer_autenticacao():
            pass

        requer_autenticacao().should.be.equal('ERRO 400')
        response_mock.assert_called_with(
            '{"metadados": {"versao": "0.1", "resultado": "request_invalido", "api": "Autenticador"}, "request_invalido": {"mensagem": "Adicione um cabe\\u00e7alho Authorization com chave_api para acessar essa api. Ex.: Authorization: chave_api XXXXXXXX-YYYY-ZZZZ-AAAA-BBBBBBBBBBBB"}}',
            400,
            {'Content-Type': 'text/json; charset=utf-8'}
        )
