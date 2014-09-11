# -*- coding: utf-8 -*-

from functools import wraps

from flask import request, jsonify


class ErrosHTTP(object):
    @staticmethod
    def erro_400(chaves):
        modelos = ["{} XXXXXXXX-YYYY-ZZZZ-AAAA-BBBBBBBBBBBB".format(chave) for chave in chaves]
        response = jsonify({
            'erro': u"Adicione um cabeçalho Authorization com {} para acessar essa api".format(", ".join(chaves)),
            'modelo': "Authorization: {}".format(" ".join(modelos))
        })
        response.status_code = 400
        return response

    @staticmethod
    def erro_401():
        response = jsonify({
            'erro': u"Você não está autorizado a acessar essa url."
        })
        response.status_code = 401
        return response


class Autenticacao(object):
    def __init__(self):
        self.VALORES = {}

    def define_valor(self, nome, valor):
        self.VALORES[nome] = valor

    def chaves_validas(self, chaves):
        for chave in self.VALORES.keys():
            if not chave in chaves:
                return False
            if chaves[chave] != self.VALORES[chave]:
                return False
        return True

    def extrai_chaves(self, chaves, headers):
        try:
            authorization = headers["AUTHORIZATION"]
        except KeyError:
            return None
        if not authorization:
            return None
        authorization = authorization.split()
        if len(authorization) != len(chaves) * 2:
            return None
        resultado = {}
        for chave in chaves:
            if chave in authorization:
                indice = authorization.index(chave) + 1
                resultado[chave] = authorization[indice]
        return resultado

    def requer_login(self, function):
        @wraps(function)
        def decorated(*args, **kwargs):
            chaves = self.extrai_chaves(self.VALORES.keys(), request.headers)
            if not chaves:
                return ErrosHTTP.erro_400(self.VALORES.keys())
            if not self.chaves_validas(chaves):
                return ErrosHTTP.erro_401()
            return function(*args, **kwargs)

        return decorated
