# -*- coding: utf-8 -*-

from functools import wraps

from flask import request, jsonify
from autenticacao_api import configuracao


class ErrosHTTP(object):
    @staticmethod
    def erro_400():
        response = jsonify({
            'erro': u"Adicione um cabeçalho Authorization com chave_api e chave_aplicacao para acessar essa api",
            'modelo': "Authorization: chave_api XXXXXXXX-YYYY-ZZZZ-AAAA-BBBBBBBBBBBB chave_aplicacao UUUUUUUU-AAAA-WWWW-BBBB-HHHHHHHHHHHH"
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


def chaves_validas(chaves):
    for chave in configuracao.VALORES.keys():
        if not chave in chaves:
            return False
        if chaves[chave] != configuracao.VALORES[chave]:
            return False
    return True


class ChavesInvalidas(Exception):
    pass


def extrai_chaves(chaves, headers):
    try:
        authorization = headers["AUTHORIZATION"]
    except KeyError:
        return None
    if not authorization:
        return None
    authorization = authorization.split()
    if len(authorization) < len(chaves) * 2:
        raise ChavesInvalidas(u"As chaves passadas não correspondem as chaves no header")
    resultado = {}
    for chave in chaves:
        if chave in authorization:
            indice = authorization.index(chave) + 1
            resultado[chave] = authorization[indice]
    return resultado


def requer_login(function):
    @wraps(function)
    def decorated(*args, **kwargs):
        chaves = extrai_chaves(configuracao.VALORES.keys(), request.headers)
        if not chaves:
            return ErrosHTTP.erro_400()
        if not chaves_validas(chaves):
            return ErrosHTTP.erro_401()
        return function(*args, **kwargs)

    return decorated
