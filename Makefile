#!/bin/sh

test:
	@echo "Iniciando os testes"
	coverage2 run `which nosetests`
	coverage2 report -m --fail-under=70