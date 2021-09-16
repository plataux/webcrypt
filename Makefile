
SHELL=/bin/bash

ifneq (,$(wildcard ./.env))
    include .env
    export
endif

clean:
	rm -f dist/*

install:
	@poetry config repositories.priv_repo ${REPO_URL} && poetry config http-basic.priv_repo ${REPO_USER} ${REPO_PASSWORD} && poetry install

update:
	@poetry config repositories.priv_repo ${REPO_URL} && poetry config http-basic.priv_repo ${REPO_USER} ${REPO_PASSWORD} && poetry update

test:
	pytest

build: clean
	@poetry build

publish: clean build
	@poetry config repositories.priv_repo ${REPO_URL} && poetry config http-basic.priv_repo ${REPO_USER} ${REPO_PASSWORD} && poetry publish -v -r priv_repo