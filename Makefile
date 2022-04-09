
SHELL=/bin/bash

clean:
	rm -f dist/*

build: clean
	@poetry build

publish: clean build
	@poetry config http-basic.plataux mk '12d@#F34g'
	@poetry publish -q -r plataux || echo "this version has already been published"