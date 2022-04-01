
SHELL=/bin/bash

clean:
	rm -f dist/*

publish: clean
	@poetry config http-basic.plataux mk '12d@#F34g'
	poetry build
	@poetry publish -q -r plataux || echo "this version has already been published"