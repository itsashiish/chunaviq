.PHONY: install test deep scale lint demo check-group site deploy

install:
	pip install --require-hashes --no-deps -r requirements/runtime.txt -r requirements/dev.txt && pip install --no-deps --no-build-isolation -e .

test:
	pytest -m "not slow" -q

deep:
	HYPOTHESIS_PROFILE=deep pytest -m "not slow" -q

scale:
	pytest -m slow -q

lint:
	ruff check src tests tools && ruff format --check src tests tools && python tools/scan_pii.py

check-group:
	python tools/gen_group.py --check

demo:
	rm -rf run && chunaviq simulate run --voters 1000 --constituencies 3 && \
	chunaviq verify run/record --expect-manifest-hash $$(python -c "import json;print(json.load(open('run/summary.json'))['manifest_hash'])") --json run/verify.json; \
	chunaviq report run/verify.json run/observer-report.html && echo "open run/observer-report.html"

site:
	chunaviq report audits/scale-10k/verify.json site/report/index.html

deploy: site
	vercel deploy --prod --yes
