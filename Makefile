.PHONY: install test deep scale scale-national capacity rehearsal-smoke rehearsal-peak lint demo check-group site deploy web-install web-test web-dev

install:
	pip install --require-hashes --no-deps -r requirements/runtime.txt -r requirements/dev.txt && pip install --no-deps --no-build-isolation -e .

test:
	pytest -m "not slow and not scale and not rehearsal" -q

deep:
	HYPOTHESIS_PROFILE=deep pytest -m "not slow and not scale and not rehearsal" -q

scale:
	pytest -m slow -q

scale-national:
	pytest -m scale -q

capacity:
	chunaviq capacity

rehearsal-smoke:
	chunaviq rehearse smoke --out rehearsal/smoke

# The largest constituency at its design rate (or as close as this machine allows), under attack, end to end.
# Takes 1-2 hours on a 16-thread desktop and ~10 GB of disk. Outputs in rehearsal/shard-peak/.
rehearsal-peak:
	chunaviq rehearse shard-peak --out rehearsal/shard-peak

lint:
	ruff check src tests tools && ruff format --check src tests tools && python tools/scan_pii.py

check-group:
	python tools/gen_group.py --check

demo:
	rm -rf run && chunaviq simulate run --voters 1000 --constituencies 3 && \
	chunaviq verify run/record --expect-manifest-hash $$(python -c "import json;print(json.load(open('run/summary.json'))['manifest_hash'])") --json run/verify.json; \
	chunaviq report run/verify.json run/observer-report.html && echo "open run/observer-report.html"

site:
	chunaviq report audits/scale-10k/verify.json web/public/report/index.html

web-install:
	npm --prefix web ci

web-test:
	npm --prefix web run lint && npm --prefix web test

web-dev:
	npm --prefix web run dev

deploy: site
	npm --prefix web run build && vercel deploy --prod --yes
