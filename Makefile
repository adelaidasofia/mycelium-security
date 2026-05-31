# Canonical CI gate. `make ci` is the ONE command CI (test.yml) and the local
# pre-push gate (ci-test) both run, so they cannot drift. Mirrors the test job:
# the pytest suite. Test deps installed by the caller before this runs.
.PHONY: ci
ci:
	pytest -v
