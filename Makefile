.PHONY: check doctor bootstrap test p0-node p0-up p0-kyverno p0-ecr p0-attest p0-admission p0-negatives p0-adversarial p0-expired
check:
	python3 scripts/check_docs.py

doctor:
	python3 scripts/doctor.py

bootstrap:
	python3 scripts/bootstrap_tools.py
	uv venv --allow-existing --python 3.12.16 .tools/venv
	uv pip sync --require-hashes --python .tools/venv/bin/python requirements-p0.lock

test:
	.tools/venv/bin/python -m unittest discover -s tests/unit -v
	.tools/venv/bin/python -m unittest discover -s tests/contract -v

p0-node:
	python3 scripts/p0_lab.py node

p0-up:
	python3 scripts/p0_lab.py up $(P0_PRIVILEGE_FLAG)

p0-kyverno:
	python3 scripts/p0_lab.py kyverno

p0-ecr:
	.tools/venv/bin/python scripts/p0_ecr.py

p0-attest:
	.tools/venv/bin/python scripts/p0_attestation.py

p0-admission:
	.tools/venv/bin/python scripts/p0_admission.py

p0-negatives:
	.tools/venv/bin/python scripts/p0_negatives.py

p0-adversarial:
	.tools/venv/bin/python scripts/p0_adversarial.py

p0-expired:
	.tools/venv/bin/python scripts/p0_admission.py --expired
