#!/bin/sh
set -eu
cd /opt/ad-audit
APP_IMAGE="${APP_IMAGE:-ad-identity-guard:2.0}"
TEST_IMAGE="${TEST_IMAGE:-ad-identity-guard:hunting-tests}"
docker build -f Dockerfile.hunting-tests --build-arg APP_IMAGE="$APP_IMAGE" -t "$TEST_IMAGE" .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,size=512m -e PYTHONDONTWRITEBYTECODE=1 -v /opt/ad-audit/app:/opt/ad-audit/app:ro -v /opt/ad-audit/tests:/opt/ad-audit/tests:ro --entrypoint python "$TEST_IMAGE" -m unittest discover -s tests -p 'test_hunting*.py' -v
