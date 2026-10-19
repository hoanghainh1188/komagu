#!/usr/bin/env python3
"""Automated verification test for Komainu Docker container packaging (Issue #52)."""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docker-publish.yml"


class TestDockerPackaging(unittest.TestCase):
    """Verify Docker container definition and CI/CD workflow."""

    def test_dockerfile_structure_and_security(self) -> None:
        """Dockerfile must exist, use python-slim, configure non-root user, and set entrypoint."""
        self.assertTrue(DOCKERFILE.is_file(), f"Dockerfile not found at {DOCKERFILE}")
        content = DOCKERFILE.read_text(encoding="utf-8")

        self.assertRegex(content, r"(?m)^FROM python:3\.\d+-slim\b")
        self.assertIn("useradd", content)
        self.assertIn("USER komainu", content)
        self.assertIn("WORKDIR /workspace", content)
        self.assertIn('ENTRYPOINT ["/app/bin/komainu"]', content)
        self.assertIn('CMD ["--help"]', content)
        self.assertIn("PYTHONPATH=/app", content)
        self.assertIn("COPY examples/ /app/examples/", content)

    def test_dockerignore_excludes_unnecessary_files(self) -> None:
        """.dockerignore must exclude git history, pycache, and temporary outputs."""
        self.assertTrue(DOCKERIGNORE.is_file(), f".dockerignore not found at {DOCKERIGNORE}")
        content = DOCKERIGNORE.read_text(encoding="utf-8")

        for pattern in (".git/", "__pycache__/", "lsa-out/", "node_modules/"):
            self.assertIn(pattern, content, f"Missing {pattern} in .dockerignore")

    def test_docker_workflow_configuration(self) -> None:
        """GitHub Actions workflow must exist and test zero-install execution."""
        self.assertTrue(WORKFLOW.is_file(), f"Workflow not found at {WORKFLOW}")
        content = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("docker/build-push-action", content)
        self.assertIn("docker run --rm komainu:test --version", content)
        self.assertIn("docker run --rm komainu:test scan --help", content)
        self.assertIn("ghcr.io", content)


if __name__ == "__main__":
    unittest.main()
