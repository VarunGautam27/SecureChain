"""Local GUI for SecureChain.

This is a non authoritative preview layer. It runs the exact same scan
pipeline the CI gate uses, so a live scan here shows the same result a push
would produce. It never replaces the CI/CD gate as the enforcement point: a
push still triggers the real GitHub Actions workflow, and that remains the
only thing that actually blocks a merge.
"""
