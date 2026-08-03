"""Sphinx configuration for the secdns documentation."""

project = "secdns"
author = "Austin Probe"
copyright = "2026, Austin Probe"
release = "0.1.0"

extensions = ["myst_parser"]
myst_enable_extensions = ["colon_fence", "deflist"]

html_theme = "furo"
html_title = "secdns"
html_static_path = []
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

source_suffix = {".md": "markdown", ".rst": "restructuredtext"}
