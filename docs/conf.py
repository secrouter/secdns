"""Sphinx configuration for the secdns documentation."""

project = "secdns"
author = "Austin Probe"
copyright = "2026, Austin Probe"
release = "0.1.0"

extensions = ["myst_parser"]
myst_enable_extensions = ["colon_fence", "deflist"]

html_theme = "furo"
html_title = "secdns"
html_static_path = ["_static"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme_options = {
    "light_logo": "logo-mark.svg",
    "dark_logo": "logo-mark-dark.svg",
    "sidebar_hide_name": False,
    "light_css_variables": {
        "color-brand-primary": "#54672f",
        "color-brand-content": "#54672f",
    },
    "dark_css_variables": {
        "color-brand-primary": "#aebb78",
        "color-brand-content": "#aebb78",
    },
}

source_suffix = {".md": "markdown", ".rst": "restructuredtext"}
