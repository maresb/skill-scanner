# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for skill-scanner."""

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None
project_root = SPECPATH

litellm_datas = collect_data_files('litellm', include_py_files=False)
certifi_datas = collect_data_files('certifi')
jsonschema_datas = collect_data_files('jsonschema')
jsonschema_spec_datas = collect_data_files('jsonschema_specifications')
pydantic_datas = collect_data_files('pydantic')
litellm_imports = collect_submodules('litellm')
rich_hidden = collect_submodules('rich._unicode_data')

a = Analysis(
    [os.path.join(project_root, 'skill_scanner_entry.py')],
    pathex=[project_root],
    binaries=[],
    datas=[
        (os.path.join(project_root, 'skill_scanner', 'data', 'yara_rules'), os.path.join('skill_scanner', 'data', 'yara_rules')),
        (os.path.join(project_root, 'skill_scanner', 'data', 'prompts'), os.path.join('skill_scanner', 'data', 'prompts')),
        (os.path.join(project_root, 'skill_scanner', 'data', 'rules'), os.path.join('skill_scanner', 'data', 'rules')),
    ] + litellm_datas + certifi_datas + jsonschema_datas + jsonschema_spec_datas + pydantic_datas,
    hiddenimports=[
        'skill_scanner', 'skill_scanner.cli', 'skill_scanner.cli.cli',
        'skill_scanner.config', 'skill_scanner.config.constants',
        'skill_scanner.core', 'skill_scanner.data', 'skill_scanner.utils',
        'click', 'rich', 'httpx', 'yara', 'pydantic', 'dotenv', 'jsonschema',
        'aiohttp', 'requests', 'yaml', 'frontmatter', 'tabulate',
        'anthropic', 'openai', 'google.genai', 'google.generativeai',
    ] + litellm_imports + rich_hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        'skill_scanner.api', 'uvicorn', 'fastapi',
        'tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy', 'PIL',
        'IPython', 'notebook', 'jupyter',
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='skill-scanner',
    debug=False, strip=False, upx=True,
    runtime_tmpdir=None, console=True,
    target_arch=None,
)
