
# Ensure we are using the latest versions of setuptools, wheel, and twine
python3 -m pip install --upgrade setuptools wheel twine

# Optional: Clean the previous build files
rm -rf build/ dist/ *.egg-info

# Build the source distribution and wheel
python3 setup.py sdist bdist_wheel

# Upload to PyPI using twine
set -a
# Load PyPI token from .env (expects PYPI_TOKEN)
. ./.env
set +a
python3 -m twine upload -u __token__ -p "$PYPI_TOKEN" dist/*
