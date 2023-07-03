python setup.py develop
python setup.py install
python setup.py sdist bdist_wheel
twine upload dist/*
