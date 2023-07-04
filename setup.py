import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="rosetta-ce",
    version="1.5.4",
    author="Ayman Mahmoud",
    author_email="content@ayman.online",
    description="Rosetta is a Python package that can be used to fake security logs and alerts for testing different "
                "detection and response use cases.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ayman-m/rosetta",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "requests",
        "faker",
        "urllib3"
    ]
)
