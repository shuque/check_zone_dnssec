import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="check_zone_dnssec",
    version="1.0.1",
    author="Shumon Huque",
    author_email="shuque@gmail.com",
    description="Check DNSSEC at all nameservers for a zone",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shuque/check_zone_dnssec",
    scripts=['check_zone_dnssec.py'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
