from setuptools import setup, find_packages
import os

# Read the contents of README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Get package version
package_init = os.path.join(os.path.dirname(__file__), "src", "api_scanner", "__init__.py")
with open(package_init, "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split('=')[1].strip().strip('"\'')
            break
    else:
        version = "0.1.0"

setup(
    name="api-scanner",
    version=version,
    author="Tisone Kironget",
    author_email="tisonkironget@gmail.com",
    description="A tool for intercepting and analyzing API requests",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/TisoneK/api-scanner",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "mitmproxy>=10.0.0",
        "python-dotenv>=0.19.0",
        "colorama>=0.4.4",
        "pydantic>=1.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "mypy>=0.910",
        ],
    },
    entry_points={
        "console_scripts": [
            "api-scanner=api_scanner.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "api_scanner": ["py.typed"],
    },
)
