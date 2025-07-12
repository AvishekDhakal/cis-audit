from setuptools import setup, find_packages

setup(
    name="cis_audit_lib",
    version="0.1.0",
    author="Your Name",
    description="Library to scan Linux hosts against CIS benchmarks",
    packages=find_packages(),
    install_requires=[
        "paramiko>=2.0.0",
        "PyYAML>=5.3.1"
    ],
    entry_points={
        "console_scripts": [
            "cis-scan=cis_audit_lib.core:scan_cli",
            "cis-report=cis_audit_lib.report:report_cli"
        ]
    },
)

