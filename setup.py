from setuptools import setup

setup(
    name='findcve',
    version='0.1.0',
    py_modules=['findcve'],
    include_package_data=True,
    install_requires=[
        'click',
        'pyyaml',
        'version_utils',
        'requests',
        'clint',
        'colorama',
    ],
    entry_points='''
        [console_scripts]
        findcve=findcve:cli
    ''',
)
