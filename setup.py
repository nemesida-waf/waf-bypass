from setuptools import setup

setup(
    name='waf-bypass',
    version='2.0',
    description='Check your WAF before an attacker does',
    author='Nemesida WAF team',
    url='https://github.com/nemesida-waf/waf-bypass',
    license='MIT',
    packages=['utils'],
    py_modules=['main'],
    install_requires=[
        'attrs==26.1.0',
        'chardet==7.4.3',
        'colorama==0.4.6',
        'curlify==3.0.0',
        'requests==2.34.2',
        'tableprint==0.9.1',
        'yarl==1.24.5'
    ],
    python_requires='>=3.10.12',
    entry_points={
        'console_scripts': [
            'waf-bypass = main:main'
        ]
    }
)
