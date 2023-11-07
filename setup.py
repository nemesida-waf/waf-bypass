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
        'attrs==22.1.0',
        'chardet==5.1.0',
        'colorama==0.4.6',
        'curlify==2.2.1',
        'requests==2.31.0',
        'tableprint==0.9.1',
        'yarl==1.8.2'
    ],
    python_requires='>=3.0.0',
    entry_points={
        'console_scripts': [
            'waf-bypass = main:main'
        ]
    }
)
