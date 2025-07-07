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
        'attrs==24.2.0',
        'chardet==5.2.0',
        'colorama==0.4.6',
        'curlify==2.2.1',
        'requests==2.32.4',
        'tableprint==0.9.1',
        'yarl==1.9.4'
    ],
    python_requires='>=3.9.0',
    entry_points={
        'console_scripts': [
            'waf-bypass = main:main'
        ]
    }
)
