from os import path
from setuptools import setup

here = path.abspath(path.dirname(__file__))

# Try to convert markdown readme file to rst format
try:
    import pypandoc
    md_file = path.join(here, 'README.md')
    rst_file = path.join(here, 'README.rst')
    pypandoc.convert_file(source_file=md_file, outputfile=rst_file, to='rst')
except (ImportError, OSError, IOError, RuntimeError):
    pass

# Get the long description from the relevant file
with open(path.join(here, 'README.rst')) as f:
    long_description = f.read()

# Get version from file
with open(path.join(here, 'version')) as f:
    version = f.read().strip()


setup(
    name='redmine2youtrack',
    version=version,
    python_requires='>=3',
    packages=['youtrackutils',
              'youtrackutils.redmine',
              'youtrackutils.utils',
              'youtrack',
              'youtrack.sync'],
    url='https://github.com/ekho/redmine2youtrack',
    license='Apache 2.0',
    maintainer='Boris Gorbylev',
    maintainer_email='ekho@ekho.name',
    description='YouTrack import and utility scripts',
    long_description=long_description,
    entry_points={
        'console_scripts': [
            'redmine2youtrack=youtrackutils.redmine2youtrack:main',
        ],
    },
    install_requires=[
        'python-dateutil',
        'pyactiveresource',
        'jsmin',
        'httplib2 >= 0.7.4',
        'six',
        'requests'
    ]
)
