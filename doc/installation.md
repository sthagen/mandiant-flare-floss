# FireEye Labs Obfuscated String Solver

## Installation
You can install FLOSS in a few different ways.
First, if you simply want to use FLOSS to extract strings, just download
 the [standalone binaries](https://github.com/fireeye/flare-floss/releases).
However, if you want to use FLOSS as a Python library,
 you can install the package  directly from Github using `pip`.
Finally, if you'd like to contribute patches or features to FLOSS,
 you'll need to work with a local copy of the source code.

## Method 1: Using FLOSS standalone

If you simply want to use FLOSS to extract strings,
use the standalone binaries we host on Github:
 https://github.com/fireeye/flare-floss/releases.
These binary executable files contain all the source code,
 Python interpreter, and associated resources needed to make FLOSS run.
This means you can run it without any installation!
Just invoke the file using your terminal shell to see the help documentation.

We use PyInstaller to create these packages.


## Method 2: Using FLOSS as a Python library

If you'd like to use FLOSS as part of an automated analysis system,
 you might want to invoke it as a Python library.
This will be less messy than using `system()` to shell-out
 to FLOSS and parse `STDOUT`.
We designed FLOSS to be as easy to use from a client program as from
 the command line.

To install FLOSS as a *Python2.7* library, you'll need to install a few
 dependencies, and then use `pip` to fetch the FLOSS module.
 
:warning: **FLOSS requires Python2.7 due to some of its dependencies.**

### Step 1: Install FLOSS module

Use `pip` (Python2.7) to install the FLOSS module to your local
 Python environment.
This fetches the library code to your computer, but does not keep
 editable source files around for you to hack on.
If you'd like to edit the source files, see Method 3.

- Install FLOSS:

    `$ pip install https://github.com/fireeye/flare-floss/zipball/master`


### Step 2: Use FLOSS from a Python script

You can now import the `floss` module from a Python script:

    #!/usr/env/python
    import floss
    print(dir(floss))


## Method 3: Inspecting the FLOSS source code

If you'd like to review and modify the FLOSS source code,
 you'll need to check it out from Github and install it locally.
By following these instructions, you'll maintain a local directory
 of source code that you can modify and run easily.

### Step 1: Check out source code

- Clone the FLOSS git repository:

    `$ git clone https://github.com/fireeye/flare-floss /local/path/to/src`

### Step 2: Install the local source code

Next, use `pip` to install the source code in "editable" mode.
This means that Python will load the FLOSS module from this local
 directory rather than copying it to `site-packages` or `dist-packages`.
This is good, because it is easy for us to modify files and see the
 effects reflected immediately.
But be careful not to remove this directory unless uninstalling FLOSS!

- Install FLOSS:

    `$ pip install -e /local/path/to/src`

you'll find that the `FLOSS.exe` (Windows) or `floss` (Linux) executables
 in your path now invoke the FLOSS binary from this directory.

### Step 3: Install development and testing dependencies

To install all testing and development dependencies, run:

`$ pip install -e /local/path/to/src[dev]`

We use a git submodule to separate [code](https://github.com/fireeye/flare-floss) and [test data](https://github.com/fireeye/flare-floss-testfiles).
To clone everything use the `--recurse-submodules` option:
- `$ git clone --recurse-submodules https://github.com/fireeye/flare-floss.git /local/path/to/src` (HTTPS)
- `$ git clone --recurse-submodules git@github.com:fireeye/flare-floss.git /local/path/to/src` (SSH)

Or use  the manual option:
- clone repository
  - `$ git clone https://github.com/fireeye/flare-floss.git /local/path/to/src` (HTTPS)
  - `$ git clone git@github.com:fireeye/flare-floss.git /local/path/to/src` (SSH)
- `$ cd /local/path/to/src`
- `$ git submodule update --init tests/data`


### Step 4: Building standalone executables

Once youre happy with your contribution to FLOSS, you can package and
 distribute a standalone exectuable for your friends using PyInstaller.
This combines the source code, Python interpreter, and required resources
 into a single file that can be run without installation.

- Install pyinstaller:

    `$ pip install pyinstaller`

- Build standalone executable:

    `$ pyinstaller floss.spec`

- Distribute standalone executable:

    `$ cp ./dist/floss.exe /the/internet`
