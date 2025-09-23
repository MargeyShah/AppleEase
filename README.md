# AppleEase

Built using python 3.13

A tool to create apple distribution certs and mobileprovision profiles.

Adds all iPhones and iPads to the mobileprovision profile 


## Setup 
Dependency links
* [uv](https://github.com/astral-sh/uv)


Run `uv sync` to install dependencies

Run `uv venv --seed` to create a venv for this app.

Run `uv tool install -e .` in the root directory to make `AppleEase` executable globally.

Requires an [Apple AppStoreConnect p8 secret](https://appstoreconnect.apple.com/access/integrations/api)
Create a Team key from the URL. Store the Issuer ID on the page as well as the Key ID in an env file you create.

Create a [static identifier](https://developer.apple.com/account/resources/identifiers/list) (no regex) and set 
that as the BUNDLE_ID


```env
EMAIL=<Your Apple email>
CN=<Your Name>
C="US" # 2 Character Country Code

# AppStore Connect API Key Info (tied to .p8 file)
KEY_ID=<on the appstoreconnect page>
ISSUER_ID=<on the appstoreconnect page>
P8_FILE=<abs path to the p8 file>

## Apple Developer Info
# Static Identifier goes here
BUNDLE_ID=com.somethin.somethinelse

# Relative output directory of usable p12 and mobileprovision files
OUT_DIR=out

# Password for P12 File
P12_PASS=<changeme>
```

## Usage
`applease run -e /path/to/env/file/.env`
The mobileprovision and p12 files will be stored in the `OUT_DIR` after this is done.

## Troubleshooting

Python - module not found
```sh 
# from the root of the project
source .venv/bin/activate
python -m ensurepip --upgrade
uv sync
uv tool install --reinstall -e .
```


409 status code 
    - Ensure you don't already have 3 certificates. Delete one if so.
