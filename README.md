storage-acl-setter-python
=========================

Applies a GCS bucket's default object ACLs to all contained objects using batch
JSON patch requests issued via the Google APIs Python Client Library.

api: storage

keywords: cmdline, pagination, oauth2


### Setup for authenticating as a user.
1. As of February 2013, the Google APIs interface to Google Cloud Storage
   (a.k.a. the GCS JSON API) is in Limited Preview, so users must request
   access from the [API Console Services tab][1]:
2. Visit the [API Access tab][2] of the APIs Console to create a client ID for
   an installed application. The new Client ID will have a "Download JSON"
   option; click on this to acquire a `client_secrets.json file`.
3. Download `acl_setter.py` from this repo.

### Setup for authenticating as a project via service accounts.
1. As of February 2013, the Google APIs interface to Google Cloud Storage
   (a.k.a. the GCS JSON API) is in Limited Preview, so users must request
   access from the [API Console Services tab][1]:
2. Visit the [API Access tab][2] of the APIs Console to create a service
   account for your project and download its private key.
3. Record the service account's email address.
4. Download `acl_setter.py` from this repo.

### Usage for authenticating as a user.
To execute `acl_setter.py` with user credentials, run

$ python acl_setter.py --bucket=mybucket --client_secrets=client_secrets.json --credentials_file=credentials.json

where

* `mybucket` is the target bucket,
* `client_secrets.json` is the path to the client_secrets.json file you
  downloaded earlier,
* and `credentials.json` is a path to a local file for storing OAuth2 tokens

### Usage for authenticating as a project via service accounts.
To execute `acl_setter.py` with user credentials, run

$ python acl_setter.py --bucket=mybucket --key_file=privatekey.p12 --client_email=1234567890-qwertyuiop@developer.gserviceaccount.com --credentials_file=credentials.json

where

* `mybucket` is the target bucket,
* `privatekey.p12` is the path to your service account private key,
* the `--client_email` flag supplies the service account email address you
  recorded earlier,
* and `credentials.json` is a path to a local file for storing OAuth2 tokens


## Contributing changes
See CONTRIB.md

## Licensing
See LICENSE


[1]: https://code.google.com/apis/console/#:services
[2]: https://code.google.com/apis/console/#:access
