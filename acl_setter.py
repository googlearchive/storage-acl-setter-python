#!/usr/bin/python

# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Apply a bucket's default object ACL on all contained objects.

Given a target bucket and credentials for a user or service account, this
script applies the bucket's default object ACLs to all existing objects in the
bucket. If no default object ACL exists, we fabricate one using the bucket's
ACL and convert all WRITER roles to READERs.

For usage details, see README.md.
"""

import json
import random
import sys
import time

from apiclient.discovery import build as discovery_build
from apiclient.errors import HttpError
from apiclient.http import BatchHttpRequest
import gflags
import httplib2
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import SignedJwtAssertionCredentials
from oauth2client.file import Storage as CredentialStorage
from oauth2client.tools import run as run_oauth2

# The full_control scope is required for ACL management. For more information
# about authorizing GCS requests, see:
#   https://developers.google.com/storage/docs/json_api/v1/how-tos/authorizing
FULL_SCOPE = 'https://www.googleapis.com/auth/devstorage.full_control'

# Number of patch requests to issue per batch (Max 1000).
BATCH_SIZE = 1000

# Maximum number of list results per request. If none, no limit is applied.
MAX_RESULTS = None

# Maximum number of retries we will issue for each HTTP request.
MAX_RETRIES = 5


gflags.DEFINE_string(
        'bucket',
        None,
        'Set this bucket\'s default object ACL on all contained objects.')

gflags.DEFINE_string(
        'credentials_file',
        'credentials.json',
        'File where we can store OAuth2 tokens.')

gflags.DEFINE_string(
        'client_secrets',
        'client_secrets.json',
        ('Client secrets file obtained from the APIs console:\n'
         '  https://code.google.com/apis/console#access.'))

gflags.DEFINE_string(
        'key_file',
        None,
        ('Service account private key file downloaded from the APIs console:\n'
         '  https://code.google.com/apis/console#access.'))

gflags.DEFINE_string(
        'client_email',
        None,
        'Email address associated with a service account.')

FLAGS = gflags.FLAGS

# Helpful message to display if the client secrets file is missing.
MISSING_CLIENT_SECRETS_MESSAGE = (
        'WARNING: Please configure OAuth 2.0 with information from the \n'
        'APIs Console: <https://code.google.com/apis/console#access>.')


def make_service_account_client(scope):
    """Make a Storage API client authenticated with a service account."""
    credential_storage = CredentialStorage(FLAGS.credentials_file)
    creds = credential_storage.get()
    if creds is None or creds.invalid:
        with open(FLAGS.key_file) as fd:
            creds = SignedJwtAssertionCredentials(
                    service_account_name=FLAGS.client_email,
                    private_key=fd.read(),
                    scope=scope)
            creds.set_store(credential_storage)

    http = creds.authorize(httplib2.Http())
    return discovery_build('storage', 'v1beta1', http=http)


def make_user_client(scope):
    """Make a Storage API client authenticated with a user account."""
    credential_storage = CredentialStorage(FLAGS.credentials_file)
    creds = credential_storage.get()
    if creds is None or creds.invalid:
        flow = flow_from_clientsecrets(FLAGS.client_secrets, scope=scope,
                                       message=MISSING_CLIENT_SECRETS_MESSAGE)
        creds = run_oauth2(flow, credential_storage)

    http = creds.authorize(httplib2.Http())
    return discovery_build('storage', 'v1beta1', http=http)


def request_with_retry(request):
    """Issue an apiclient request and retry if necessary."""
    for i in xrange(MAX_RETRIES + 1):
        if i:
            sleeptime = 2**i * random.random()
            sys.stderr.write(
                    'Sleeping for %d seconds before retry #%d.\n' %
                    (sleeptime, i))
            time.sleep(sleeptime)
        try:
            return request.execute()
        except HttpError as err:
            sys.stderr.write('Caught exception: %s\n' % str(err))
            if err.resp.status < 500:
                raise


def get_def_object_acl(client):
    """Gets the default object ACL from the flag-provided bucket."""
    req = client.buckets().get(
            bucket=FLAGS.bucket,
            fields='defaultObjectAcl,acl',
            projection='full')
    resp = request_with_retry(req)
    if 'defaultObjectAcl' in resp:
        return resp['defaultObjectAcl']
    else:
        # If there's no defaultObjectAcl, use the bucket's ACL and replace
        # WRITER with READER
        for ac_entry in resp['acl']:
            if ac_entry['role'] == 'WRITER':
                ac_entry['role'] = 'READER'
        return resp['acl']


def generate_objects(client):
    """Generator that yields names of objects in FLAGS.bucket."""
    list_req = client.objects().list(
            bucket=FLAGS.bucket,
            max_results=MAX_RESULTS,
            fields='items(name),nextPageToken')

    # We use the API client's built-in support for pagination. For more
    # information, see:
    #   https://developers.google.com/api-client-library/python/guide/pagination
    while list_req:
        list_resp = request_with_retry(list_req)

        for obj in list_resp['items']:
            yield obj['name']

        list_req = client.objects().list_next(list_req, list_resp)


def make_callback(names_to_setacl):
    """Return a callback for processing individual batch responses."""
    def callback(_, resp, exception):
        """Clears successfully patched objects from names_to_setacl."""
        if not exception:
            names_to_setacl.remove(resp['name'])
        elif exception.resp.status < 500:
            raise exception
        else:
            # In case of a retryable exception, print and don't remove the
            # object from names_to_setacl.
            print exception
    return callback


def batch_set_acl(client, names_to_setacl, new_acl):
    """Set new_acl on all objects in names_to_setacl with a batch request."""
    # For more information about batch requests, see:
    #   https://developers.google.com/api-client-library/python/guide/batch
    #   https://developers.google.com/storage/docs/json_api/v1/how-tos/batch
    callback = make_callback(names_to_setacl)
    batch_req = BatchHttpRequest(callback=callback)
    for name in names_to_setacl:
        req_body = {'acl': new_acl}
        patch_req = client.objects().patch(
                bucket=FLAGS.bucket,
                object=name,
                projection='full',
                body=req_body)

        batch_req.add(patch_req)
    print 'Issuing %d patch requests in batch.' % len(names_to_setacl)
    request_with_retry(batch_req)


def main():
    if FLAGS.key_file and FLAGS.client_email:
        client = make_service_account_client(FULL_SCOPE)
    else:
        client = make_user_client(FULL_SCOPE)
    default_acl = get_def_object_acl(client)
    print ('Applying default ACL (printed below) to all objects in %s.'
                 % FLAGS.bucket)
    print json.dumps(default_acl, indent=2)

    names_to_setacl = set()
    for name in generate_objects(client):
        while len(names_to_setacl) >= BATCH_SIZE:
            batch_set_acl(client, names_to_setacl, default_acl)
        names_to_setacl.add(name)
    batch_set_acl(client, names_to_setacl, default_acl)


if __name__ == '__main__':
    FLAGS(sys.argv)
    main()
