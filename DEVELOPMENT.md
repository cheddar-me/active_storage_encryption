# Development

## Running the tests

```sh
bundle install
bin/rails app:test
```

To run against a specific Rails version, point Bundler at one of the Appraisal gemfiles, the same way CI does:

```sh
BUNDLE_GEMFILE=gemfiles/rails_8.gemfile bundle install
BUNDLE_GEMFILE=gemfiles/rails_8.gemfile bin/rails app:test
```

The disk, mirror and overrides tests need nothing. The tests for the cloud services talk to real buckets, and each suite skips itself unless all of its env vars are set.

## Environment variables

### EncryptedS3Service on AWS

`test/lib/encrypted_s3_service_test.rb`, against the `active-storage-encryption-test-bucket` bucket in `eu-central-1`.

| Variable | Required | On CI |
| --- | --- | --- |
| `AWS_ACCESS_KEY_ID` | yes | secret |
| `AWS_SECRET_ACCESS_KEY` | yes | secret |

### EncryptedS3Service on DigitalOcean Spaces

`test/lib/encrypted_s3_service_digital_ocean_test.rb`, running the same tests as AWS against a Spaces bucket.

| Variable | Required | On CI |
| --- | --- | --- |
| `DO_SPACES_ACCESS_KEY_ID` | yes | variable |
| `DO_SPACES_SECRET_ACCESS_KEY` | yes | secret |
| `DO_SPACES_BUCKET` | yes | variable |
| `DO_SPACES_REGION` | no, defaults to `fra1` | variable |

### EncryptedGCSService

`test/lib/encrypted_gcs_service_test.rb`, against the `sandbox-ci-testing-secure-documents` bucket in the `sandbox-ci-25b8` project. These tests do not run on CI.

| Variable | Required | On CI |
| --- | --- | --- |
| `GOOGLE_APPLICATION_CREDENTIALS` | yes, the path to a service account JSON keyfile | not set |

## Credentials on CI

On GitHub only the credentials themselves (secret keys, keyfiles) are secrets. Everything else, such as bucket names, regions and access key IDs, is a repository variable, so that it is visible which accounts and buckets CI is actually using. `AWS_ACCESS_KEY_ID` predates this and is still a secret. `gh variable list` and `gh secret list` show what is set.
