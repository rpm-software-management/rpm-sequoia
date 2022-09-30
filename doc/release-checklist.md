This is a checklist for doing releases.

  1. Start from origin/main, create a branch 'release'
  1. Bump the version in Cargo.toml to XXX.
  1. Bump the version in README.md to XXX.
  1. Make a commit with the message "Release XXX.".
  1. cd /tmp && git clone ~/.../rpm-sequoia && cd rpm-sequoia && cargo publish --dry-run
  1. Push to github, and create a merge request.  Don't auto merge!!!
  1. Make a tag vXXX with the message "Release XXX." signed with an
     offline-key.
  1. In case of errors, correct them, and go back to the step creating
     the release commit.
  1. For the crate to be published, cd back into /tmp/rpm-sequoia, and do
     'cargo publish'.
  1. Merge the branch to main by merging the merge request created in
     step 6, push the tag.
