#!/usr/bin/env bash

# Test all commits on this branch but the last one.
#
# Used in the all_commits ci job to ensure all commits build
# and tests pass at least for the sequoia-openpgp crate.

# NOTE: under gitlab's Settings, "CI/CD", General Pipelines ensure
# that the "git shallow clone" setting is set to 0.  Otherwise other
# branch are not fetched.

set -e
set -x

# Use dummy identity to make git rebase happy.
git config user.name "C.I. McTestface"
git config user.email "ci.mctestface@example.com"

# Make sure the gitlab project is configured.
if ! git describe --all origin/main
then
    echo "origin/main is not present.  Configure the gitlab project (see .ci/all_commits.sh)."
    exit 1
fi

# If the previous commit already is on main we're done.
git merge-base --is-ancestor HEAD~ origin/main &&
  echo "All commits tested already" &&
  exit 0

# Leave out the last commit - it has already been checked.
git checkout HEAD~
git status
git rebase origin/main \
           --exec 'echo ===; echo ===; echo ===; git log -n 1;' \
           --exec 'cargo test --all' &&
  echo "All commits passed tests" &&
  exit 0

# The rebase failed - probably because a test failed.
git rebase --abort; exit 1
