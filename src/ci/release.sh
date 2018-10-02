#!/bin/bash
#
# Copyright 2017-Present Okta, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

COMMON_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/common.sh"
# shellcheck source=src/ci/common.sh
source "${COMMON_SCRIPT}"

OLD_VERSION="$(xmllint --xpath "//*[local-name()='project']/*[local-name()='version']/text()" pom.xml)"
NEW_VERSION="${OLD_VERSION/-SNAPSHOT}"
TAG_NAME="${PROJECT_NAME}-${NEW_VERSION}" # default release plugin tag format

# TODO: we must use our local maven settings file as this script is NOT ready for triggered by travis
# GPG agent configuration needed to sign artifacts
MVN_CMD="./mvnw"

# Update pom versions, tag, update to new dev version
${MVN_CMD} release:prepare --batch-mode

# stage the release artifacts
${MVN_CMD} release:perform

# the release plugin does not create signed tags, so update the existing tag
git tag "${TAG_NAME}" -f -s -m "${TAG_NAME}" "${TAG_NAME}"

# the release plugin uses this dir to cut the release
# switch to the release dir/tag and publish the javadoc
pushd target/checkout

git clone -b gh-pages "git@github.com:${REPO_SLUG}.git" target/gh-pages

# publish once to the versioned dir
${MVN_CMD} javadoc:aggregate jxr:aggregate -Ppub-docs -Djavadoc.version.dir=''
# and again to the unversioned dir
${MVN_CMD} javadoc:aggregate com.okta:okta-doclist-maven-plugin:generate jxr:aggregate -Ppub-docs -Djavadoc.version.dir="${NEW_VERSION}/"

cd target/gh-pages
git add .
git commit -m "deploying javadocs for v${NEW_VERSION}"
git push origin gh-pages

popd

# push signed tag
git push origin "${TAG_NAME}"

BRANCH_TO_PUSH="$(git rev-parse --abbrev-ref HEAD)"
echo "Attempting to push to '${BRANCH_TO_PUSH}', this may fail depending on GitHub access configuration"
if git push origin "${BRANCH_TO_PUSH}"; then
    echo "Push successful to ${BRANCH_TO_PUSH}"
else
    echo "Manual release, creating pull request"
    PR_BRANCH="release-pr-${NEW_VERSION}"
    git checkout -b "${PR_BRANCH}"
    git push origin "${PR_BRANCH}"

    echo
    echo "Release PR created:"
    hub pull-request -m "Automated PR created while releasing v${NEW_VERSION}" -b "${BRANCH_TO_PUSH}"
fi

echo
echo "Tag '${TAG_NAME}' has been created"
echo "Manually update the release notes at https://github.com/${REPO_SLUG}/releases/new?tag=${TAG_NAME}"