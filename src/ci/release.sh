#!/bin/bash
#
# Copyright 2017 Okta
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
source "${COMMON_SCRIPT}"

OLD_VERSION="$(xmllint --xpath "//*[local-name()='project']/*[local-name()='version']/text()" pom.xml)"
NEW_VERSION="${OLD_VERSION/-SNAPSHOT}"
TAG_NAME="okta-sdk-root-${NEW_VERSION}" # default release plugin tag format

# TODO: we must use our local maven settings file as this script is NOT ready for triggered by travis
# GPG agent configuration needed to sign artifacts
MVN_CMD="mvn"

# Update pom versions, tag, update to new dev version
${MVN_CMD} release:prepare --batch-mode

# stage the release artifacts
${MVN_CMD} release:perform

# the release plugin does not create signed tags, so update the existing tag
git tag ${TAG_NAME} -f -s -m "${TAG_NAME}"

echo
echo "Tag '${TAG_NAME}' has been created"
echo "To complete release run: ./src/ci/finalize-release.sh"

