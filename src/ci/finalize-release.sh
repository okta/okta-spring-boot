#!/bin/bash
#
# Copyright 2017 Okta, Inc.
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

# TODO: we must use our local maven settings file as this script is NOT ready for triggered by travis
# GPG agent configuration needed to sign artifacts
MVN_CMD="./mvnw"

# the release plugin uses this dir to cut the release
cd target/checkout

NEW_VERSION="$(xmllint --xpath "//*[local-name()='project']/*[local-name()='version']/text()" pom.xml)"
TAG_NAME="okta-spring-boot-parent-${NEW_VERSION}" # default release plugin tag format
#
##Release
$MVN_CMD org.sonatype.plugins:nexus-staging-maven-plugin:release

git clone -b gh-pages git@github.com:okta/okta-spring-boot.git target/gh-pages

# publish once to the versioned dir
$MVN_CMD javadoc:aggregate -Ppub-docs -Djavadoc.version.dir=''
# and again to the unversioned dir
$MVN_CMD javadoc:aggregate -Ppub-docs -Djavadoc.version.dir="${NEW_VERSION}/"

cd target/gh-pages
git add .
git commit -m "deploying javadocs for v${NEW_VERSION}"
git push origin gh-pages

cd ../../../..

git push origin $(git rev-parse --abbrev-ref HEAD)
git push origin ${TAG_NAME}
