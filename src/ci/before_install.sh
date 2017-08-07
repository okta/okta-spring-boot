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

# Travis uses an older version of Java8 by default
JAVA_VERSION=8u131-zulu
MVN_VERSION=3.5.0

# use sdkman to manage installations
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"

sdk install java ${JAVA_VERSION} < /dev/null
sdk install maven ${MVN_VERSION} < /dev/null
export JAVA_HOME="${HOME}/.sdkman/candidates/java/current"
export M2_HOME="${HOME}/.sdkman/candidates/java/current"
export PATH=$M2_HOME/bin:${JAVA_HOME}/bin:$PATH

#Using xmllint is faster than invoking maven
export ARTIFACT_VERSION="$(xmllint --xpath "//*[local-name()='project']/*[local-name()='version']/text()" pom.xml)"
export IS_RELEASE="$([ ${ARTIFACT_VERSION/SNAPSHOT} == $ARTIFACT_VERSION ] && [ $TRAVIS_BRANCH == 'master' ] && echo 'true')"

info "Build configuration:"
echo "Version:             $ARTIFACT_VERSION"
echo "Is release:          ${IS_RELEASE:-false}"
