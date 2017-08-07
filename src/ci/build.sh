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

# all the prep is done, lets run the build!
MVN_CMD="mvn -s src/ci/settings.xml"

# if this build was triggered via a cron job, just scan the dependencies
if [ "$TRAVIS_EVENT_TYPE" = "cron" ] ; then
    echo "Running TRAVIS CRON task"
    $MVN_CMD dependency-check:aggregate -Powasp
else
    # run 'mvn deploy' if we can
    if [ "$DEPLOY" = true ] ; then
        echo "Deploying SNAPSHOT build"
        $MVN_CMD deploy -Pci

        # also deploy the javadocs to the site
        git config --global user.email "developers@okta.com"
        git config --global user.name "travis-ci Auto Doc Build"
        $MVN_CMD javadoc:aggregate scm-publish:publish-scm -Ppub-docs -Pci
    else
        # else try to run the ITs if possible (for someone who has push access to the repo
        if [ "$RUN_ITS" = true ] ; then
            echo "Running mvn install"
            $MVN_CMD install -Pci
        else
            # fall back to running an install and skip the ITs
            echo "Skipping ITs, likely this build is a pull request from a fork"
            $MVN_CMD install -DskipITs -Pci
        fi
    fi
fi
