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

JAVA_PACKAGE=jdk-8u131-linux-x64
MVN_VERSION=3.5.0

# Travis uses an older version of Java8 by default
wget --no-cookies \
     --header "Cookie: oraclelicense=accept-securebackup-cookie" \
     http://download.oracle.com/otn-pub/java/jdk/8u131-b11/d54c1d3a095b4ff2b6607d096fa80163/${JAVA_PACKAGE}.tar.gz
mkdir ../java
tar -zxf ${JAVA_PACKAGE}.tar.gz -C ../java
rm ${JAVA_PACKAGE}.tar.gz
export JAVA_HOME="$(pwd)/../java/$(ls ../java)"

#Using xmllint is faster than invoking maven
export ARTIFACT_VERSION="$(xmllint --xpath "//*[local-name()='project']/*[local-name()='version']/text()" pom.xml)"
export IS_RELEASE="$([ ${ARTIFACT_VERSION/SNAPSHOT} == $ARTIFACT_VERSION ] && [ $TRAVIS_BRANCH == 'master' ] && echo 'true')"

#Install newer Maven since Travis uses 3.2 by default
wget https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/${MVN_VERSION}/apache-maven-${MVN_VERSION}-bin.zip
unzip -qq apache-maven-${MVN_VERSION}-bin.zip -d ..
rm apache-maven-${MVN_VERSION}-bin.zip
export M2_HOME=$PWD/../apache-maven-${MVN_VERSION}
export PATH=$M2_HOME/bin:${JAVA_HOME}/bin:$PATH

echo "Build configuration:"
echo "Version:             $ARTIFACT_VERSION"
echo "Is release:          ${IS_RELEASE:-false}"

#Download the oidc-tck jar for integration tests
TCK_JAR="https://oss.sonatype.org/service/local/artifact/maven/redirect?r=snapshots&g=com.okta.tests&a=okta-oidc-tck&v=0.2.0-SNAPSHOT&e=jar&c=shaded"
cd integration-tests/oauth2
curl ${TCK_JAR} -L -o okta-oidc-tck-0.2.0-SNAPSHOT-shaded.jar
cd ../..
