package com.okta.test.mock

class Config {

    String implementation
    Map<String, TestScenario> scenarios = new LinkedHashMap<>()
}

class TestScenario {
    String command
    List<String> args = new ArrayList<>()
    Map<String, Integer> ports = new HashMap<>()
}
