/*
 * Copyright 2014 Stormpath, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.sdk.cache

import org.springframework.cache.concurrent.ConcurrentMapCache
import org.testng.annotations.Test

import static org.hamcrest.CoreMatchers.nullValue
import static org.hamcrest.CoreMatchers.is
import static org.hamcrest.CoreMatchers.not
import static org.hamcrest.CoreMatchers.notNullValue
import static org.hamcrest.MatcherAssert.assertThat

import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when
import static org.mockito.Mockito.verify

/**
 * @since 0.3.0
 */
class SpringCacheTest {

    @Test(expectedExceptions = IllegalArgumentException)
    void testNullSpringCache() {
        new SpringCache(null)
    }

    @Test
    void testGet() {

        def springCache = mock(org.springframework.cache.Cache)
        def valueWrapper = mock(org.springframework.cache.Cache.ValueWrapper)
        def key = 'key'
        def value = 'value'

        when(springCache.get(key)).thenReturn(valueWrapper)
        when(valueWrapper.get()).thenReturn(value)

        def cache = new SpringCache(springCache)
        assertThat value, is(cache.get(key))
    }

    @Test
    void testGetNull() {

        def springCache = mock(org.springframework.cache.Cache)
        def key = 'key'
        when(springCache.get(key)).thenReturn(null)

        def cache = new SpringCache(springCache)
        assertThat cache.get(key), nullValue()
    }
    @Test
    void testPut() {

        def cache = new SpringCache(new ConcurrentMapCache('foo'))
        def key = 'key'
        def value = 'value1'
        def prev = 'value0'
        def val = cache.get(key)

        assertThat val, nullValue()
        assertThat cache.put(key, prev), notNullValue()
        assertThat prev, is(not(cache.put(key, value)))
    }

    @Test
    void testRemove() {

        def springCache = mock(org.springframework.cache.Cache)
        def valueWrapper = mock(org.springframework.cache.Cache.ValueWrapper)

        def key = 'key'
        def prev = 'value0'

        when(springCache.get(key)).thenReturn(valueWrapper)
        when(valueWrapper.get()).thenReturn(prev)

        def cache = new SpringCache(springCache)
        def retval = cache.remove(key)

        assertThat prev, is(retval)
        verify(springCache).evict(key)
    }
}