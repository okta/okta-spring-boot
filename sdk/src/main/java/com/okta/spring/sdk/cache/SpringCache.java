/*
 * Copyright 2015 Stormpath, Inc.
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
package com.okta.spring.sdk.cache;

import com.okta.sdk.cache.Cache;
import com.okta.sdk.lang.Assert;

/**
 * A Okta SDK {@link com.okta.sdk.cache.Cache} implementation that wraps a Spring {@link org.springframework.cache.Cache Cache} instance.
 * This allows the Okta SDK to use your existing Spring caching mechanism so you only need to configure one
 * caching implementation.
 * <p>
 * This implementation effectively acts as an adapter or bridge from the Okta SDK cache API to the Spring cache API.
 *
 * @param <K> The cache key type
 * @param <V> The cache value type
 * @since 0.3.0
 */
@SuppressWarnings("unchecked")
public class SpringCache<K, V> implements Cache<K, V> {

    private final org.springframework.cache.Cache springCache;

    public SpringCache(org.springframework.cache.Cache springCache) {
        Assert.notNull(springCache, "spring cache instance cannot be null.");
        this.springCache = springCache;
    }

    @Override
    public V get(K key) {
        org.springframework.cache.Cache.ValueWrapper vw = springCache.get(key);
        if (vw == null) {
            return null;
        }
        return (V) vw.get();
    }

    @Override
    public V put(K key, V value) {
        springCache.put(key, value);
        return get(key);
    }

    @Override
    public V remove(K key) {
        V v = get(key);
        springCache.evict(key);
        return v;
    }
}