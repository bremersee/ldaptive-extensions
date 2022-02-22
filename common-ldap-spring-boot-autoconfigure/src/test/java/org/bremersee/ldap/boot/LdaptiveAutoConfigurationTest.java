/*
 * Copyright 2021-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bremersee.ldap.boot;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

/**
 * The ldaptive autoconfiguration test.
 */
class LdaptiveAutoConfigurationTest {

  /**
   * Init.
   */
  @Test
  void init() {
    LdaptiveProperties properties = new LdaptiveProperties();
    properties.setPooled(false);
    LdaptiveAutoConfiguration configuration = buildConfiguration(properties);
    configuration.init();
  }

  /**
   * Ldaptive template.
   */
  @Test
  void ldaptiveTemplate() {
    LdaptiveProperties properties = new LdaptiveProperties();
    properties.setPooled(false);

    LdaptiveAutoConfiguration configuration = buildConfiguration(properties);
    assertNotNull(configuration.ldaptiveTemplate(configuration.connectionFactory()));
  }

  /**
   * Connection factory.
   */
  @Test
  void connectionFactory() {
    LdaptiveProperties properties = new LdaptiveProperties();
    properties.setPooled(false);

    LdaptiveAutoConfiguration configuration = buildConfiguration(properties);
    assertNotNull(configuration.connectionFactory());
  }

  @SuppressWarnings("unchecked")
  private static LdaptiveAutoConfiguration buildConfiguration(LdaptiveProperties properties) {
    ObjectProvider<LdaptiveConnectionConfigFactory> connectionConfigFactory
        = mock(ObjectProvider.class);
    when(connectionConfigFactory.getIfAvailable(any()))
        .thenReturn(LdaptiveConnectionConfigFactory.defaultFactory());

    return new LdaptiveAutoConfiguration(
        properties,
        connectionConfigFactory);
  }
}