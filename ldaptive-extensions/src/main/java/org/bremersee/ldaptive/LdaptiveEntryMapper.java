/*
 * Copyright 2019 the original author or authors.
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

package org.bremersee.ldaptive;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import org.ldaptive.AttributeModification;
import org.ldaptive.AttributeModification.Type;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.ModifyRequest;
import org.ldaptive.beans.LdapEntryMapper;
import org.ldaptive.transcode.ValueTranscoder;

/**
 * The ldap entry mapper.
 *
 * @param <T> the type of the domain object
 * @author Christian Bremer
 */
@Valid
public interface LdaptiveEntryMapper<T> extends LdapEntryMapper<T> {

  /**
   * Get object classes of the ldap entry. The object classes are only required, if a new ldap entry
   * should be persisted.
   *
   * @return the object classes of the ldap entry
   */
  String[] getObjectClasses();

  @Override
  String mapDn(T domainObject);

  /**
   * Map a ldap entry into a domain object.
   *
   * @param ldapEntry the ldap entry
   * @return the domain object
   */
  T map(LdapEntry ldapEntry);

  @Override
  void map(LdapEntry source, T destination);

  @Override
  default void map(T source, LdapEntry destination) {
    mapAndComputeModifications(source, destination);
  }

  /**
   * Map and compute attribute modifications (see {@link LdapEntry#computeModifications(LdapEntry,
   * LdapEntry)}**).
   *
   * @param source the source (domain object)
   * @param destination the destination (ldap entry)
   * @return the attribute modifications
   */
  AttributeModification[] mapAndComputeModifications(
      @NotNull T source,
      @NotNull LdapEntry destination);

  /**
   * Map and compute modify request.
   *
   * @param source the source (domain object)
   * @param destination the destination (ldap entry)
   * @return the modify request
   */
  default ModifyRequest mapAndComputeModifyRequest(
      @NotNull T source,
      @NotNull LdapEntry destination) {
    return new ModifyRequest(destination.getDn(), mapAndComputeModifications(source, destination));
  }

  /**
   * Gets attribute value.
   *
   * @param <T> the type parameter
   * @param ldapEntry the ldap entry
   * @param name the name
   * @param valueTranscoder the value transcoder
   * @param defaultValue the default value
   * @return the attribute value
   */
  static <T> T getAttributeValue(
      LdapEntry ldapEntry,
      @NotNull String name,
      ValueTranscoder<T> valueTranscoder,
      T defaultValue) {
    LdapAttribute attr = ldapEntry == null ? null : ldapEntry.getAttribute(name);
    T value = attr != null ? attr.getValue(valueTranscoder.decoder()) : null;
    return value != null ? value : defaultValue;
  }

  /**
   * Gets attribute values.
   *
   * @param <T> the type parameter
   * @param ldapEntry the ldap entry
   * @param name the name
   * @param valueTranscoder the value transcoder
   * @return the attribute values
   */
  static <T> Collection<T> getAttributeValues(
      LdapEntry ldapEntry,
      @NotNull String name,
      ValueTranscoder<T> valueTranscoder) {
    LdapAttribute attr = ldapEntry == null ? null : ldapEntry.getAttribute(name);
    Collection<T> values = attr != null ? attr.getValues(valueTranscoder.decoder()) : null;
    return values != null ? values : new ArrayList<>();
  }

  /**
   * Gets attribute values as set.
   *
   * @param <T> the type parameter
   * @param ldapEntry the ldap entry
   * @param name the name
   * @param valueTranscoder the value transcoder
   * @return the attribute values as set
   */
  static <T> Set<T> getAttributeValuesAsSet(
      LdapEntry ldapEntry,
      @NotNull String name,
      ValueTranscoder<T> valueTranscoder) {
    return new LinkedHashSet<>(getAttributeValues(ldapEntry, name, valueTranscoder));
  }

  /**
   * Gets attribute values as list.
   *
   * @param <T> the type parameter
   * @param ldapEntry the ldap entry
   * @param name the name
   * @param valueTranscoder the value transcoder
   * @return the attribute values as list
   */
  static <T> List<T> getAttributeValuesAsList(
      LdapEntry ldapEntry,
      @NotNull String name,
      ValueTranscoder<T> valueTranscoder) {
    return new ArrayList<>(getAttributeValues(ldapEntry, name, valueTranscoder));
  }

  /**
   * Replaces the value of the attribute with the specified value.
   *
   * @param <T> the type of the domain object
   * @param ldapEntry the ldap entry
   * @param name the attribute name
   * @param value the attribute value
   * @param isBinary specifies whether the attribute value is binary or not
   * @param valueTranscoder the value transcoder (can be null if value is also null)
   * @param modifications the list of modifications
   */
  static <T> void setAttribute(
      @NotNull LdapEntry ldapEntry,
      @NotNull String name,
      T value,
      boolean isBinary,
      ValueTranscoder<T> valueTranscoder,
      @NotNull List<AttributeModification> modifications) {

    setAttributes(
        ldapEntry,
        name,
        value != null ? Collections.singleton(value) : null,
        isBinary,
        valueTranscoder,
        modifications);
  }

  /**
   * Replaces the values of the attribute with the specified values.
   *
   * @param <T> the type of the domain object
   * @param ldapEntry the ldap entry
   * @param name the attribute name
   * @param values the values of the attribute
   * @param isBinary specifies whether the attribute value is binary or not
   * @param valueTranscoder the value transcoder (can be null if values is also null)
   * @param modifications the list of modifications
   */
  static <T> void setAttributes(
      @NotNull LdapEntry ldapEntry,
      @NotNull String name,
      Collection<T> values,
      boolean isBinary,
      ValueTranscoder<T> valueTranscoder,
      @NotNull List<AttributeModification> modifications) {

    Collection<T> realValues = values == null ? null : values.stream()
        .filter(value -> {
          if (value instanceof CharSequence) {
            return ((CharSequence) value).length() > 0;
          }
          return value != null;
        })
        .collect(Collectors.toList());
    LdapAttribute attr = ldapEntry.getAttribute(name);
    if (attr == null && realValues != null && !realValues.isEmpty()) {
      addAttributes(ldapEntry, name, realValues, isBinary, valueTranscoder, modifications);
    } else if (attr != null) {
      if (realValues == null || realValues.isEmpty()) {
        ldapEntry.removeAttribute(name);
        modifications.add(
            new AttributeModification(
                Type.DELETE,
                attr));
      } else if (!new ArrayList<>(realValues)
          .equals(new ArrayList<>(attr.getValues(valueTranscoder.decoder())))) {
        LdapAttribute newAttr = new LdapAttribute();
        newAttr.setBinary(isBinary);
        newAttr.setName(name);
        newAttr.addValues(valueTranscoder.encoder(), realValues);
        ldapEntry.addAttributes(newAttr);
        modifications.add(
            new AttributeModification(
                Type.REPLACE,
                newAttr));
      }
    }
  }

  /**
   * Adds the specified value to the attribute with the specified name.
   *
   * @param <T> the type of the domain object
   * @param ldapEntry the ldap entry
   * @param name the attribute name
   * @param value the attribute value
   * @param isBinary specifies whether the attribute value is binary or not
   * @param valueTranscoder the value transcoder
   * @param modifications the list of modifications
   */
  static <T> void addAttribute(
      @NotNull LdapEntry ldapEntry,
      @NotNull String name,
      T value,
      boolean isBinary,
      @NotNull ValueTranscoder<T> valueTranscoder,
      @NotNull List<AttributeModification> modifications) {
    addAttributes(
        ldapEntry,
        name,
        value != null ? Collections.singleton(value) : null,
        isBinary,
        valueTranscoder,
        modifications);
  }

  /**
   * Adds the specified values to the attribute with the specified name.
   *
   * @param <T> the type of the domain object
   * @param ldapEntry the ldap entry
   * @param name the attribute name
   * @param values the attribute values
   * @param isBinary specifies whether the attribute value is binary or not
   * @param valueTranscoder the value transcoder
   * @param modifications the list of modifications
   */
  static <T> void addAttributes(
      @NotNull LdapEntry ldapEntry,
      @NotNull String name,
      Collection<T> values,
      boolean isBinary,
      @NotNull ValueTranscoder<T> valueTranscoder,
      @NotNull List<AttributeModification> modifications) {
    Collection<T> realValues = values == null ? null : values.stream()
        .filter(value -> {
          if (value instanceof CharSequence) {
            return ((CharSequence) value).length() > 0;
          }
          return value != null;
        })
        .collect(Collectors.toList());
    if (realValues == null || realValues.isEmpty()) {
      return;
    }
    LdapAttribute attr = ldapEntry.getAttribute(name);
    if (attr == null) {
      LdapAttribute newAttr = new LdapAttribute();
      newAttr.setBinary(isBinary);
      newAttr.setName(name);
      newAttr.addValues(valueTranscoder.encoder(), realValues);
      ldapEntry.addAttributes(newAttr);
      modifications.add(
          new AttributeModification(
              Type.ADD,
              newAttr));
    } else {
      List<T> newValues = new ArrayList<>(
          getAttributeValues(ldapEntry, name, valueTranscoder));
      newValues.addAll(realValues);
      setAttributes(ldapEntry, name, newValues, attr.isBinary(), valueTranscoder, modifications);
    }
  }

  /**
   * Removes an attribute with the specified name.
   *
   * @param ldapEntry the ldap entry
   * @param name the name
   * @param modifications the modifications
   */
  static void removeAttribute(
      @NotNull LdapEntry ldapEntry,
      @NotNull String name,
      @NotNull List<AttributeModification> modifications) {
    LdapAttribute attr = ldapEntry.getAttribute(name);
    if (attr == null) {
      return;
    }
    ldapEntry.removeAttributes(attr);
    modifications.add(
        new AttributeModification(
            Type.DELETE,
            attr));
  }

  /**
   * Removes an attribute with the specified value. If the value is {@code null}, the whole
   * attribute will be removed.
   *
   * @param <T> the type of the domain object
   * @param ldapEntry the ldap entry
   * @param name the name
   * @param value the value
   * @param valueTranscoder the value transcoder
   * @param modifications the modifications
   */
  static <T> void removeAttribute(
      @NotNull LdapEntry ldapEntry,
      @NotNull String name,
      T value,
      ValueTranscoder<T> valueTranscoder,
      @NotNull List<AttributeModification> modifications) {
    LdapAttribute attr = ldapEntry.getAttribute(name);
    if (attr == null) {
      return;
    }
    if (value == null) {
      removeAttribute(ldapEntry, name, modifications);
    } else {
      removeAttributes(ldapEntry, name, Collections.singleton(value), valueTranscoder,
          modifications);
    }
  }

  /**
   * Remove attributes with the specified values. If values are empty or {@code null}, no attributes
   * will be removed.
   *
   * @param <T> the type of the domain object
   * @param ldapEntry the ldap entry
   * @param name the name
   * @param values the values
   * @param valueTranscoder the value transcoder
   * @param modifications the modifications
   */
  static <T> void removeAttributes(
      @NotNull LdapEntry ldapEntry,
      @NotNull String name,
      Collection<T> values,
      ValueTranscoder<T> valueTranscoder,
      @NotNull List<AttributeModification> modifications) {

    LdapAttribute attr = ldapEntry.getAttribute(name);
    if (attr == null || values == null || values.isEmpty()) {
      return;
    }
    List<T> newValues = new ArrayList<>(getAttributeValues(ldapEntry, name, valueTranscoder));
    newValues.removeAll(values);
    setAttributes(ldapEntry, name, newValues, attr.isBinary(), valueTranscoder, modifications);
  }

  /**
   * Create dn string.
   *
   * @param rdn the rdn
   * @param rdnValue the rdn value
   * @param baseDn the base dn
   * @return the string
   */
  static String createDn(
      @NotNull String rdn,
      @NotNull String rdnValue,
      @NotNull String baseDn) {
    return rdn + "=" + rdnValue + "," + baseDn;
  }

  /**
   * Gets rdn.
   *
   * @param dn the dn
   * @return the rdn
   */
  static String getRdn(String dn) {
    if (dn == null) {
      return null;
    }
    int start = dn.indexOf('=');
    if (start < 0) {
      return dn;
    }
    int end = dn.indexOf(',', start);
    if (end < 0) {
      return dn.substring(start + 1).trim();
    }
    return dn.substring(start + 1, end).trim();
  }

}
