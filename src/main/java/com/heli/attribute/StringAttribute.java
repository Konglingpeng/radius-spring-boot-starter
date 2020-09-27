package com.heli.attribute;

import java.nio.charset.StandardCharsets;

/**
 * This class represents a Radius attribute which only
 * contains a string.
 */
public class StringAttribute extends RadiusAttribute {

	/**
	 * Constructs an empty string attribute.
	 */
	public StringAttribute() {
	}
	
	/**
	 * Constructs a string attribute with the given value.
	 * @param type attribute type
	 * @param value attribute value
	 */
	public StringAttribute(int type, String value) {
		setAttributeType(type);
		setAttributeValue(value);
	}
	
	/**
	 * Returns the string value of this attribute.
	 * @return a string
	 */
	public String getAttributeValue() {
		return new String(getAttributeData(), StandardCharsets.UTF_8);
	}
	
	/**
	 * Sets the string value of this attribute.
	 * @param value string, not null
	 */
	public void setAttributeValue(String value) {
		if (value == null)
			throw new NullPointerException("string value not set");
		setAttributeData(value.getBytes(StandardCharsets.UTF_8));
	}
	
}
