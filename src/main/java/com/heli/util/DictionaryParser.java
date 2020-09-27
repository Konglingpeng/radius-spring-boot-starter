package com.heli.util;

import com.heli.attribute.*;

/**
 * Parses a dictionary in "Radiator format" and fills a
 * WritableDictionary.
 */
public class DictionaryParser {
	private DictionaryParser() {
	}

	/**
	 * Returns the RadiusAttribute descendant class for the given
	 * attribute type.
	 * 
	 * @param attributeType
	 * 
	 * @param typeStr
	 *            string|octets|integer|date|ipaddr|ipv6addr|ipv6prefix
	 * @return RadiusAttribute class or descendant
	 */
	public static Class<?> getAttributeTypeClass(String typeStr) {
		Class<?> type = RadiusAttribute.class;
		if (typeStr.equalsIgnoreCase("string"))
			type = StringAttribute.class;
		else if (typeStr.equalsIgnoreCase("octets"))
			type = RadiusAttribute.class;
		else if (typeStr.equalsIgnoreCase("integer") || typeStr.equalsIgnoreCase("date"))
			type = IntegerAttribute.class;
		else if (typeStr.equalsIgnoreCase("ipaddr"))
			type = IpAttribute.class;
		else if (typeStr.equalsIgnoreCase("ipv6addr"))
			type = Ipv6Attribute.class;
		else if (typeStr.equalsIgnoreCase("ipv6prefix"))
			type = Ipv6PrefixAttribute.class;
		return type;
	}

}
