/*
 * Copyright (c) 2022-2026 Samuel Ugochukwu <sammycageagle@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef PLUTOBOOK_XMLPARSER_H
#define PLUTOBOOK_XMLPARSER_H

#include <cstdint>
#include <string_view>

namespace plutobook {

class XMLDocument;
class ContainerNode;

class XMLParser {
public:
    explicit XMLParser(XMLDocument* document);

    bool parse(std::string_view content);

    void handleStartNamespace(const char* prefix, const char* uri);
    void handleEndNamespace(const char* prefix);

    void handleStartElement(const char* name, const char** attrs);
    void handleEndElement(const char* name);
    void handleCharacterData(const char* data, size_t length);

private:
    XMLDocument* m_document;
    ContainerNode* m_currentNode;
    // True current element depth, tracked independently of whether m_currentNode actually descended
    // into each element -- see handleStartElement()/handleEndElement() (V08).
    uint32_t m_depth{0};
};

} // namespace plutobook

#endif // PLUTOBOOK_SVGPARSER_H
