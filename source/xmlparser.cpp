/*
 * Copyright (c) 2022-2026 Samuel Ugochukwu <sammycageagle@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "xmlparser.h"
#include "xmldocument.h"
#include "plutobook.hpp"

// Requests the expat.h prototypes for the billion-laughs protection setters
// (V16, see below): expat.h only declares them when XML_DTD or XML_GE is
// defined by the includer, matching how the linked libexpat was itself built
// (Debian/bundled expat >= 2.4.0 both export these symbols). This does not
// enable DTD/external/parameter-entity parsing by itself -- no such handler
// is registered in this file -- it only unlocks the two prototypes used
// below to harden internal entity expansion.
#ifndef XML_GE
#define XML_GE 1
#endif
#include <expat.h>

namespace plutobook {

XMLParser::XMLParser(XMLDocument* document)
    : m_document(document)
    , m_currentNode(document)
{
}

inline XMLParser* getParser(void* userData)
{
    return (XMLParser*)(userData);
}

static void startElementCallback(void* userData, const XML_Char* name, const XML_Char** attrs)
{
    getParser(userData)->handleStartElement((const char*)(name), (const char**)(attrs));
}

static void endElementCallback(void* userData, const XML_Char* name)
{
    getParser(userData)->handleEndElement((const char*)(name));
}

static void characterDataCallback(void* userData, const XML_Char* data, int length)
{
    getParser(userData)->handleCharacterData((const char*)(data), (size_t)(length));
}

constexpr XML_Char kXmlNamespaceSep = '|';

bool XMLParser::parse(std::string_view content)
{
    auto parser = XML_ParserCreateNS(NULL, kXmlNamespaceSep);
    XML_SetUserData(parser, this);
    XML_SetElementHandler(parser, startElementCallback, endElementCallback);
    XML_SetCharacterDataHandler(parser, characterDataCallback);

    // Billion-laughs (internal entity expansion) defense-in-depth (V16). expat
    // enables this protection by default from 2.4.0 onward, and meson.build
    // already requires expat >= 2.4.0 -- but set the thresholds explicitly
    // rather than relying solely on expat's built-in defaults, in case a
    // vendored/patched expat ships different defaults. No external-entity or
    // parameter-entity handler is registered above/below, so XXE stays
    // unreachable; this only bounds internal entity expansion.
#if defined(XML_MAJOR_VERSION) && (XML_MAJOR_VERSION > 2 || (XML_MAJOR_VERSION == 2 && XML_MINOR_VERSION >= 4))
    XML_SetBillionLaughsAttackProtectionMaximumAmplification(parser, 100.0f);
    XML_SetBillionLaughsAttackProtectionActivationThreshold(parser, 8 * 1024 * 1024);
#endif

    auto status = XML_Parse(parser, content.data(), content.length(), XML_TRUE);
    if(status == XML_STATUS_OK) {
        m_document->finishParsingDocument();
        XML_ParserFree(parser);
        return true;
    }

    auto errorString = (const char*)(XML_ErrorString(XML_GetErrorCode(parser)));
    auto lineNumber = (int)(XML_GetCurrentLineNumber(parser));
    auto columnNumber = (int)(XML_GetCurrentColumnNumber(parser));
    plutobook_set_error_message("xml parse error: %s on line %d column %d", errorString, lineNumber, columnNumber);
    XML_ParserFree(parser);
    return false;
}

class QualifiedName {
public:
    QualifiedName(const GlobalString& namespaceURI, const GlobalString& localName)
        : m_namespaceURI(namespaceURI), m_localName(localName)
    {}

    const GlobalString& namespaceURI() const { return m_namespaceURI; }
    const GlobalString& localName() const { return m_localName; }

    static QualifiedName parse(std::string_view name);

private:
    GlobalString m_namespaceURI;
    GlobalString m_localName;
};

QualifiedName QualifiedName::parse(std::string_view name)
{
    auto index = name.rfind(kXmlNamespaceSep);
    if(index == std::string_view::npos)
        return QualifiedName(emptyGlo, GlobalString(name));
    GlobalString namespaceURI(name.substr(0, index));
    GlobalString localName(name.substr(index + 1));
    return QualifiedName(namespaceURI, localName);
}

void XMLParser::handleStartElement(const char* name, const char** attrs)
{
    auto tagName = QualifiedName::parse(name);
    auto element = m_document->createElement(tagName.namespaceURI(), tagName.localName());
    while(attrs && *attrs) {
        auto attrName = QualifiedName::parse(attrs[0]);
        auto attrValue = m_document->heap()->createString(attrs[1]);
        element->setAttribute(attrName.localName(), attrValue);
        attrs += 2;
    }

    element->setIsCaseSensitive(true);
    m_currentNode->appendChild(element);

    // Bounds the DOM nesting depth built here against EngineLimits::maxNestingDepth() (V08): expat's
    // start/end element handlers are not themselves recursive, but every element is appended as a
    // child of m_currentNode and then descended into unconditionally, so nothing otherwise stops the
    // resulting DOM from nesting as deep as the input does -- which later, purely recursive passes
    // (Document::finishParsingDocument(), layout, paint, destruction) must walk by depth. m_depth
    // tracks the *true* nesting depth symmetrically across every start/end pair (expat guarantees
    // they are well-formed/balanced), independent of the cap, so handleEndElement() below can tell
    // whether a given end tag's matching start had descended into its element and undo exactly that.
    ++m_depth;
    auto maxDepth = engineLimits()->maxNestingDepth();
    if(!maxDepth || m_depth <= maxDepth)
        m_currentNode = element;
    // Otherwise: element is already in the DOM (appended above), preserving its content, but
    // m_currentNode is left pointing at the ancestor at the cap, so further elements -- until a
    // matching end tag brings m_depth back down to the cap -- become its siblings instead of
    // descendants, flattening the excess nesting rather than growing the tree deeper.
}

void XMLParser::handleEndElement(const char* name)
{
    auto maxDepth = engineLimits()->maxNestingDepth();
    if(!maxDepth || m_depth <= maxDepth)
        m_currentNode = m_currentNode->parentNode();
    --m_depth;
}

void XMLParser::handleCharacterData(const char* data, size_t length)
{
    std::string_view content(data, length);
    if(auto lastTextNode = to<TextNode>(m_currentNode->lastChild())) {
        lastTextNode->appendData(content);
    } else {
        m_currentNode->appendChild(m_document->createTextNode(content));
    }
}

} // namespace plutobook
