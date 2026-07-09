/*
 * Copyright (c) 2022-2026 Samuel Ugochukwu <sammycageagle@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "htmlparser.h"
#include "htmldocument.h"
#include "stringutils.h"
#include "plutobook.hpp"

namespace plutobook {

inline bool isNumberedHeaderTag(const GlobalString& tagName)
{
    return tagName == h1Tag
        || tagName == h2Tag
        || tagName == h3Tag
        || tagName == h4Tag
        || tagName == h5Tag
        || tagName == h6Tag;
}

inline bool isImpliedEndTag(const GlobalString& tagName)
{
    return tagName == ddTag
        || tagName == dtTag
        || tagName == liTag
        || tagName == optionTag
        || tagName == optgroupTag
        || tagName == pTag
        || tagName == rpTag
        || tagName == rtTag;
}

inline bool isFosterRedirectingTag(const GlobalString& tagName)
{
    return tagName == tableTag
        || tagName == tbodyTag
        || tagName == theadTag
        || tagName == trTag;
}

inline bool isNumberedHeaderElement(const Element* element)
{
    return isNumberedHeaderTag(element->tagName());
}

inline bool isSpecialElement(const Element* element)
{
    const auto& tagName = element->tagName();
    if(element->namespaceURI() == svgNs) {
        return tagName == foreignObjectTag
            || tagName == descTag
            || tagName == titleTag;
    }

    if(element->namespaceURI() == mathmlNs) {
        return tagName == miTag
            || tagName == moTag
            || tagName == mnTag
            || tagName == msTag
            || tagName == mtextTag
            || tagName == annotation_xmlTag;
    }

    return tagName == addressTag
        || tagName == appletTag
        || tagName == areaTag
        || tagName == articleTag
        || tagName == asideTag
        || tagName == baseTag
        || tagName == basefontTag
        || tagName == bgsoundTag
        || tagName == blockquoteTag
        || tagName == bodyTag
        || tagName == brTag
        || tagName == buttonTag
        || tagName == captionTag
        || tagName == centerTag
        || tagName == colTag
        || tagName == colgroupTag
        || tagName == commandTag
        || tagName == ddTag
        || tagName == detailsTag
        || tagName == dirTag
        || tagName == divTag
        || tagName == dlTag
        || tagName == dtTag
        || tagName == embedTag
        || tagName == fieldsetTag
        || tagName == figcaptionTag
        || tagName == figureTag
        || tagName == footerTag
        || tagName == formTag
        || tagName == frameTag
        || tagName == framesetTag
        || isNumberedHeaderTag(tagName)
        || tagName == headTag
        || tagName == headerTag
        || tagName == hgroupTag
        || tagName == hrTag
        || tagName == htmlTag
        || tagName == iframeTag
        || tagName == imgTag
        || tagName == inputTag
        || tagName == liTag
        || tagName == linkTag
        || tagName == listingTag
        || tagName == mainTag
        || tagName == marqueeTag
        || tagName == menuTag
        || tagName == metaTag
        || tagName == navTag
        || tagName == noembedTag
        || tagName == noframesTag
        || tagName == noscriptTag
        || tagName == objectTag
        || tagName == olTag
        || tagName == pTag
        || tagName == paramTag
        || tagName == plaintextTag
        || tagName == preTag
        || tagName == scriptTag
        || tagName == sectionTag
        || tagName == selectTag
        || tagName == styleTag
        || tagName == summaryTag
        || tagName == tableTag
        || tagName == tbodyTag
        || tagName == tdTag
        || tagName == textareaTag
        || tagName == tfootTag
        || tagName == thTag
        || tagName == theadTag
        || tagName == titleTag
        || tagName == trTag
        || tagName == ulTag
        || tagName == wbrTag
        || tagName == xmpTag;
}

inline bool isHTMLIntegrationPoint(const Element* element)
{
    if(element->namespaceURI() == mathmlNs
        && element->tagName() == annotation_xmlTag) {
        auto attribute = element->findAttribute(encodingAttr);
        if(attribute == nullptr)
            return false;
        const auto& encoding = attribute->value();
        return equals(encoding, "text/html", false)
            || equals(encoding, "application/xhtml+xml", false);
    }

    if(element->namespaceURI() == svgNs) {
        return element->tagName() == foreignObjectTag
            || element->tagName() == descTag
            || element->tagName() == titleTag;
    }

    return false;
}

inline bool isMathMLTextIntegrationPoint(const Element* element)
{
    if(element->namespaceURI() == mathmlNs) {
        return element->tagName() == miTag
            || element->tagName() == moTag
            || element->tagName() == mnTag
            || element->tagName() == msTag
            || element->tagName() == mtextTag;
    }

    return false;
}

inline bool isScopeMarker(const Element* element)
{
    const auto& tagName = element->tagName();
    if(element->namespaceURI() == svgNs) {
        return tagName == foreignObjectTag
            || tagName == descTag
            || tagName == titleTag;
    }

    if(element->namespaceURI() == mathmlNs) {
        return tagName == miTag
            || tagName == moTag
            || tagName == mnTag
            || tagName == msTag
            || tagName == mtextTag
            || tagName == annotation_xmlTag;
    }

    return tagName == captionTag
        || tagName == marqueeTag
        || tagName == objectTag
        || tagName == tableTag
        || tagName == tdTag
        || tagName == thTag
        || tagName == htmlTag;
}

inline bool isListItemScopeMarker(const Element* element)
{
    return isScopeMarker(element)
        || element->tagName() == olTag
        || element->tagName() == ulTag;
}

inline bool isTableScopeMarker(const Element* element)
{
    return element->tagName() == tableTag
        || element->tagName() == htmlTag;
}

inline bool isTableBodyScopeMarker(const Element* element)
{
    return element->tagName() == tbodyTag
        || element->tagName() == tfootTag
        || element->tagName() == theadTag
        || element->tagName() == htmlTag;
}

inline bool isTableRowScopeMarker(const Element* element)
{
    return element->tagName() == trTag
        || element->tagName() == htmlTag;
}

inline bool isForeignContentScopeMarker(const Element* element)
{
    return isMathMLTextIntegrationPoint(element)
        || isHTMLIntegrationPoint(element)
        || element->namespaceURI() == xhtmlNs;
}

inline bool isButtonScopeMarker(const Element* element)
{
    return isScopeMarker(element)
        || element->tagName() == buttonTag;
}

inline bool isSelectScopeMarker(const Element* element)
{
    return element->tagName() != optgroupTag
        && element->tagName() != optionTag;
}

void HTMLElementList::remove(const Element* element)
{
    remove(index(element));
}

void HTMLElementList::remove(size_t index)
{
    assert(index < m_elements.size());
    m_elements.erase(m_elements.begin() + index);
}

void HTMLElementList::replace(const Element* element, Element* item)
{
    replace(index(element), item);
}

void HTMLElementList::replace(size_t index, Element* element)
{
    m_elements.at(index) = element;
}

void HTMLElementList::insert(size_t index, Element* element)
{
    assert(index <= m_elements.size());
    m_elements.insert(m_elements.begin() + index, element);
}

size_t HTMLElementList::index(const Element* element) const
{
    for(int i = m_elements.size() - 1; i >= 0; --i) {
        if(element == m_elements.at(i)) {
            return i;
        }
    }

    assert(false);
    return 0;
}

bool HTMLElementList::contains(const Element* element) const
{
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    for(; it != end; ++it) {
        if(element == *it) {
            return true;
        }
    }

    return false;
}

void HTMLElementStack::push(Element* element)
{
    assert(element->tagName() != htmlTag);
    assert(element->tagName() != headTag);
    assert(element->tagName() != bodyTag);
    // Capping this stack is the caller's job (V08): see HTMLParser::pushElement(), which decides
    // *whether* to call this at all. HTMLElementStack itself stays a plain, unbounded container --
    // it has no notion of EngineLimits -- so that every push it does receive keeps the HTML5
    // tree-construction invariants (scope checks, insertion-mode transitions, ...) consistent.
    m_elements.push_back(element);
}

void HTMLElementStack::pushHTMLHtmlElement(Element* element)
{
    assert(element->tagName() == htmlTag);
    assert(m_htmlElement == nullptr);
    assert(m_elements.empty());
    m_htmlElement = element;
    m_elements.push_back(element);
}

void HTMLElementStack::pushHTMLHeadElement(Element* element)
{
    assert(element->tagName() == headTag);
    assert(m_headElement == nullptr);
    m_headElement = element;
    m_elements.push_back(element);
}

void HTMLElementStack::pushHTMLBodyElement(Element* element)
{
    assert(element->tagName() == bodyTag);
    assert(m_bodyElement == nullptr);
    m_bodyElement = element;
    m_elements.push_back(element);
}

void HTMLElementStack::pop()
{
    auto element = m_elements.back();
    assert(element->tagName() != htmlTag);
    assert(element->tagName() != headTag);
    assert(element->tagName() != bodyTag);
    m_elements.pop_back();
}

void HTMLElementStack::popHTMLHeadElement()
{
    auto element = m_elements.back();
    assert(element == m_headElement);
    m_headElement = nullptr;
    m_elements.pop_back();
}

void HTMLElementStack::popHTMLBodyElement()
{
    auto element = m_elements.back();
    assert(element == m_bodyElement);
    m_bodyElement = nullptr;
    m_elements.pop_back();
}

void HTMLElementStack::popUntil(const GlobalString& tagName)
{
    while(tagName != top()->tagName()) {
        pop();
    }
}

void HTMLElementStack::popUntil(const Element* element)
{
    while(element != top()) {
        pop();
    }
}

void HTMLElementStack::popUntilNumberedHeaderElement()
{
    while(!isNumberedHeaderElement(top())) {
        pop();
    }
}

void HTMLElementStack::popUntilTableScopeMarker()
{
    while(!isTableScopeMarker(top())) {
        pop();
    }
}

void HTMLElementStack::popUntilTableBodyScopeMarker()
{
    while(!isTableBodyScopeMarker(top())) {
        pop();
    }
}

void HTMLElementStack::popUntilTableRowScopeMarker()
{
    while(!isTableRowScopeMarker(top())) {
        pop();
    }
}

void HTMLElementStack::popUntilForeignContentScopeMarker()
{
    while(!isForeignContentScopeMarker(top())) {
        pop();
    }
}

void HTMLElementStack::popUntilPopped(const GlobalString& tagName)
{
    popUntil(tagName);
    pop();
}

void HTMLElementStack::popUntilPopped(const Element* element)
{
    popUntil(element);
    pop();
}

void HTMLElementStack::popUntilNumberedHeaderElementPopped()
{
    popUntilNumberedHeaderElement();
    pop();
}

void HTMLElementStack::popAll()
{
    m_htmlElement = nullptr;
    m_headElement = nullptr;
    m_bodyElement = nullptr;
    m_elements.clear();
}

void HTMLElementStack::generateImpliedEndTags()
{
    while(isImpliedEndTag(top()->tagName())) {
        pop();
    }
}

void HTMLElementStack::generateImpliedEndTagsExcept(const GlobalString& tagName)
{
    while(top()->tagName() != tagName && isImpliedEndTag(top()->tagName())) {
        pop();
    }
}

void HTMLElementStack::removeHTMLHeadElement(const Element* element)
{
    if(element == top())
        return popHTMLHeadElement();
    assert(m_headElement == element);
    m_headElement = nullptr;
    remove(index(element));
}

void HTMLElementStack::removeHTMLBodyElement()
{
    assert(m_htmlElement != nullptr);
    assert(m_bodyElement != nullptr);
    auto element = m_bodyElement;
    m_htmlElement->removeChild(m_bodyElement);
    popUntil(m_bodyElement);
    popHTMLBodyElement();
    assert(m_htmlElement == top());
    delete element;
}

void HTMLElementStack::insertAfter(const Element* element, Element* item)
{
    insert(index(element) + 1, item);
}

Element* HTMLElementStack::furthestBlockForFormattingElement(const Element* formattingElement) const
{
    Element* furthestBlock = nullptr;
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    for(; it != end; ++it) {
        if(formattingElement == *it)
            return furthestBlock;
        if(!isSpecialElement(*it))
            continue;
        furthestBlock = *it;
    }

    assert(false);
    return nullptr;
}

Element* HTMLElementStack::topmost(const GlobalString& tagName) const
{
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    for(; it != end; ++it) {
        auto element = *it;
        if(tagName == element->tagName()) {
            return element;
        }
    }

    return nullptr;
}

Element* HTMLElementStack::previous(const Element* element) const
{
    return m_elements.at(index(element) - 1);
}

template<bool isMarker(const Element*)>
bool HTMLElementStack::inScopeTemplate(const GlobalString& tagName) const
{
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    for(; it != end; ++it) {
        auto element = *it;
        if(element->tagName() == tagName)
            return true;
        if(isMarker(element)) {
            return false;
        }
    }

    assert(false);
    return false;
}

bool HTMLElementStack::inScope(const Element* element) const
{
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    for(; it != end; ++it) {
        if(element == *it)
            return true;
        if(isScopeMarker(*it)) {
            return false;
        }
    }

    assert(false);
    return false;
}

bool HTMLElementStack::inScope(const GlobalString& tagName) const
{
    return inScopeTemplate<isScopeMarker>(tagName);
}

bool HTMLElementStack::inButtonScope(const GlobalString& tagName) const
{
    return inScopeTemplate<isButtonScopeMarker>(tagName);
}

bool HTMLElementStack::inListItemScope(const GlobalString& tagName) const
{
    return inScopeTemplate<isListItemScopeMarker>(tagName);
}

bool HTMLElementStack::inTableScope(const GlobalString& tagName) const
{
    return inScopeTemplate<isTableScopeMarker>(tagName);
}

bool HTMLElementStack::inSelectScope(const GlobalString& tagName) const
{
    return inScopeTemplate<isSelectScopeMarker>(tagName);
}

bool HTMLElementStack::isNumberedHeaderElementInScope() const
{
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    for(; it != end; ++it) {
        if(isNumberedHeaderElement(*it))
            return true;
        if(isScopeMarker(*it)) {
            return false;
        }
    }

    assert(false);
    return false;
}

void HTMLFormattingElementList::append(Element* element)
{
    assert(element != nullptr);
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    int count = 0;
    for(; it != end; ++it) {
        auto item = *it;
        if(item == nullptr)
            break;
        if(element->tagName() == item->tagName()
            && element->namespaceURI() == item->namespaceURI()
            && element->attributes() == item->attributes()) {
            count += 1;
        }

        if(count == 3) {
            remove(*it);
            break;
        }
    }

    m_elements.push_back(element);
}

void HTMLFormattingElementList::appendMarker()
{
    m_elements.push_back(nullptr);
}

void HTMLFormattingElementList::clearToLastMarker()
{
    while(!m_elements.empty()) {
        auto element = m_elements.back();
        m_elements.pop_back();
        if(element == nullptr) {
            break;
        }
    }
}

Element* HTMLFormattingElementList::closestElementInScope(const GlobalString& tagName)
{
    auto it = m_elements.rbegin();
    auto end = m_elements.rend();
    for(; it != end; ++it) {
        auto element = *it;
        if(element == nullptr)
            break;
        if(element->tagName() == tagName) {
            return element;
        }
    }

    return nullptr;
}

HTMLParser::HTMLParser(HTMLDocument* document, std::string_view content)
    : m_document(document), m_tokenizer(content, document->heap())
{
}

bool HTMLParser::parse()
{
    while(!m_tokenizer.atEOF()) {
        auto token = m_tokenizer.nextToken();
        if(token.type() == HTMLToken::Type::DOCTYPE) {
            handleDoctypeToken(token);
            continue;
        }

        if(token.type() == HTMLToken::Type::Comment) {
            handleCommentToken(token);
            continue;
        }

        if(m_skipLeadingNewline
            && token.type() == HTMLToken::Type::SpaceCharacter) {
            token.skipLeadingNewLine();
        }

        m_skipLeadingNewline = false;
        handleToken(token, currentInsertionMode(token));
    }

    assert(!m_openElements.empty());
    m_openElements.popAll();
    m_document->finishParsingDocument();
    return true;
}

Element* HTMLParser::createHTMLElement(const HTMLTokenView& token) const
{
    return createElement(token, xhtmlNs);
}

Element* HTMLParser::createElement(const HTMLTokenView& token, const GlobalString& namespaceURI) const
{
    auto element = m_document->createElement(namespaceURI, token.tagName());
    element->setIsCaseSensitive(!token.hasCamelCase());
    for(const auto& attribute : token.attributes())
        element->setAttribute(attribute);
    return element;
}

Element* HTMLParser::cloneElement(const Element* element) const
{
    auto newElement = m_document->createElement(element->namespaceURI(), element->tagName());
    newElement->setIsCaseSensitive(element->isCaseSensitive());
    newElement->setAttributes(element->attributes());
    return newElement;
}

void HTMLParser::insertNode(const InsertionLocation& location, Node* child)
{
    if(location.nextChild) {
        location.parent->insertChild(child, location.nextChild);
    } else {
        location.parent->appendChild(child);
    }
}

void HTMLParser::insertElement(Element* child, ContainerNode* parent)
{
    InsertionLocation location;
    location.parent = parent;
    if(shouldFosterParent())
        findFosterLocation(location);
    insertNode(location, child);
}

void HTMLParser::insertElement(Element* child)
{
    insertElement(child, currentElement());
}

bool HTMLParser::pushElement(Element* element, bool bounded)
{
    // Bounds the open-elements stack itself against EngineLimits::maxNestingDepth() (V08). This stack
    // is scanned from top to bottom by essentially every scope check (inScope(), inTableScope(),
    // inButtonScope(), ...), which run on close to every token; for a long chain of elements with no
    // intervening scope marker (e.g. <div> x N), each such scan costs O(current depth), so letting the
    // stack grow without bound turns parsing of deeply nested input into an O(n^2) operation -- this is
    // what previously made an attachment-only depth cap (bounding only *where* elements land in the
    // DOM, while this stack kept growing) insufficient: it stopped the stack-overflow crash but not the
    // quadratic-time hang.
    //
    // Once the stack already holds maxNestingDepth() elements, refuse to push further ones. The caller
    // (insertHTMLElement() et al.) has already attached `element` to the DOM by the time it calls this,
    // so its content is preserved either way -- it just isn't tracked as "open": it becomes a flattened
    // sibling of the element at the cap instead of its descendant, which is what keeps this stack, and
    // therefore every scan over it, bounded from here on. Callers that also transition the insertion
    // mode alongside pushing (entering table/select/frameset/... context) must gate that transition on
    // this returning true, so the state machine never claims to be "inside" an element that in fact
    // never made it onto the stack -- which is what keeps later scope-check asserts (e.g. "a <td>/<th>
    // is in table scope while in InCell mode") consistent with what is really open.
    //
    // `bounded` is false for elements that switch the tokenizer into RCDATA/RAWTEXT/script-data state
    // (title, style, script, textarea, xmp, iframe, noembed -- see handleRCDataToken()/
    // handleRawTextToken()/handleScriptDataToken()): while consuming their content, the tokenizer
    // recognizes nothing but their own matching end tag, so they can never contain a further nested
    // start tag of their own kind. They cannot be chained to defeat this cap, so exempting them from it
    // is safe, and it avoids having to track -- across arbitrarily many intervening character tokens --
    // whether a later end tag's matching start had itself been capped.
    if(bounded) {
        auto maxDepth = engineLimits()->maxNestingDepth();
        if(maxDepth && m_openElements.size() >= maxDepth)
            return false;
    }

    m_openElements.push(element);
    return true;
}

bool HTMLParser::shouldFosterParent() const
{
    return m_fosterRedirecting && isFosterRedirectingTag(currentElement()->tagName());
}

void HTMLParser::findFosterLocation(InsertionLocation& location) const
{
    auto lastTable = m_openElements.topmost(tableTag);
    assert(lastTable && lastTable->parentNode());
    location.parent = lastTable->parentNode();
    location.nextChild = lastTable;
}

void HTMLParser::fosterParent(Node* child)
{
    InsertionLocation location;
    findFosterLocation(location);
    insertNode(location, child);
}

void HTMLParser::reconstructActiveFormattingElements()
{
    if(m_activeFormattingElements.empty())
        return;
    auto index = m_activeFormattingElements.size();
    do {
        index -= 1;
        auto element = m_activeFormattingElements.at(index);
        if(element == nullptr || m_openElements.contains(element)) {
            index += 1;
            break;
        }
    } while(index > 0);
    for(; index < m_activeFormattingElements.size(); ++index) {
        auto element = m_activeFormattingElements.at(index);
        auto newElement = cloneElement(element);
        insertElement(newElement);
        if(!pushElement(newElement))
            break; // At the depth cap (V08): stop reconstructing further rather than growing the stack.
        m_activeFormattingElements.replace(index, newElement);
    }
}

void HTMLParser::flushPendingTableCharacters()
{
    for(auto cc : m_pendingTableCharacters) {
        if(isSpace(cc))
            continue;
        reconstructActiveFormattingElements();
        m_fosterRedirecting = true;
        insertTextNode(m_pendingTableCharacters);
        m_fosterRedirecting = false;
        m_framesetOk = false;
        m_insertionMode = m_originalInsertionMode;
        return;
    }

    insertTextNode(m_pendingTableCharacters);
    m_insertionMode = m_originalInsertionMode;
}

void HTMLParser::closeTheCell()
{
    if(m_openElements.inTableScope(tdTag)) {
        assert(!m_openElements.inTableScope(thTag));
        handleFakeEndTagToken(tdTag);
        return;
    }

    assert(m_openElements.inTableScope(thTag));
    handleFakeEndTagToken(thTag);
}

void HTMLParser::adjustSVGTagNames(HTMLTokenView& token)
{
    static const std::map<GlobalString, GlobalString> table = {
        {"altglyph"_glo, "altGlyph"_glo},
        {"altglyphdef"_glo, "altGlyphDef"_glo},
        {"altglyphitem"_glo, "altGlyphItem"_glo},
        {"animatecolor"_glo, "animateColor"_glo},
        {"animatemotion"_glo, "animateMotion"_glo},
        {"animatetransform"_glo, "animateTransform"_glo},
        {"clippath"_glo, "clipPath"_glo},
        {"feblend"_glo, "feBlend"_glo},
        {"fecolormatrix"_glo, "feColorMatrix"_glo},
        {"fecomponenttransfer"_glo, "feComponentTransfer"_glo},
        {"fecomposite"_glo, "feComposite"_glo},
        {"feconvolvematrix"_glo, "feConvolveMatrix"_glo},
        {"fediffuselighting"_glo, "feDiffuseLighting"_glo},
        {"fedisplacementmap"_glo, "feDisplacementMap"_glo},
        {"fedistantlight"_glo, "feDistantLight"_glo},
        {"fedropshadow"_glo, "feDropShadow"_glo},
        {"feflood"_glo, "feFlood"_glo},
        {"fefunca"_glo, "feFuncA"_glo},
        {"fefuncb"_glo, "feFuncB"_glo},
        {"fefuncg"_glo, "feFuncG"_glo},
        {"fefuncr"_glo, "feFuncR"_glo},
        {"fegaussianblur"_glo, "feGaussianBlur"_glo},
        {"feimage"_glo, "feImage"_glo},
        {"femerge"_glo, "feMerge"_glo},
        {"femergenode"_glo, "feMergeNode"_glo},
        {"femorphology"_glo, "feMorphology"_glo},
        {"feoffset"_glo, "feOffset"_glo},
        {"fepointlight"_glo, "fePointLight"_glo},
        {"fespecularlighting"_glo, "feSpecularLighting"_glo},
        {"fespotlight"_glo, "feSpotLight"_glo},
        {"glyphref"_glo, "glyphRef"_glo},
        {"lineargradient"_glo, "linearGradient"_glo},
        {"radialgradient"_glo, "radialGradient"_glo},
        {"textpath"_glo, "textPath"_glo}
    };

    auto it = table.find(token.tagName());
    if(it != table.end()) {
        token.adjustTagName(it->second);
        token.setHasCamelCase(true);
    }
}

void HTMLParser::adjustSVGAttributes(HTMLTokenView& token)
{
    static const std::map<GlobalString, GlobalString> table = {
        {"attributename"_glo, "attributeName"_glo},
        {"attributetype"_glo, "attributeType"_glo},
        {"basefrequency"_glo, "baseFrequency"_glo},
        {"baseprofile"_glo, "baseProfile"_glo},
        {"calcmode"_glo, "calcMode"_glo},
        {"clippathunits"_glo, "clipPathUnits"_glo},
        {"diffuseconstant"_glo, "diffuseConstant"_glo},
        {"edgemode"_glo, "edgeMode"_glo},
        {"filterunits"_glo, "filterUnits"_glo},
        {"glyphref"_glo, "glyphRef"_glo},
        {"gradienttransform"_glo, "gradientTransform"_glo},
        {"gradientunits"_glo, "gradientUnits"_glo},
        {"kernelmatrix"_glo, "kernelMatrix"_glo},
        {"kernelunitlength"_glo, "kernelUnitLength"_glo},
        {"keypoints"_glo, "keyPoints"_glo},
        {"keysplines"_glo, "keySplines"_glo},
        {"keytimes"_glo, "keyTimes"_glo},
        {"lengthadjust"_glo, "lengthAdjust"_glo},
        {"limitingconeangle"_glo, "limitingConeAngle"_glo},
        {"markerheight"_glo, "markerHeight"_glo},
        {"markerunits"_glo, "markerUnits"_glo},
        {"markerwidth"_glo, "markerWidth"_glo},
        {"maskcontentunits"_glo, "maskContentUnits"_glo},
        {"maskunits"_glo, "maskUnits"_glo},
        {"numoctaves"_glo, "numOctaves"_glo},
        {"pathlength"_glo, "pathLength"_glo},
        {"patterncontentunits"_glo, "patternContentUnits"_glo},
        {"patterntransform"_glo, "patternTransform"_glo},
        {"patternunits"_glo, "patternUnits"_glo},
        {"pointsatx"_glo, "pointsAtX"_glo},
        {"pointsaty"_glo, "pointsAtY"_glo},
        {"pointsatz"_glo, "pointsAtZ"_glo},
        {"preservealpha"_glo, "preserveAlpha"_glo},
        {"preserveaspectratio"_glo, "preserveAspectRatio"_glo},
        {"primitiveunits"_glo, "primitiveUnits"_glo},
        {"refx"_glo, "refX"_glo},
        {"refy"_glo, "refY"_glo},
        {"repeatcount"_glo, "repeatCount"_glo},
        {"repeatdur"_glo, "repeatDur"_glo},
        {"requiredextensions"_glo, "requiredExtensions"_glo},
        {"requiredfeatures"_glo, "requiredFeatures"_glo},
        {"specularconstant"_glo, "specularConstant"_glo},
        {"specularexponent"_glo, "specularExponent"_glo},
        {"spreadmethod"_glo, "spreadMethod"_glo},
        {"startoffset"_glo, "startOffset"_glo},
        {"stddeviation"_glo, "stdDeviation"_glo},
        {"stitchtiles"_glo, "stitchTiles"_glo},
        {"surfacescale"_glo, "surfaceScale"_glo},
        {"systemlanguage"_glo, "systemLanguage"_glo},
        {"tablevalues"_glo, "tableValues"_glo},
        {"targetx"_glo, "targetX"_glo},
        {"targety"_glo, "targetY"_glo},
        {"textlength"_glo, "textLength"_glo},
        {"viewbox"_glo, "viewBox"_glo},
        {"viewtarget"_glo, "viewTarget"_glo},
        {"xchannelselector"_glo, "xChannelSelector"_glo},
        {"ychannelselector"_glo, "yChannelSelector"_glo},
        {"zoomandpan"_glo, "zoomAndPan"_glo}
    };

    for(auto& attribute : token.attributes()) {
        auto it = table.find(attribute.name());
        if(it != table.end()) {
            attribute.setName(it->second);
            token.setHasCamelCase(true);
        }
    }
}

void HTMLParser::adjustMathMLAttributes(HTMLTokenView& token)
{
    static const GlobalString definitionurl("definitionurl");
    for(auto& attribute : token.attributes()) {
        if(definitionurl == attribute.name()) {
            static const GlobalString definitionUrlAttr("definitionUrl");
            attribute.setName(definitionUrlAttr);
            token.setHasCamelCase(true);
        }
    }
}

void HTMLParser::adjustForeignAttributes(HTMLTokenView& token)
{
    static const GlobalString xlinkhref("xlink:href");
    for(auto& attribute : token.attributes()) {
        if(xlinkhref == attribute.name()) {
            attribute.setName(hrefAttr);
        }
    }
}

void HTMLParser::insertDoctype(const HTMLTokenView& token)
{
}

void HTMLParser::insertComment(const HTMLTokenView& token, ContainerNode* parent)
{
}

void HTMLParser::insertHTMLHtmlElement(const HTMLTokenView& token)
{
    auto element = createHTMLElement(token);
    insertElement(element, m_document);
    m_openElements.pushHTMLHtmlElement(element);
}

void HTMLParser::insertHeadElement(const HTMLTokenView& token)
{
    auto element = createHTMLElement(token);
    insertElement(element);
    m_openElements.pushHTMLHeadElement(element);
    m_head = element;
}

void HTMLParser::insertHTMLBodyElement(const HTMLTokenView& token)
{
    auto element = createHTMLElement(token);
    insertElement(element);
    m_openElements.pushHTMLBodyElement(element);
}

bool HTMLParser::insertHTMLFormElement(const HTMLTokenView& token)
{
    auto element = createHTMLElement(token);
    insertElement(element);
    if(!pushElement(element))
        return false;
    m_form = element;
    return true;
}

void HTMLParser::insertSelfClosingHTMLElement(const HTMLTokenView& token)
{
    insertElement(createHTMLElement(token));
}

bool HTMLParser::insertHTMLElement(const HTMLTokenView& token, bool bounded)
{
    auto element = createHTMLElement(token);
    insertElement(element);
    return pushElement(element, bounded);
}

bool HTMLParser::insertHTMLFormattingElement(const HTMLTokenView& token)
{
    auto element = createHTMLElement(token);
    insertElement(element);
    if(!pushElement(element))
        return false;
    m_activeFormattingElements.append(element);
    return true;
}

bool HTMLParser::insertForeignElement(const HTMLTokenView& token, const GlobalString& namespaceURI)
{
    auto element = createElement(token, namespaceURI);
    insertElement(element);
    if(token.selfClosing())
        return true;
    return pushElement(element);
}

void HTMLParser::insertTextNode(std::string_view data)
{
    InsertionLocation location;
    location.parent = m_openElements.top();
    if(shouldFosterParent())
        findFosterLocation(location);
    Node* previousChild;
    if(location.nextChild)
        previousChild = location.nextChild->previousSibling();
    else
        previousChild = location.parent->lastChild();
    if(auto previousText = to<TextNode>(previousChild)) {
        previousText->appendData(data);
        return;
    }

    insertNode(location, m_document->createTextNode(data));
}

void HTMLParser::resetInsertionModeAppropriately()
{
    for(int i = m_openElements.size() - 1; i >= 0; --i) {
        auto element = m_openElements.at(i);
        if(element->tagName() == selectTag) {
            for(int j = i; j > 0; --j) {
                auto ancestor = m_openElements.at(j - 1);
                if(ancestor->tagName() == tableTag) {
                    m_insertionMode = InsertionMode::InSelectInTable;
                    return;
                }
            }

            m_insertionMode = InsertionMode::InSelect;
            return;
        }

        if(element->tagName() == tdTag
            || element->tagName() == thTag) {
            m_insertionMode = InsertionMode::InCell;
            return;
        }

        if(element->tagName() == trTag) {
            m_insertionMode = InsertionMode::InRow;
            return;
        }

        if(element->tagName() == tbodyTag
            || element->tagName() == theadTag
            || element->tagName() == tfootTag) {
            m_insertionMode = InsertionMode::InTableBody;
            return;
        }

        if(element->tagName() == captionTag) {
            m_insertionMode = InsertionMode::InCaption;
            return;
        }

        if(element->tagName() == colgroupTag) {
            m_insertionMode = InsertionMode::InColumnGroup;
            return;
        }

        if(element->tagName() == tableTag) {
            m_insertionMode = InsertionMode::InTable;
            return;
        }

        if(element->tagName() == headTag
            || element->tagName() == bodyTag) {
            m_insertionMode = InsertionMode::InBody;
            return;
        }

        if(element->tagName() == framesetTag) {
            m_insertionMode = InsertionMode::InFrameset;
            return;
        }

        if(element->tagName() == htmlTag) {
            assert(m_head != nullptr);
            m_insertionMode = InsertionMode::AfterHead;
            return;
        }
    }
}

HTMLParser::InsertionMode HTMLParser::currentInsertionMode(const HTMLTokenView& token) const
{
    if(m_openElements.empty())
        return m_insertionMode;
    auto element = m_openElements.top();
    if(element->namespaceURI() == xhtmlNs)
        return m_insertionMode;
    if(isMathMLTextIntegrationPoint(element)) {
        if(token.type() == HTMLToken::Type::StartTag
            && token.tagName() != mglyphTag
            && token.tagName() != malignmarkTag)
            return m_insertionMode;
        if(token.type() == HTMLToken::Type::Character
            || token.type() == HTMLToken::Type::SpaceCharacter) {
            return m_insertionMode;
        }
    }

    if(element->namespaceURI() == mathmlNs
        && element->tagName() == annotation_xmlTag
        && token.type() == HTMLToken::Type::StartTag
        && token.tagName() == svgTag) {
        return m_insertionMode;
    }

    if(isHTMLIntegrationPoint(element)) {
        if(token.type() == HTMLToken::Type::StartTag)
            return m_insertionMode;
        if(token.type() == HTMLToken::Type::Character
            || token.type() == HTMLToken::Type::SpaceCharacter) {
            return m_insertionMode;
        }
    }

    if(token.type() == HTMLToken::Type::EndOfFile)
        return m_insertionMode;
    return InsertionMode::InForeignContent;
}

void HTMLParser::handleInitialMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::SpaceCharacter) {
        return;
    }

    handleErrorToken(token);
    m_inQuirksMode = true;
    m_insertionMode = InsertionMode::BeforeHTML;
    handleToken(token);
}

void HTMLParser::handleBeforeHTMLMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            insertHTMLHtmlElement(token);
            m_insertionMode = InsertionMode::BeforeHead;
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() != headTag
            || token.tagName() != bodyTag
            || token.tagName() != htmlTag
            || token.tagName() != brTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        return;
    }

    handleFakeStartTagToken(htmlTag);
    handleToken(token);
}

void HTMLParser::handleBeforeHeadMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == headTag) {
            insertHeadElement(token);
            m_insertionMode = InsertionMode::InHead;
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() != headTag
            || token.tagName() != bodyTag
            || token.tagName() != htmlTag
            || token.tagName() != brTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        return;
    }

    handleFakeStartTagToken(headTag);
    handleToken(token);
}

void HTMLParser::handleInHeadMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == baseTag
            || token.tagName() == basefontTag
            || token.tagName() == bgsoundTag
            || token.tagName() == commandTag
            || token.tagName() == linkTag
            || token.tagName() == metaTag) {
            insertSelfClosingHTMLElement(token);
            return;
        }

        if(token.tagName() == titleTag) {
            handleRCDataToken(token);
            return;
        }

        if(token.tagName() == noscriptTag) {
            if(insertHTMLElement(token))
                m_insertionMode = InsertionMode::InHeadNoscript;
            return;
        }

        if(token.tagName() == noframesTag
            || token.tagName() == styleTag) {
            handleRawTextToken(token);
            return;
        }

        if(token.tagName() == scriptTag) {
            handleScriptDataToken(token);
            return;
        }

        if(token.tagName() == headTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == headTag) {
            m_openElements.popHTMLHeadElement();
            m_insertionMode = InsertionMode::AfterHead;
            return;
        }

        if(token.tagName() != bodyTag
            || token.tagName() != htmlTag
            || token.tagName() != brTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        return;
    }

    handleFakeEndTagToken(headTag);
    handleToken(token);
}

void HTMLParser::handleInHeadNoscriptMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == basefontTag
            || token.tagName() == bgsoundTag
            || token.tagName() == linkTag
            || token.tagName() == metaTag
            || token.tagName() == noframesTag
            || token.tagName() == styleTag) {
            handleInHeadMode(token);
            return;
        }

        if(token.tagName() == headTag
            || token.tagName() == noscriptTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == noscriptTag) {
            assert(currentElement()->tagName() == noscriptTag);
            m_openElements.pop();
            assert(currentElement()->tagName() == headTag);
            m_insertionMode = InsertionMode::InHead;
            return;
        }

        if(token.tagName() != brTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        handleInHeadMode(token);
        return;
    }

    handleErrorToken(token);
    handleFakeEndTagToken(noscriptTag);
    handleToken(token);
}

void HTMLParser::handleAfterHeadMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == bodyTag) {
            insertHTMLBodyElement(token);
            m_framesetOk = false;
            m_insertionMode = InsertionMode::InBody;
            return;
        }

        if(token.tagName() == framesetTag) {
            if(insertHTMLElement(token))
                m_insertionMode = InsertionMode::InFrameset;
            return;
        }

        if(token.tagName() == baseTag
            || token.tagName() == basefontTag
            || token.tagName() == bgsoundTag
            || token.tagName() == linkTag
            || token.tagName() == metaTag
            || token.tagName() == noframesTag
            || token.tagName() == scriptTag
            || token.tagName() == styleTag
            || token.tagName() == titleTag) {
            handleErrorToken(token);
            m_openElements.pushHTMLHeadElement(m_head);
            handleInHeadMode(token);
            m_openElements.removeHTMLHeadElement(m_head);
            return;
        }

        if(token.tagName() == headTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() != bodyTag
            || token.tagName() != htmlTag
            || token.tagName() != brTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        return;
    }

    handleFakeStartTagToken(bodyTag);
    m_framesetOk = true;
    handleToken(token);
}

void HTMLParser::handleInBodyMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleErrorToken(token);
            auto element = m_openElements.htmlElement();
            for(const auto& attribute : token.attributes()) {
                if(element->hasAttribute(attribute.name()))
                    continue;
                element->setAttribute(attribute);
            }

            return;
        }

        if(token.tagName() == baseTag
            || token.tagName() == basefontTag
            || token.tagName() == bgsoundTag
            || token.tagName() == commandTag
            || token.tagName() == linkTag
            || token.tagName() == metaTag
            || token.tagName() == noframesTag
            || token.tagName() == scriptTag
            || token.tagName() == styleTag
            || token.tagName() == titleTag) {
            handleInHeadMode(token);
            return;
        }

        if(token.tagName() == bodyTag) {
            handleErrorToken(token);
            m_framesetOk = false;
            auto element = m_openElements.bodyElement();
            for(const auto& attribute : token.attributes()) {
                if(element->hasAttribute(attribute.name()))
                    continue;
                element->setAttribute(attribute);
            }

            return;
        }

        if(token.tagName() == framesetTag) {
            handleErrorToken(token);
            if(!m_framesetOk)
                return;
            m_openElements.removeHTMLBodyElement();
            if(insertHTMLElement(token))
                m_insertionMode = InsertionMode::InFrameset;
            return;
        }

        if(token.tagName() == addressTag
            || token.tagName() == articleTag
            || token.tagName() == asideTag
            || token.tagName() == blockquoteTag
            || token.tagName() == centerTag
            || token.tagName() == detailsTag
            || token.tagName() == dirTag
            || token.tagName() == divTag
            || token.tagName() == dlTag
            || token.tagName() == fieldsetTag
            || token.tagName() == figcaptionTag
            || token.tagName() == figureTag
            || token.tagName() == footerTag
            || token.tagName() == headerTag
            || token.tagName() == hgroupTag
            || token.tagName() == mainTag
            || token.tagName() == menuTag
            || token.tagName() == navTag
            || token.tagName() == olTag
            || token.tagName() == pTag
            || token.tagName() == sectionTag
            || token.tagName() == summaryTag
            || token.tagName() == ulTag) {
            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            insertHTMLElement(token);
            return;
        }

        if(isNumberedHeaderTag(token.tagName())) {
            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            if(isNumberedHeaderElement(currentElement())) {
                handleErrorToken(token);
                m_openElements.pop();
            }

            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == preTag
            || token.tagName() == listingTag) {
            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            insertHTMLElement(token);
            m_skipLeadingNewline = true;
            m_framesetOk = false;
            return;
        }

        if(token.tagName() == formTag) {
            if(m_form != nullptr) {
                handleErrorToken(token);
                return;
            }

            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            insertHTMLFormElement(token);
            return;
        }

        if(token.tagName() == liTag) {
            m_framesetOk = false;
            for(int i = m_openElements.size() - 1; i >= 0; --i) {
                auto element = m_openElements.at(i);
                if(element->tagName() == liTag) {
                    handleFakeEndTagToken(liTag);
                    break;
                }

                if(isSpecialElement(element)
                    && element->tagName() != addressTag
                    && element->tagName() != divTag
                    && element->tagName() != pTag) {
                    break;
                }
            }

            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == ddTag
            || token.tagName() == dtTag) {
            m_framesetOk = false;
            for(int i = m_openElements.size() - 1; i >= 0; --i) {
                auto element = m_openElements.at(i);
                if(element->tagName() == ddTag
                    || element->tagName() == dtTag) {
                    handleFakeEndTagToken(element->tagName());
                    break;
                }

                if(isSpecialElement(element)
                    && element->tagName() != addressTag
                    && element->tagName() != divTag
                    && element->tagName() != pTag) {
                    break;
                }
            }

            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == plaintextTag) {
            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            insertHTMLElement(token);
            m_tokenizer.setState(HTMLTokenizer::State::PLAINTEXT);
            return;
        }

        if(token.tagName() == buttonTag) {
            if(m_openElements.inScope(buttonTag)) {
                handleErrorToken(token);
                handleFakeEndTagToken(buttonTag);
                handleToken(token);
                return;
            }

            reconstructActiveFormattingElements();
            insertHTMLElement(token);
            m_framesetOk = false;
            return;
        }

        if(token.tagName() == aTag) {
            if(auto aElement = m_activeFormattingElements.closestElementInScope(aTag)) {
                handleErrorToken(token);
                handleFakeEndTagToken(aTag);
                if(m_activeFormattingElements.contains(aElement))
                    m_activeFormattingElements.remove(aElement);
                if(m_openElements.contains(aElement)) {
                    m_openElements.remove(aElement);
                }
            }

            reconstructActiveFormattingElements();
            insertHTMLFormattingElement(token);
            return;
        }

        if(token.tagName() == bTag
            || token.tagName() == bigTag
            || token.tagName() == codeTag
            || token.tagName() == emTag
            || token.tagName() == fontTag
            || token.tagName() == iTag
            || token.tagName() == sTag
            || token.tagName() == smallTag
            || token.tagName() == strikeTag
            || token.tagName() == strongTag
            || token.tagName() == ttTag
            || token.tagName() == uTag) {
            reconstructActiveFormattingElements();
            insertHTMLFormattingElement(token);
            return;
        }

        if(token.tagName() == nobrTag) {
            reconstructActiveFormattingElements();
            if(m_openElements.inScope(nobrTag)) {
                handleErrorToken(token);
                handleFakeEndTagToken(nobrTag);
                reconstructActiveFormattingElements();
            }

            insertHTMLFormattingElement(token);
            return;
        }

        if(token.tagName() == appletTag
            || token.tagName() == marqueeTag
            || token.tagName() == objectTag) {
            reconstructActiveFormattingElements();
            if(insertHTMLElement(token))
                m_activeFormattingElements.appendMarker();
            m_framesetOk = false;
            return;
        }

        if(token.tagName() == tableTag) {
            if(!m_inQuirksMode && m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            if(insertHTMLElement(token))
                m_insertionMode = InsertionMode::InTable;
            m_framesetOk = false;
            return;
        }

        if(token.tagName() == areaTag
            || token.tagName() == brTag
            || token.tagName() == embedTag
            || token.tagName() == imgTag
            || token.tagName() == keygenTag
            || token.tagName() == wbrTag) {
            reconstructActiveFormattingElements();
            insertSelfClosingHTMLElement(token);
            m_framesetOk = false;
            return;
        }

        if(token.tagName() == inputTag) {
            reconstructActiveFormattingElements();
            insertSelfClosingHTMLElement(token);
            auto typeAttribute = token.findAttribute(typeAttr);
            if(typeAttribute == nullptr || !equals(typeAttribute->value(), "hidden", false))
                m_framesetOk = false;
            return;
        }

        if(token.tagName() == paramTag
            || token.tagName() == sourceTag
            || token.tagName() == trackTag) {
            insertSelfClosingHTMLElement(token);
            return;
        }

        if(token.tagName() == hrTag) {
            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            insertSelfClosingHTMLElement(token);
            m_framesetOk = false;
            return;
        }

        if(token.tagName() == imageTag) {
            handleErrorToken(token);
            token.adjustTagName(imgTag);
            handleToken(token);
            return;
        }

        if(token.tagName() == textareaTag) {
            insertHTMLElement(token, false);
            m_skipLeadingNewline = true;
            m_tokenizer.setState(HTMLTokenizer::State::RCDATA);
            m_originalInsertionMode = m_insertionMode;
            m_framesetOk = false;
            m_insertionMode = InsertionMode::Text;
            return;
        }

        if(token.tagName() == xmpTag) {
            if(m_openElements.inButtonScope(pTag))
                handleFakeEndTagToken(pTag);
            reconstructActiveFormattingElements();
            m_framesetOk = false;
            handleRawTextToken(token);
            return;
        }

        if(token.tagName() == iframeTag) {
            m_framesetOk = false;
            handleRawTextToken(token);
            return;
        }

        if(token.tagName() == noembedTag) {
            handleRawTextToken(token);
            return;
        }

        if(token.tagName() == selectTag) {
            reconstructActiveFormattingElements();
            if(insertHTMLElement(token)) {
                if(m_insertionMode == InsertionMode::InTable
                    || m_insertionMode == InsertionMode::InCaption
                    || m_insertionMode == InsertionMode::InColumnGroup
                    || m_insertionMode == InsertionMode::InTableBody
                    || m_insertionMode == InsertionMode::InRow
                    || m_insertionMode == InsertionMode::InCell) {
                    m_insertionMode = InsertionMode::InSelectInTable;
                } else {
                    m_insertionMode = InsertionMode::InSelect;
                }
            }

            m_framesetOk = false;
            return;
        }

        if(token.tagName() == optgroupTag
            || token.tagName() == optionTag) {
            if(currentElement()->tagName() == optionTag) {
                handleFakeEndTagToken(optionTag);
            }

            reconstructActiveFormattingElements();
            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == rpTag
            || token.tagName() == rtTag) {
            if(m_openElements.inScope(rubyTag)) {
                m_openElements.generateImpliedEndTags();
                if(currentElement()->tagName() != rubyTag) {
                    handleErrorToken(token);
                }
            }

            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == mathTag) {
            reconstructActiveFormattingElements();
            adjustMathMLAttributes(token);
            adjustForeignAttributes(token);
            insertForeignElement(token, mathmlNs);
            return;
        }

        if(token.tagName() == svgTag) {
            reconstructActiveFormattingElements();
            adjustSVGAttributes(token);
            adjustForeignAttributes(token);
            insertForeignElement(token, svgNs);
            return;
        }

        if(token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == frameTag
            || token.tagName() == headTag
            || token.tagName() == tbodyTag
            || token.tagName() == tdTag
            || token.tagName() == tfootTag
            || token.tagName() == thTag
            || token.tagName() == theadTag
            || token.tagName() == trTag) {
            handleErrorToken(token);
            return;
        }

        reconstructActiveFormattingElements();
        insertHTMLElement(token);
        return;
    }

    if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == bodyTag) {
            if(!m_openElements.inScope(bodyTag)) {
                handleErrorToken(token);
                return;
            }

            m_insertionMode = InsertionMode::AfterBody;
            return;
        }

        if(token.tagName() == htmlTag) {
            if(!m_openElements.inScope(bodyTag))
                return;
            handleFakeEndTagToken(bodyTag);
            handleToken(token);
            return;
        }

        if(token.tagName() == addressTag
            || token.tagName() == articleTag
            || token.tagName() == asideTag
            || token.tagName() == blockquoteTag
            || token.tagName() == buttonTag
            || token.tagName() == centerTag
            || token.tagName() == detailsTag
            || token.tagName() == dirTag
            || token.tagName() == divTag
            || token.tagName() == dlTag
            || token.tagName() == fieldsetTag
            || token.tagName() == figcaptionTag
            || token.tagName() == figureTag
            || token.tagName() == footerTag
            || token.tagName() == headerTag
            || token.tagName() == hgroupTag
            || token.tagName() == listingTag
            || token.tagName() == mainTag
            || token.tagName() == menuTag
            || token.tagName() == navTag
            || token.tagName() == olTag
            || token.tagName() == preTag
            || token.tagName() == sectionTag
            || token.tagName() == summaryTag
            || token.tagName() == ulTag) {
            if(!m_openElements.inScope(token.tagName())) {
                handleErrorToken(token);
                return;
            }

            m_openElements.generateImpliedEndTags();
            if(currentElement()->tagName() != token.tagName())
                handleErrorToken(token);
            m_openElements.popUntilPopped(token.tagName());
            return;
        }

        if(token.tagName() == formTag) {
            auto node = m_form;
            m_form = nullptr;
            if(node == nullptr || !m_openElements.inScope(node)) {
                handleErrorToken(token);
                return;
            }

            m_openElements.generateImpliedEndTags();
            if(currentElement() != node)
                handleErrorToken(token);
            m_openElements.remove(node);
            return;
        }

        if(token.tagName() == pTag) {
            if(!m_openElements.inButtonScope(pTag)) {
                handleErrorToken(token);
                // The fake <p> below can be a no-op at the depth cap (V08, see pushElement()): if it
                // is, inButtonScope(pTag) will still be false on reprocess, sending this same </p> right
                // back here and recursing forever. Only reprocess if the fake start really pushed
                // something, so an over-deep, unmatched </p> is dropped instead of looping.
                auto depthBefore = m_openElements.size();
                handleFakeStartTagToken(pTag);
                if(m_openElements.size() > depthBefore)
                    handleToken(token);
                return;
            }

            m_openElements.generateImpliedEndTagsExcept(pTag);
            if(currentElement()->tagName() != pTag)
                handleErrorToken(token);
            m_openElements.popUntilPopped(pTag);
            return;
        }

        if(token.tagName() == liTag) {
            if(!m_openElements.inListItemScope(liTag)) {
                handleErrorToken(token);
                return;
            }

            m_openElements.generateImpliedEndTagsExcept(liTag);
            if(currentElement()->tagName() != liTag)
                handleErrorToken(token);
            m_openElements.popUntilPopped(liTag);
            return;
        }

        if(token.tagName() == ddTag
            || token.tagName() == dtTag) {
            if(!m_openElements.inScope(token.tagName())) {
                handleErrorToken(token);
                return;
            }

            m_openElements.generateImpliedEndTagsExcept(token.tagName());
            if(currentElement()->tagName() != token.tagName())
                handleErrorToken(token);
            m_openElements.popUntilPopped(token.tagName());
            return;
        }

        if(isNumberedHeaderTag(token.tagName())) {
            if(!m_openElements.isNumberedHeaderElementInScope()) {
                handleErrorToken(token);
                return;
            }

            m_openElements.generateImpliedEndTags();
            if(currentElement()->tagName() != token.tagName())
                handleErrorToken(token);
            m_openElements.popUntilNumberedHeaderElementPopped();
            return;
        }

        if(token.tagName() == aTag
            || token.tagName() == bTag
            || token.tagName() == bigTag
            || token.tagName() == codeTag
            || token.tagName() == emTag
            || token.tagName() == fontTag
            || token.tagName() == iTag
            || token.tagName() == nobrTag
            || token.tagName() == sTag
            || token.tagName() == smallTag
            || token.tagName() == strikeTag
            || token.tagName() == strongTag
            || token.tagName() == ttTag
            || token.tagName() == uTag) {
            handleFormattingEndTagToken(token);
            return;
        }

        if(token.tagName() == appletTag
            || token.tagName() == marqueeTag
            || token.tagName() == objectTag) {
            if(!m_openElements.inScope(token.tagName())) {
                handleErrorToken(token);
                return;
            }

            m_openElements.generateImpliedEndTags();
            if(currentElement()->tagName() != token.tagName())
                handleErrorToken(token);
            m_openElements.popUntilPopped(token.tagName());
            m_activeFormattingElements.clearToLastMarker();
            return;
        }

        if(token.tagName() == brTag) {
            handleErrorToken(token);
            handleFakeStartTagToken(brTag);
            return;
        }

        handleOtherFormattingEndTagToken(token);
        return;
    }

    if(token.type() == HTMLToken::Type::Character
        || token.type() == HTMLToken::Type::SpaceCharacter) {
        reconstructActiveFormattingElements();
        insertTextNode(token.data());
        if(token.type() == HTMLToken::Type::Character)
            m_framesetOk = false;
        return;
    }

    if(token.type() == HTMLToken::Type::EndOfFile) {
        for(int i = m_openElements.size() - 1; i >= 0; --i) {
            auto element = m_openElements.at(i);
            if(element->tagName() != ddTag
                || element->tagName() != dtTag
                || element->tagName() != liTag
                || element->tagName() != pTag
                || element->tagName() != tbodyTag
                || element->tagName() != tdTag
                || element->tagName() != tfootTag
                || element->tagName() != thTag
                || element->tagName() != theadTag
                || element->tagName() != trTag
                || element->tagName() != bodyTag
                || element->tagName() != htmlTag) {
                handleErrorToken(token);
                return;
            }
        }
    }
}

void HTMLParser::handleTextMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::Character
        || token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        return;
    }

    if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == scriptTag) {
            assert(currentElement()->tagName() == scriptTag);
            m_tokenizer.setState(HTMLTokenizer::State::Data);
            m_openElements.pop();
            m_insertionMode = m_originalInsertionMode;
            return;
        }

        m_openElements.pop();
        m_insertionMode = m_originalInsertionMode;
        return;
    }

    if(token.type() == HTMLToken::Type::EndOfFile) {
        handleErrorToken(token);
        m_openElements.pop();
        m_insertionMode = m_originalInsertionMode;
        handleToken(token);
        return;
    }
}

void HTMLParser::handleInTableMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == captionTag) {
            m_openElements.popUntilTableScopeMarker();
            if(insertHTMLElement(token)) {
                m_activeFormattingElements.appendMarker();
                m_insertionMode = InsertionMode::InCaption;
            }
            return;
        }

        if(token.tagName() == colgroupTag) {
            m_openElements.popUntilTableScopeMarker();
            if(insertHTMLElement(token))
                m_insertionMode = InsertionMode::InColumnGroup;
            return;
        }

        if(token.tagName() == colTag) {
            // The fake <colgroup> below can be a no-op at the depth cap (V08, see pushElement()): if it
            // is, mode stays InTable and reprocessing would hit this same branch forever. Only
            // reprocess if it really pushed something, so an over-deep <col> is dropped instead.
            auto depthBefore = m_openElements.size();
            handleFakeStartTagToken(colgroupTag);
            if(m_openElements.size() > depthBefore)
                handleToken(token);
            return;
        }

        if(token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag) {
            m_openElements.popUntilTableScopeMarker();
            if(insertHTMLElement(token))
                m_insertionMode = InsertionMode::InTableBody;
            return;
        }

        if(token.tagName() == thTag
            || token.tagName() == tdTag
            || token.tagName() == trTag) {
            // Same reasoning as the colTag branch above: only reprocess if the fake <tbody> really
            // pushed something, so an over-deep <tr>/<td>/<th> is dropped instead of looping forever.
            auto depthBefore = m_openElements.size();
            handleFakeStartTagToken(tbodyTag);
            if(m_openElements.size() > depthBefore)
                handleToken(token);
            return;
        }

        if(token.tagName() == tableTag) {
            handleErrorToken(token);
            handleFakeEndTagToken(tableTag);
            handleToken(token);
            return;
        }

        if(token.tagName() == styleTag
            || token.tagName() == scriptTag) {
            handleInHeadMode(token);
            return;
        }

        if(token.tagName() == inputTag) {
            auto typeAttribute = token.findAttribute(typeAttr);
            if(typeAttribute && equals(typeAttribute->value(), "hidden", false)) {
                handleErrorToken(token);
                insertSelfClosingHTMLElement(token);
                return;
            }

            handleErrorToken(token);
            m_fosterRedirecting = true;
            handleInBodyMode(token);
            m_fosterRedirecting = false;
            return;
        }

        if(token.tagName() == formTag) {
            handleErrorToken(token);
            if(m_form != nullptr)
                return;
            if(insertHTMLFormElement(token))
                m_openElements.pop();
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == tableTag) {
            assert(m_openElements.inTableScope(tableTag));
            m_openElements.popUntilPopped(tableTag);
            resetInsertionModeAppropriately();
            return;
        }

        if(token.tagName() == bodyTag
            || token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == htmlTag
            || token.tagName() == tbodyTag
            || token.tagName() == tdTag
            || token.tagName() == tfootTag
            || token.tagName() == thTag
            || token.tagName() == theadTag
            || token.tagName() == trTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::Character
        || token.type() == HTMLToken::Type::SpaceCharacter) {
        m_pendingTableCharacters.clear();
        m_originalInsertionMode = m_insertionMode;
        m_insertionMode = InsertionMode::InTableText;
        handleToken(token);
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        assert(currentElement()->tagName() != htmlTag);
        handleErrorToken(token);
        return;
    }

    handleErrorToken(token);
    m_fosterRedirecting = true;
    handleInBodyMode(token);
    m_fosterRedirecting = false;
}

void HTMLParser::handleInTableTextMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::Character
        || token.type() == HTMLToken::Type::SpaceCharacter) {
        m_pendingTableCharacters += token.data();
        return;
    }

    flushPendingTableCharacters();
    handleToken(token);
}

void HTMLParser::handleInCaptionMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == tbodyTag
            || token.tagName() == tdTag
            || token.tagName() == tfootTag
            || token.tagName() == thTag
            || token.tagName() == theadTag
            || token.tagName() == trTag) {
            handleErrorToken(token);
            handleFakeEndTagToken(captionTag);
            handleToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == captionTag) {
            assert(m_openElements.inTableScope(captionTag));
            m_openElements.generateImpliedEndTags();
            m_openElements.popUntilPopped(captionTag);
            m_activeFormattingElements.clearToLastMarker();
            m_insertionMode = InsertionMode::InTable;
            return;
        }

        if(token.tagName() == tableTag) {
            handleErrorToken(token);
            handleFakeEndTagToken(captionTag);
            handleToken(token);
            return;
        }

        if(token.tagName() == bodyTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == htmlTag
            || token.tagName() == tbodyTag
            || token.tagName() == tdTag
            || token.tagName() == tfootTag
            || token.tagName() == thTag
            || token.tagName() == theadTag
            || token.tagName() == trTag) {
            handleErrorToken(token);
            return;
        }
    }

    handleInBodyMode(token);
}

void HTMLParser::handleInColumnGroupMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == colTag) {
            insertSelfClosingHTMLElement(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == colgroupTag) {
            assert(currentElement()->tagName() == colgroupTag);
            m_openElements.pop();
            m_insertionMode = InsertionMode::InTable;
            return;
        }

        if(token.tagName() == colTag) {
            handleErrorToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        assert(currentElement()->tagName() != htmlTag);
        handleFakeEndTagToken(colgroupTag);
        handleToken(token);
        return;
    }

    handleFakeEndTagToken(colgroupTag);
    handleToken(token);
}

void HTMLParser::handleInTableBodyMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == trTag) {
            m_openElements.popUntilTableBodyScopeMarker();
            if(insertHTMLElement(token))
                m_insertionMode = InsertionMode::InRow;
            return;
        }

        if(token.tagName() == tdTag
            || token.tagName() == thTag) {
            handleErrorToken(token);
            // Same reasoning as handleInTableMode's colTag/th-td-tr branches above: only reprocess if
            // the fake <tr> really pushed something, so an over-deep <td>/<th> is dropped instead of
            // looping forever once the depth cap (V08) makes it a no-op.
            auto depthBefore = m_openElements.size();
            handleFakeStartTagToken(trTag);
            if(m_openElements.size() > depthBefore)
                handleToken(token);
            return;
        }

        if(token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag) {
            assert(m_openElements.inTableScope(tbodyTag) || m_openElements.inTableScope(theadTag) || m_openElements.inTableScope(tfootTag));
            m_openElements.popUntilTableBodyScopeMarker();
            handleFakeEndTagToken(currentElement()->tagName());
            handleToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag) {
            if(!m_openElements.inTableScope(token.tagName())) {
                handleErrorToken(token);
                return;
            }

            m_openElements.popUntilTableBodyScopeMarker();
            m_openElements.pop();
            m_insertionMode = InsertionMode::InTable;
            return;
        }

        if(token.tagName() == tableTag) {
            assert(m_openElements.inTableScope(tbodyTag) || m_openElements.inTableScope(theadTag) || m_openElements.inTableScope(tfootTag));
            m_openElements.popUntilTableBodyScopeMarker();
            handleFakeEndTagToken(currentElement()->tagName());
            handleToken(token);
            return;
        }

        if(token.tagName() == bodyTag
            || token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == htmlTag
            || token.tagName() == tdTag
            || token.tagName() == thTag
            || token.tagName() == trTag) {
            handleErrorToken(token);
            return;
        }
    }

    handleInTableMode(token);
}

void HTMLParser::handleInRowMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == tdTag
            || token.tagName() == thTag) {
            m_openElements.popUntilTableRowScopeMarker();
            if(insertHTMLElement(token)) {
                m_insertionMode = InsertionMode::InCell;
                m_activeFormattingElements.appendMarker();
            }
            return;
        }

        if(token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag
            || token.tagName() == trTag) {
            handleFakeEndTagToken(trTag);
            handleToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == trTag) {
            assert(m_openElements.inTableScope(trTag));
            m_openElements.popUntilTableRowScopeMarker();
            m_openElements.pop();
            m_insertionMode = InsertionMode::InTableBody;
            return;
        }

        if(token.tagName() == tableTag) {
            handleFakeEndTagToken(trTag);
            handleToken(token);
            return;
        }

        if(token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag) {
            if(!m_openElements.inTableScope(token.tagName())) {
                handleErrorToken(token);
                return;
            }

            handleFakeEndTagToken(trTag);
            handleToken(token);
            return;
        }

        if(token.tagName() == bodyTag
            || token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == htmlTag
            || token.tagName() == tdTag
            || token.tagName() == thTag) {
            handleErrorToken(token);
            return;
        }
    }

    handleInTableMode(token);
}

void HTMLParser::handleInCellMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == tbodyTag
            || token.tagName() == tdTag
            || token.tagName() == tfootTag
            || token.tagName() == thTag
            || token.tagName() == theadTag
            || token.tagName() == trTag) {
            assert(m_openElements.inTableScope(tdTag) || m_openElements.inTableScope(thTag));
            closeTheCell();
            handleToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == tdTag
            || token.tagName() == thTag) {
            if(!m_openElements.inTableScope(token.tagName())) {
                handleErrorToken(token);
                return;
            }

            m_openElements.generateImpliedEndTags();
            if(currentElement()->tagName() != token.tagName())
                handleErrorToken(token);
            m_openElements.popUntilPopped(token.tagName());
            m_activeFormattingElements.clearToLastMarker();
            m_insertionMode = InsertionMode::InRow;
            return;
        }

        if(token.tagName() == bodyTag
            || token.tagName() == captionTag
            || token.tagName() == colTag
            || token.tagName() == colgroupTag
            || token.tagName() == htmlTag) {
            handleErrorToken(token);
            return;
        }

        if(token.tagName() == tableTag
            || token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag
            || token.tagName() == trTag) {
            if(!m_openElements.inTableScope(token.tagName())) {
                handleErrorToken(token);
                return;
            }

            closeTheCell();
            handleToken(token);
            return;
        }
    }

    handleInBodyMode(token);
}

void HTMLParser::handleInSelectMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == optionTag) {
            if(currentElement()->tagName() == optionTag)
                handleFakeEndTagToken(optionTag);
            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == optgroupTag) {
            if(currentElement()->tagName() == optionTag)
                handleFakeEndTagToken(optionTag);
            if(currentElement()->tagName() == optgroupTag)
                handleFakeEndTagToken(optgroupTag);
            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == selectTag) {
            handleErrorToken(token);
            handleFakeEndTagToken(selectTag);
            return;
        }

        if(token.tagName() == inputTag
            || token.tagName() == keygenTag
            || token.tagName() == textareaTag) {
            handleErrorToken(token);
            assert(m_openElements.inSelectScope(selectTag));
            handleFakeEndTagToken(selectTag);
            handleToken(token);
            return;
        }

        if(token.tagName() == scriptTag) {
            handleInHeadMode(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == optgroupTag) {
            if(currentElement()->tagName() == optionTag) {
                auto element = m_openElements.at(m_openElements.size() - 2);
                if(element->tagName() == optgroupTag)  {
                    handleFakeEndTagToken(optionTag);
                }
            }

            if(currentElement()->tagName() == optgroupTag) {
                m_openElements.pop();
                return;
            }

            handleErrorToken(token);
            return;
        }

        if(token.tagName() == optionTag) {
            if(currentElement()->tagName() == optionTag) {
                m_openElements.pop();
                return;
            }

            handleErrorToken(token);
            return;
        }

        if(token.tagName() == selectTag) {
            assert(m_openElements.inSelectScope(token.tagName()));
            m_openElements.popUntilPopped(selectTag);
            resetInsertionModeAppropriately();
            return;
        }
    } else if(token.type() == HTMLToken::Type::Character
        || token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        assert(currentElement()->tagName() != htmlTag);
        handleErrorToken(token);
        return;
    }

    handleErrorToken(token);
}

void HTMLParser::handleInSelectInTableMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == captionTag
            || token.tagName() == tableTag
            || token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag
            || token.tagName() == trTag
            || token.tagName() == tdTag
            || token.tagName() == thTag) {
            handleErrorToken(token);
            handleFakeEndTagToken(selectTag);
            handleToken(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == captionTag
            || token.tagName() == tableTag
            || token.tagName() == tbodyTag
            || token.tagName() == tfootTag
            || token.tagName() == theadTag
            || token.tagName() == trTag
            || token.tagName() == tdTag
            || token.tagName() == thTag) {
            handleErrorToken(token);
            if(m_openElements.inTableScope(token.tagName())) {
                handleFakeEndTagToken(selectTag);
                handleToken(token);
            }

            return;
        }
    }

    handleInSelectMode(token);
}

void HTMLParser::handleAfterBodyMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == htmlTag) {
            m_insertionMode = InsertionMode::AfterAfterBody;
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        handleInBodyMode(token);
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        return;
    }

    handleErrorToken(token);
    m_insertionMode = InsertionMode::InBody;
    handleToken(token);
}

void HTMLParser::handleInFramesetMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == framesetTag) {
            insertHTMLElement(token);
            return;
        }

        if(token.tagName() == frameTag) {
            insertSelfClosingHTMLElement(token);
            return;
        }

        if(token.tagName() == noframesTag) {
            handleInHeadMode(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == framesetTag) {
            // A nested <frameset> start tag above may have been ignored at the depth cap (V08, see
            // pushElement()): unlike table/select/..., frameset has no scope check to gate this pop on,
            // so guard it directly against what is really open, rather than popping unconditionally --
            // otherwise a spurious end tag for a start tag that was never pushed would pop whatever
            // real frameset happens to be on top instead.
            if(currentElement()->tagName() == framesetTag) {
                assert(currentElement()->tagName() != htmlTag);
                m_openElements.pop();
            }

            if(currentElement()->tagName() != framesetTag)
                m_insertionMode = InsertionMode::AfterFrameset;
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        assert(currentElement()->tagName() != htmlTag);
        handleErrorToken(token);
        return;
    }

    handleErrorToken(token);
}

void HTMLParser::handleAfterFramesetMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == noframesTag) {
            handleInHeadMode(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::EndTag) {
        if(token.tagName() == htmlTag) {
            m_insertionMode = InsertionMode::AfterAfterFrameset;
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        return;
    }

    handleErrorToken(token);
}

void HTMLParser::handleAfterAfterBodyMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        handleInBodyMode(token);
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        return;
    }

    handleErrorToken(token);
    m_insertionMode = InsertionMode::InBody;
    handleToken(token);
}

void HTMLParser::handleAfterAfterFramesetMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == htmlTag) {
            handleInBodyMode(token);
            return;
        }

        if(token.tagName() == noframesTag) {
            handleInHeadMode(token);
            return;
        }
    } else if(token.type() == HTMLToken::Type::SpaceCharacter) {
        handleInBodyMode(token);
        return;
    } else if(token.type() == HTMLToken::Type::EndOfFile) {
        return;
    }

    handleErrorToken(token);
}

void HTMLParser::handleInForeignContentMode(HTMLTokenView& token)
{
    if(token.type() == HTMLToken::Type::Character
        || token.type() == HTMLToken::Type::SpaceCharacter) {
        insertTextNode(token.data());
        if(token.type() == HTMLToken::Type::Character)
            m_framesetOk = false;
        return;
    }

    if(token.type() == HTMLToken::Type::StartTag) {
        if(token.tagName() == bTag
            || token.tagName() == bigTag
            || token.tagName() == blockquoteTag
            || token.tagName() == bodyTag
            || token.tagName() == brTag
            || token.tagName() == centerTag
            || token.tagName() == codeTag
            || token.tagName() == ddTag
            || token.tagName() == divTag
            || token.tagName() == dlTag
            || token.tagName() == dtTag
            || token.tagName() == emTag
            || token.tagName() == embedTag
            || isNumberedHeaderTag(token.tagName())
            || token.tagName() == headTag
            || token.tagName() == hrTag
            || token.tagName() == iTag
            || token.tagName() == imgTag
            || token.tagName() == liTag
            || token.tagName() == listingTag
            || token.tagName() == menuTag
            || token.tagName() == metaTag
            || token.tagName() == nobrTag
            || token.tagName() == olTag
            || token.tagName() == pTag
            || token.tagName() == preTag
            || token.tagName() == rubyTag
            || token.tagName() == sTag
            || token.tagName() == smallTag
            || token.tagName() == spanTag
            || token.tagName() == strongTag
            || token.tagName() == strikeTag
            || token.tagName() == subTag
            || token.tagName() == supTag
            || token.tagName() == tableTag
            || token.tagName() == ttTag
            || token.tagName() == uTag
            || token.tagName() == ulTag
            || token.tagName() == varTag
            || (token.tagName() == fontTag && (token.hasAttribute(colorAttr) || token.hasAttribute(faceAttr) || token.hasAttribute(sizeAttr)))) {
            handleErrorToken(token);
            m_openElements.popUntilForeignContentScopeMarker();
            handleToken(token);
            return;
        }

        const auto& currentNamespace = currentElement()->namespaceURI();
        if(currentNamespace == mathmlNs) {
            adjustMathMLAttributes(token);
        } else if(currentNamespace == svgNs) {
            adjustSVGTagNames(token);
            adjustSVGAttributes(token);
        }

        adjustForeignAttributes(token);
        insertForeignElement(token, currentNamespace);
        return;
    }

    if(token.type() == HTMLToken::Type::EndTag) {
        auto node = m_openElements.top();
        if(node->namespaceURI() == svgNs)
            adjustSVGTagNames(token);
        if(node->tagName() != token.tagName()) {
            handleErrorToken(token);
        }

        for(int i = m_openElements.size() - 1; i >= 0; --i) {
            if(node->tagName() == token.tagName()) {
                m_openElements.popUntilPopped(node);
                return;
            }

            node = m_openElements.at(i - 1);
            if(node->namespaceURI() == xhtmlNs) {
                handleToken(token);
                return;
            }
        }
    }
}

void HTMLParser::handleFakeStartTagToken(const GlobalString& tagName)
{
    HTMLTokenView token(HTMLToken::Type::StartTag, tagName);
    handleToken(token, m_insertionMode);
}

void HTMLParser::handleFakeEndTagToken(const GlobalString& tagName)
{
    HTMLTokenView token(HTMLToken::Type::EndTag, tagName);
    handleToken(token, m_insertionMode);
}

void HTMLParser::handleFormattingEndTagToken(HTMLTokenView& token)
{
    static const int outerIterationLimit = 8;
    static const int innerIterationLimit = 3;
    for(int i = 0; i < outerIterationLimit; ++i) {
        auto formattingElement = m_activeFormattingElements.closestElementInScope(token.tagName());
        if(formattingElement == nullptr) {
            handleOtherFormattingEndTagToken(token);
            return;
        }

        if(!m_openElements.contains(formattingElement)) {
            handleErrorToken(token);
            m_activeFormattingElements.remove(formattingElement);
            return;
        }

        if(!m_openElements.inScope(formattingElement)) {
            handleErrorToken(token);
            return;
        }

        if(formattingElement != m_openElements.top())
            handleErrorToken(token);
        auto furthestBlock = m_openElements.furthestBlockForFormattingElement(formattingElement);
        if(furthestBlock == nullptr) {
            m_openElements.popUntilPopped(formattingElement);
            m_activeFormattingElements.remove(formattingElement);
            return;
        }

        auto commonAncestor = m_openElements.previous(formattingElement);
        auto bookmark = m_activeFormattingElements.index(formattingElement);

        auto furthestBlockIndex = m_openElements.index(furthestBlock);
        auto lastNode = furthestBlock;
        for(int i = 0; i < innerIterationLimit; ++i) {
            furthestBlockIndex -= 1;
            auto node = m_openElements.at(furthestBlockIndex);
            if(!m_activeFormattingElements.contains(node)) {
                m_openElements.remove(furthestBlockIndex);
                continue;
            }

            if(node == formattingElement)
                break;
            if(lastNode == furthestBlock) {
                bookmark = m_activeFormattingElements.index(node) + 1;
            }

            auto newNode = cloneElement(node);
            m_activeFormattingElements.replace(node, newNode);
            m_openElements.replace(furthestBlockIndex, newNode);

            lastNode->reparent(newNode);
            lastNode = newNode;
        }

        lastNode->remove();

        if(isFosterRedirectingTag(commonAncestor->tagName())) {
            fosterParent(lastNode);
        } else {
            commonAncestor->appendChild(lastNode);
        }

        auto newNode = cloneElement(formattingElement);
        furthestBlock->reparentChildren(newNode);
        furthestBlock->appendChild(newNode);

        m_activeFormattingElements.remove(formattingElement);
        m_activeFormattingElements.insert(bookmark, newNode);

        m_openElements.remove(formattingElement);
        m_openElements.insertAfter(furthestBlock, newNode);
    }
}

void HTMLParser::handleOtherFormattingEndTagToken(HTMLTokenView& token)
{
    for(int i = m_openElements.size() - 1; i >= 0; --i) {
        auto element = m_openElements.at(i);
        if(element->tagName() == token.tagName()) {
            m_openElements.generateImpliedEndTagsExcept(token.tagName());
            if(currentElement()->tagName() != token.tagName())
                handleErrorToken(token);
            m_openElements.popUntilPopped(element);
            break;
        }

        if(isSpecialElement(element)) {
            handleErrorToken(token);
            break;
        }
    }
}

void HTMLParser::handleErrorToken(HTMLTokenView& token)
{
}

void HTMLParser::handleRCDataToken(HTMLTokenView& token)
{
    // Exempt from the depth cap (V08, see pushElement()): once the tokenizer switches to RCDATA, it
    // recognizes nothing but this element's own matching end tag, so it cannot contain a further
    // nested <title>/<textarea> to chain into unbounded depth. handleTextMode() below unconditionally
    // pops this element on that end tag (or EOF), so it must always have been genuinely pushed.
    insertHTMLElement(token, false);
    m_tokenizer.setState(HTMLTokenizer::State::RCDATA);
    m_originalInsertionMode = m_insertionMode;
    m_insertionMode = InsertionMode::Text;
}

void HTMLParser::handleRawTextToken(HTMLTokenView& token)
{
    // Exempt from the depth cap (V08): same reasoning as handleRCDataToken() above, for
    // <style>/<noframes>/<xmp>/<iframe>/<noembed>, all of which switch the tokenizer to RAWTEXT.
    insertHTMLElement(token, false);
    m_tokenizer.setState(HTMLTokenizer::State::RAWTEXT);
    m_originalInsertionMode = m_insertionMode;
    m_insertionMode = InsertionMode::Text;
}

void HTMLParser::handleScriptDataToken(HTMLTokenView& token)
{
    // Exempt from the depth cap (V08): same reasoning as handleRCDataToken() above, for <script>.
    insertHTMLElement(token, false);
    m_tokenizer.setState(HTMLTokenizer::State::ScriptData);
    m_originalInsertionMode = m_insertionMode;
    m_insertionMode = InsertionMode::Text;
}

void HTMLParser::handleDoctypeToken(HTMLTokenView& token)
{
    if(m_insertionMode == InsertionMode::Initial) {
        insertDoctype(token);
        m_insertionMode = InsertionMode::BeforeHTML;
        return;
    }

    if(m_insertionMode == InsertionMode::InTableText) {
        flushPendingTableCharacters();
        handleDoctypeToken(token);
        return;
    }

    handleErrorToken(token);
}

void HTMLParser::handleCommentToken(HTMLTokenView& token)
{
    if(m_insertionMode == InsertionMode::Initial
        || m_insertionMode == InsertionMode::BeforeHTML
        || m_insertionMode == InsertionMode::AfterAfterBody
        || m_insertionMode == InsertionMode::AfterAfterFrameset) {
        insertComment(token, m_document);
        return;
    }

    if(m_insertionMode == InsertionMode::AfterBody) {
        insertComment(token, m_openElements.htmlElement());
        return;
    }

    if(m_insertionMode == InsertionMode::InTableText) {
        flushPendingTableCharacters();
        handleCommentToken(token);
        return;
    }

    insertComment(token, m_openElements.top());
}

void HTMLParser::handleToken(HTMLTokenView& token, InsertionMode mode)
{
    switch(mode) {
    case InsertionMode::Initial:
        return handleInitialMode(token);
    case InsertionMode::BeforeHTML:
        return handleBeforeHTMLMode(token);
    case InsertionMode::BeforeHead:
        return handleBeforeHeadMode(token);
    case InsertionMode::InHead:
        return handleInHeadMode(token);
    case InsertionMode::InHeadNoscript:
        return handleInHeadNoscriptMode(token);
    case InsertionMode::AfterHead:
        return handleAfterHeadMode(token);
    case InsertionMode::InBody:
        return handleInBodyMode(token);
    case InsertionMode::Text:
        return handleTextMode(token);
    case InsertionMode::InTable:
        return handleInTableMode(token);
    case InsertionMode::InTableText:
        return handleInTableTextMode(token);
    case InsertionMode::InCaption:
        return handleInCaptionMode(token);
    case InsertionMode::InColumnGroup:
        return handleInColumnGroupMode(token);
    case InsertionMode::InTableBody:
        return handleInTableBodyMode(token);
    case InsertionMode::InRow:
        return handleInRowMode(token);
    case InsertionMode::InCell:
        return handleInCellMode(token);
    case InsertionMode::InSelect:
        return handleInSelectMode(token);
    case InsertionMode::InSelectInTable:
        return handleInSelectInTableMode(token);
    case InsertionMode::AfterBody:
        return handleAfterBodyMode(token);
    case InsertionMode::InFrameset:
        return handleInFramesetMode(token);
    case InsertionMode::AfterFrameset:
        return handleAfterFramesetMode(token);
    case InsertionMode::AfterAfterBody:
        return handleAfterAfterBodyMode(token);
    case InsertionMode::AfterAfterFrameset:
        return handleAfterAfterFramesetMode(token);
    case InsertionMode::InForeignContent:
        return handleInForeignContentMode(token);
    }
}

} // namespace plutobook
