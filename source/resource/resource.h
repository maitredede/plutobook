/*
 * Copyright (c) 2022-2026 Samuel Ugochukwu <sammycageagle@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef PLUTOBOOK_RESOURCE_H
#define PLUTOBOOK_RESOURCE_H

#include "pointer.h"
#include "heapstring.h"
#include "url.h"

namespace plutobook {

class Resource : public HeapMember, public RefCounted<Resource> {
public:
    enum class Type {
        Text,
        Image,
        Font
    };

    virtual ~Resource() = default;
    virtual Type type() const = 0;

protected:
    Resource() = default;
};

class ResourceData;
class ResourceFetcher;

class ResourceLoader {
public:
    // `trusted` is true only for the top-level document URL passed to Book::loadUrl (the URL the
    // embedder explicitly asked to load). It is false (the default) for every sub-resource fetch
    // (images, stylesheets, fonts, SVG references, ...) triggered while parsing document content,
    // which may originate from untrusted input. See ResourceFetcher::fetchUrl(const std::string&, bool)
    // and DefaultResourceFetcher for how the flag is used.
    static ResourceData loadUrl(const Url& url, ResourceFetcher* customFetcher = nullptr, bool trusted = false);
    static Url completeUrl(std::string_view value);
    static Url baseUrl();
};

} // namespace plutobook

#endif // PLUTOBOOK_RESOURCE_H
