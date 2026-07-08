/*
 * Copyright (c) 2022-2026 Samuel Ugochukwu <sammycageagle@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "resource.h"
#include "stringutils.h"

#include "plutobook.hpp"

#ifdef PLUTOBOOK_HAS_CURL
#include <curl/curl.h>
#else
#include <fstream>
#endif

#include <filesystem>
#include <cstring>
#include <vector>
#include <map>

namespace plutobook {

using ByteArray = std::vector<char>;

static ByteArray* ByteArrayCreate(size_t size = 0)
{
    return new ByteArray(size);
}

static void ByteArrayDestroy(void* data)
{
    delete (ByteArray*)(data);
}

static void parseContentType(std::string_view input, std::string& mimeType, std::string& textEncoding)
{
    auto type = input.substr(0, input.find(';'));
    input.remove_prefix(type.size());
    stripLeadingAndTrailingSpaces(type);
    mimeType.assign(type);
    while(!input.empty()) {
        input.remove_prefix(1);
        auto parameter = input.substr(0, input.find(';'));
        input.remove_prefix(parameter.size());
        stripLeadingAndTrailingSpaces(parameter);
        auto name = parameter.substr(0, parameter.find('='));
        parameter.remove_prefix(name.size());
        stripLeadingAndTrailingSpaces(name);
        if(!parameter.empty() && equals(name, "charset", false)) {
            parameter.remove_prefix(1);
            if(!parameter.empty() && parameter.front() == '\"')
                parameter.remove_prefix(1);
            if(!parameter.empty() && parameter.back() == '\"')
                parameter.remove_suffix(1);
            auto value = parameter.substr(0, parameter.size());
            stripLeadingAndTrailingSpaces(value);
            textEncoding.assign(value);
            break;
        }
    }
}

static const char base64DecMap[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool base64Decode(std::string_view input, ByteArray& output)
{
    output.resize(input.length());
    size_t equalsSignCount = 0;
    size_t outputLength = 0;
    for(int cc : input) {
        if(cc == '=') {
            ++equalsSignCount;
        } else if(cc == '+' || cc == '/' || isAlpha(cc) || isDigit(cc)) {
            if(equalsSignCount > 0)
                return false;
            output[outputLength++] = base64DecMap[cc];
        } else if(!isSpace(cc)) {
            return false;
        }
    }

    if(outputLength == 0 || equalsSignCount > 2 || (outputLength % 4) == 1)
        return false;
    if(outputLength < input.length())
        output.resize(outputLength);
    outputLength -= (outputLength + 3) / 4;
    if(outputLength == 0) {
        return false;
    }

    size_t sidx = 0;
    size_t didx = 0;
    if(outputLength > 1) {
        while(didx < outputLength - 2) {
            output[didx + 0] = (((output[sidx + 0] << 2) & 255) | ((output[sidx + 1] >> 4) & 003));
            output[didx + 1] = (((output[sidx + 1] << 4) & 255) | ((output[sidx + 2] >> 2) & 017));
            output[didx + 2] = (((output[sidx + 2] << 6) & 255) | ((output[sidx + 3] >> 0) & 077));
            sidx += 4;
            didx += 3;
        }
    }

    if(didx < outputLength)
        output[didx] = (((output[sidx + 0] << 2) & 255) | ((output[sidx + 1] >> 4) & 003));
    if(++didx < outputLength)
        output[didx] = (((output[sidx + 1] << 4) & 255) | ((output[sidx + 2] >> 2) & 017));
    if(outputLength < output.size())
        output.resize(outputLength);
    return true;
}

static std::string percentDecode(std::string_view input)
{
    std::string output;
    output.reserve(input.length());
    while(!input.empty()) {
        auto cc = input.front();
        if(cc == '%' && input.length() > 2 && isHexDigit(input[1]) && isHexDigit(input[2])) {
            output.push_back(toHexByte(input[1], input[2]));
            input.remove_prefix(3);
        } else {
            output.push_back(cc);
            input.remove_prefix(1);
        }
    }

    return output;
}

static ResourceData loadDataUrl(std::string_view input)
{
    assert(startswith(input, "data:", false));
    input.remove_prefix(5);

    auto headerEnd = input.find(',');
    if(headerEnd == std::string_view::npos) {
        plutobook_set_error_message("invalid data URL: missing comma separator");
        return ResourceData();
    }

    auto header = input.substr(0, headerEnd);
    auto mediaTypeEnd = header.rfind(';');
    if(mediaTypeEnd == std::string_view::npos) {
        mediaTypeEnd = header.length();
    }

    std::string mimeType;
    std::string textEncoding;
    auto mediaType = header.substr(0, mediaTypeEnd);
    parseContentType(mediaType, mimeType, textEncoding);
    if(mimeType.empty() && textEncoding.empty()) {
        mimeType.assign("text/plain");
        textEncoding.assign("US-ASCII");
    }

    std::string_view formatType;
    if(mediaTypeEnd < header.length()) {
        formatType = header.substr(mediaTypeEnd + 1);
        stripLeadingAndTrailingSpaces(formatType);
    }

    auto content = ByteArrayCreate();
    input.remove_prefix(headerEnd + 1);
    if(!equals(formatType, "base64", false)) {
        content->reserve(input.length());
        content->assign(input.begin(), input.end());
    } else {
        if(!base64Decode(input, *content)) {
            plutobook_set_error_message("invalid data URL: base64 decoding failed");
            ByteArrayDestroy(content);
            return ResourceData();
        }
    }

    return ResourceData(content->data(), content->size(), mimeType, textEncoding, ByteArrayDestroy, content);
}

static UrlValidator& globalUrlValidator()
{
    static UrlValidator validator;
    return validator;
}

void setUrlValidator(UrlValidator validator)
{
    globalUrlValidator() = std::move(validator);
}

static bool mimeTypeFromPath(std::string& mimeType, std::string_view path)
{
    auto index = path.rfind('.');
    if(index == std::string_view::npos)
        return false;
    static std::map<std::string_view, std::string_view> table = {
        {"xhtml", "application/xhtml+xml"},
        {"html", "text/html"},
        {"htm", "text/html"},
        {"txt", "text/plain"},
        {"css", "text/css"},
        {"xml", "text/xml"},
        {"jpeg", "image/jpeg"},
        {"jpg", "image/jpeg"},
        {"png", "image/png"},
        {"webp", "image/webp"},
        {"svg", "image/svg+xml"},
        {"gif", "image/gif"},
        {"bmp", "image/bmp"}
    };

    auto it = table.find(path.substr(index + 1));
    if(it == table.end())
        return false;
    mimeType.assign(it->second);
    return true;
}

#ifdef PLUTOBOOK_HAS_CURL

DefaultResourceFetcher::DefaultResourceFetcher()
{
    curl_global_init(CURL_GLOBAL_ALL);
#ifdef PLUTOBOOK_AUTODETECT_CA
    static const char* cainfos[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/usr/share/ssl/certs/ca-bundle.crt",
        "/usr/local/share/certs/ca-root-nss.crt",
        "/etc/ssl/cert.pem"
    };

    static const char* capaths[] = {
        "/etc/ssl/certs"
    };

    for(auto path : cainfos) {
        if(std::filesystem::exists(path)
            && std::filesystem::is_regular_file(path)) {
            m_caInfo.assign(path);
            break;
        }
    }

    for(auto path : capaths) {
        if(std::filesystem::exists(path)
            && std::filesystem::is_directory(path)) {
            m_caPath.assign(path);
            break;
        }
    }
#endif // PLUTOBOOK_AUTODETECT_CA
}

DefaultResourceFetcher::~DefaultResourceFetcher()
{
    curl_global_cleanup();
}

// CURLOPT_MAXFILESIZE_LARGE (set on the handle below) only rejects a transfer whose size is known in
// advance, from a `Content-Length` header or equivalent -- it never inspects the bytes actually
// flowing through this callback. A chunked or otherwise streamed response advertises no size up
// front, so a server can stream past that limit indefinitely and MAXFILESIZE never fires. This
// struct carries the same cap into the callback so it can be enforced as a hard stop on the
// accumulated buffer regardless of transfer shape.
struct WriteCallbackContext {
    ByteArray* response;
    size_t maxDownloadSize; // 0 means unlimited, see DefaultResourceFetcher::setMaxDownloadSize()
};

static size_t writeCallback(const char* contents, size_t blockSize, size_t numberOfBlocks, WriteCallbackContext* context)
{
    size_t totalSize = blockSize * numberOfBlocks;
    if(context->maxDownloadSize > 0 && context->response->size() + totalSize > context->maxDownloadSize)
        return 0; // short count: curl aborts the transfer with CURLE_WRITE_ERROR
    context->response->insert(context->response->end(), contents, contents + totalSize);
    return totalSize;
}

static std::string curlAllowedProtocols(std::string_view allowedProtocols)
{
    std::string result;
    while(!allowedProtocols.empty()) {
        auto comma = allowedProtocols.find(',');
        auto scheme = allowedProtocols.substr(0, comma);
        stripLeadingAndTrailingSpaces(scheme);
        if(!scheme.empty() && !equals(scheme, "data", false)) {
            if(!result.empty())
                result += ',';
            result.append(scheme);
        }

        if(comma == std::string_view::npos)
            break;
        allowedProtocols.remove_prefix(comma + 1);
    }

    return result;
}

static bool parseIPv4Address(std::string_view address, uint8_t octets[4])
{
    for(int index = 0;; ++index) {
        auto dot = address.find('.');
        auto part = address.substr(0, dot);
        if(index >= 4 || part.empty() || part.length() > 3)
            return false;
        unsigned value = 0;
        for(char cc : part) {
            if(!isDigit(cc))
                return false;
            value = value * 10 + (cc - '0');
        }

        if(value > 255)
            return false;
        octets[index] = static_cast<uint8_t>(value);
        if(dot == std::string_view::npos)
            return index == 3;
        address.remove_prefix(dot + 1);
    }
}

static bool isLocalOrPrivateAddress(const char* address)
{
    if(address == nullptr)
        return false;
    std::string_view input(address);
    if(input.find(':') != std::string_view::npos) {
        if(equals(input, "::1", true))
            return true; // loopback
        return input.length() >= 3 && (input[0] == 'f' || input[0] == 'F')
            && (input[1] == 'e' || input[1] == 'E')
            && (input[2] == '8' || input[2] == '9' || input[2] == 'a' || input[2] == 'A' || input[2] == 'b' || input[2] == 'B'); // fe80::/10 link-local
    }

    uint8_t o[4];
    if(!parseIPv4Address(input, o))
        return false;
    if(o[0] == 127) return true; // 127.0.0.0/8 loopback
    if(o[0] == 169 && o[1] == 254) return true; // 169.254.0.0/16 link-local
    if(o[0] == 10) return true; // 10.0.0.0/8 private
    if(o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true; // 172.16.0.0/12 private
    if(o[0] == 192 && o[1] == 168) return true; // 192.168.0.0/16 private
    return false;
}

static int prereqCallback(void*, char* connPrimaryIp, char*, int, int)
{
    if(isLocalOrPrivateAddress(connPrimaryIp))
        return CURL_PREREQFUNC_ABORT;
    return CURL_PREREQFUNC_OK;
}

ResourceData DefaultResourceFetcher::fetchUrl(const std::string& url)
{
    return fetchUrl(url, false);
}

ResourceData DefaultResourceFetcher::fetchUrl(const std::string& url, bool trusted)
{
    if(startswith(url, "data:", false))
        return loadDataUrl(percentDecode(url));
    std::string mimeType;
    std::string textEncoding;
    auto content = ByteArrayCreate();

    WriteCallbackContext writeContext{content, m_maxDownloadSize};

    auto curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url.data());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeContext);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "PlutoBook/" PLUTOBOOK_VERSION_STRING);

    if(!m_caInfo.empty())
        curl_easy_setopt(curl, CURLOPT_CAINFO, m_caInfo.data());
    if(!m_caPath.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAPATH, m_caPath.data());
    }

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, m_verifyPeer ? 2L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, m_verifyHost ? 1L : 0L);
#ifdef CURLSSLOPT_NATIVE_CA
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, m_followRedirects);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, m_maxRedirects);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, m_connectTimeout);

    // Rejects the transfer up front when a size is advertised in advance (Content-Length or
    // equivalent) and exceeds the cap. This is only a first line of defense: it has no effect on
    // chunked/streamed responses that never advertise a size, which is what writeCallback's hard cap
    // (via WriteCallbackContext above) is for. A limit of 0 means unlimited, matching curl's own
    // default of "no limit" for this option.
    if(m_maxDownloadSize > 0)
        curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)m_maxDownloadSize);

    // A redirect target is never the URL anyone explicitly asked for, whether the initiating
    // request is the trusted top-level load or an untrusted sub-resource fetch, and whatever the
    // configured allowlist is: always cap redirects to http/https.
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    // The scheme allowlist and internal-network filter only guard untrusted sub-resource fetches
    // (images, stylesheets, fonts, ...). The trusted top-level document URL (Book::loadUrl) keeps
    // whatever scheme/destination the caller explicitly chose; the URL validator (if any) still ran
    // for it in ResourceLoader::loadUrl before we got here.
    std::string allowedProtocols;
    if(!trusted) {
        allowedProtocols = curlAllowedProtocols(m_allowedProtocols);
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, allowedProtocols.data());
        if(!m_allowLocalNetwork)
            curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, prereqCallback);
    }

    auto response = curl_easy_perform(curl);
    if(response == CURLE_OK) {
        const char* contentType = nullptr;
        auto response = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &contentType);
        if(response == CURLE_OK && contentType) {
            parseContentType(contentType, mimeType, textEncoding);
        }

        if(mimeType.empty()) {
            mimeTypeFromPath(mimeType, percentDecode(url.substr(0, url.rfind('?'))));
        }
    }

    curl_easy_cleanup(curl);
    if(response == CURLE_OK)
        return ResourceData(content->data(), content->size(), mimeType, textEncoding, ByteArrayDestroy, content);
    if(response == CURLE_FILESIZE_EXCEEDED || response == CURLE_WRITE_ERROR) {
        // CURLE_FILESIZE_EXCEEDED comes from the CURLOPT_MAXFILESIZE_LARGE pre-check above;
        // CURLE_WRITE_ERROR is what curl reports when writeCallback returns a short count, which it
        // only ever does when the accumulated size would exceed m_maxDownloadSize. Either way, give a
        // clear, specific message instead of curl's generic strerror for this code.
        plutobook_set_error_message("Unable to fetch URL '%s': download size exceeds the %zu byte maximum", url.data(), m_maxDownloadSize);
    } else {
        plutobook_set_error_message("Unable to fetch URL '%s': %s", url.data(), curl_easy_strerror(response));
    }
    ByteArrayDestroy(content);
    return ResourceData();
}

#else

DefaultResourceFetcher::DefaultResourceFetcher() = default;
DefaultResourceFetcher::~DefaultResourceFetcher() = default;

static bool isProtocolAllowed(std::string_view allowedProtocols, std::string_view scheme)
{
    while(!allowedProtocols.empty()) {
        auto comma = allowedProtocols.find(',');
        auto entry = allowedProtocols.substr(0, comma);
        stripLeadingAndTrailingSpaces(entry);
        if(equals(entry, scheme, false))
            return true;
        if(comma == std::string_view::npos)
            break;
        allowedProtocols.remove_prefix(comma + 1);
    }

    return false;
}

ResourceData DefaultResourceFetcher::fetchUrl(const std::string& url)
{
    return fetchUrl(url, false);
}

ResourceData DefaultResourceFetcher::fetchUrl(const std::string& url, bool trusted)
{
    if(startswith(url, "data:", false))
        return loadDataUrl(percentDecode(url));
    std::string_view input(url);
    if(!startswith(input, "file://", false)) {
        plutobook_set_error_message("Unable to fetch URL '%s': Unsupported protocol", url.data());
        return ResourceData();
    }

    // Same trust distinction as the curl build: the allowlist only guards untrusted sub-resource
    // fetches, not the trusted top-level document URL (Book::loadUrl). There is no network here to
    // apply an internal-address filter to.
    if(!trusted && !isProtocolAllowed(m_allowedProtocols, "file")) {
        plutobook_set_error_message("Unable to fetch URL '%s': Unsupported protocol", url.data());
        return ResourceData();
    }

    input.remove_prefix(7);
    if(input.size() >= 3 && input[0] == '/' && isAlpha(input[1]) && input[2] == ':') {
        input.remove_prefix(1);
    }

    auto filename = percentDecode(input.substr(0, input.rfind('?')));
#ifdef _WIN32
    std::replace(filename.begin(), filename.end(), '/', '\\');
#endif

    std::ifstream in(filename, std::ios::ate | std::ios::binary);
    if(!in.is_open()) {
        plutobook_set_error_message("Unable to fetch URL '%s': %s", url.data(), std::strerror(errno));
        return ResourceData();
    }

    std::string mimeType;
    std::string textEncoding;
    mimeTypeFromPath(mimeType, filename);

    // m_maxDownloadSize (V04) is deliberately not enforced here: it targets an attacker-controlled
    // remote server streaming an unbounded body past the caller's expectations, which local
    // filesystem access does not model -- the size is known up front (tellg) and reading it is a
    // single bounded allocation, not an open-ended transfer. Capping it here would risk silently
    // truncating a legitimate large local file with no equivalent benefit.
    auto content = ByteArrayCreate(in.tellg());
    in.seekg(0, std::ios::beg);
    in.read(content->data(), content->size());
    in.close();

    return ResourceData(content->data(), content->size(), mimeType, textEncoding, ByteArrayDestroy, content);
}

#endif // PLUTOBOOK_HAS_CURL

ResourceData ResourceLoader::loadUrl(const Url& url, ResourceFetcher* customFetcher, bool trusted)
{
    const auto& validator = globalUrlValidator();
    if(validator && !validator(url.value())) {
        plutobook_set_error_message("Unable to fetch URL '%s': rejected by URL validator", url.value().data());
        return ResourceData();
    }

    if(url.protocolIs("data"))
        return loadDataUrl(percentDecode(url.value()));
    if(customFetcher == nullptr)
        customFetcher = defaultResourceFetcher();
    return customFetcher->fetchUrl(url.value(), trusted);
}

Url ResourceLoader::baseUrl()
{
    auto path = std::filesystem::current_path().generic_string();
    if(!path.empty() && path.front() != '/')
        path.insert(path.begin(), '/');
    return Url("file://" + path + "/");
}

Url ResourceLoader::completeUrl(std::string_view value)
{
    return baseUrl().complete(value);
}

DefaultResourceFetcher* defaultResourceFetcher()
{
    static DefaultResourceFetcher defaultFetcher;
    return &defaultFetcher;
}

} // namespace plutobook
