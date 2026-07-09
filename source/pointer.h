/*
 * Copyright (c) 2022-2026 Samuel Ugochukwu <sammycageagle@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef PLUTOBOOK_POINTER_H
#define PLUTOBOOK_POINTER_H

#include <algorithm>
#include <cstdint>
#include <cassert>
#include <atomic>

namespace plutobook {

template<typename T>
class RefCounted {
public:
    RefCounted() = default;

    void ref() { ++m_refCount; }
    void deref() {
        if(--m_refCount == 0) {
            delete static_cast<T*>(this);
        }
    }

    uint32_t refCount() const { return m_refCount; }
    bool hasOneRefCount() const { return m_refCount == 1; }

private:
    RefCounted(const RefCounted&) = delete;
    RefCounted& operator=(const RefCounted&) = delete;
    std::atomic_uint32_t m_refCount{1};
};

template<typename T>
inline void refIfNotNull(T* ptr)
{
    if(ptr) {
        ptr->ref();
    }
}

template<typename T>
inline void derefIfNotNull(T* ptr)
{
    if(ptr) {
        ptr->deref();
    }
}

template<typename T> class RefPtr;
template<typename T> RefPtr<T> adoptPtr(T*);

template<typename T>
class RefPtr {
public:
    RefPtr() = default;
    RefPtr(std::nullptr_t) : m_ptr(nullptr) {}
    RefPtr(T* ptr) : m_ptr(ptr) { refIfNotNull(m_ptr); }
    RefPtr(T& ref) : m_ptr(&ref) { m_ptr->ref(); }
    RefPtr(const RefPtr<T>& p) : m_ptr(p.get()) { refIfNotNull(m_ptr); }
    RefPtr(RefPtr<T>&& p) : m_ptr(p.release()) {}

    template<typename U>
    RefPtr(const RefPtr<U>& p) : m_ptr(p.get()) { refIfNotNull(m_ptr); }

    template<typename U>
    RefPtr(RefPtr<U>&& p) : m_ptr(p.release()) {}

    ~RefPtr() { derefIfNotNull(m_ptr); }

    T* get() const { return m_ptr; }
    T& operator*() const {
        assert(m_ptr);
        return *m_ptr;
    }

    T* operator->() const {
        assert(m_ptr);
        return m_ptr;
    }

    operator T*() const { return m_ptr; }
    operator bool() const { return !!m_ptr; }

    RefPtr<T>& operator=(std::nullptr_t) {
        clear();
        return *this;
    }

    RefPtr<T>& operator=(T* o) {
        RefPtr<T> p = o;
        swap(p);
        return *this;
    }

    RefPtr<T>& operator=(T& o) {
        RefPtr<T> p = o;
        swap(p);
        return *this;
    }

    RefPtr<T>& operator=(const RefPtr<T>& o) {
        RefPtr<T> p = o;
        swap(p);
        return *this;
    }

    RefPtr<T>& operator=(RefPtr<T>&& o) {
        RefPtr<T> p = std::move(o);
        swap(p);
        return *this;
    }

    template<typename U>
    RefPtr<T>& operator=(const RefPtr<U>& o) {
        RefPtr<T> p = o;
        swap(p);
        return *this;
    }

    template<typename U>
    RefPtr<T>& operator=(RefPtr<U>&& o) {
        RefPtr<T> p = std::move(o);
        swap(p);
        return *this;
    }

    void swap(RefPtr<T>& o) {
        std::swap(m_ptr, o.m_ptr);
    }

    T* release() {
        T* ptr = m_ptr;
        m_ptr = nullptr;
        return ptr;
    }

    void clear() {
        derefIfNotNull(m_ptr);
        m_ptr = nullptr;
    }

    template<typename U>
    bool operator==(const RefPtr<U>& o) const {
        return m_ptr == o.get();
    }

    template<typename U>
    bool operator<(const RefPtr<U>& o) const {
        return m_ptr < o.get();
    }

    friend RefPtr<T> adoptPtr<T>(T*);

private:
    RefPtr(T* ptr, std::nullptr_t) : m_ptr(ptr) {}
    T* m_ptr{nullptr};
};

template<typename T>
inline RefPtr<T> adoptPtr(T* ptr)
{
    return RefPtr<T>(ptr, nullptr);
}

template<class T>
inline void swap(RefPtr<T>& a, RefPtr<T>& b)
{
    a.swap(b);
}

template<typename T>
inline bool operator==(const RefPtr<T>& a, std::nullptr_t)
{
    return a.get() == nullptr;
}

template<typename T>
inline bool operator==(std::nullptr_t, const RefPtr<T>& a)
{
    return nullptr == a.get();
}

template<typename T>
struct is_a {
    template<typename U>
    static bool check(const U& value);
};

template<typename T, typename U>
constexpr bool is(U& value) {
    return is_a<T>::check(value);
}

template<typename T, typename U>
constexpr bool is(const U& value) {
    return is_a<T>::check(value);
}

template<typename T, typename U>
constexpr bool is(U* value) {
    return value && is_a<T>::check(*value);
}

template<typename T, typename U>
constexpr bool is(const U* value) {
    return value && is_a<T>::check(*value);
}

template<typename T, typename U>
constexpr bool is(RefPtr<U>& value) {
    return value && is_a<T>::check(*value);
}

template<typename T, typename U>
constexpr bool is(const RefPtr<U>& value) {
    return value && is_a<T>::check(*value);
}

// Security note (V15 hardening pass): the pointer/RefPtr overloads of to<T>() below already perform
// a real runtime check via is<T>() and fail safe (return nullptr) in release builds -- they were
// never assert-only, so they are not a downcast/type-confusion risk regardless of NDEBUG. Only the
// two reference-taking overloads immediately below rely on assert() alone, which compiles out under
// NDEBUG and leaves a bare static_cast<T&>.
//
// We deliberately do NOT add a runtime check to these two overloads. Reasons:
//  - A reference-returning cast has no safe "failure" value to return, so a runtime check would have
//    to abort/throw on mismatch. Throwing is not viable here: these calls sit deep in CSS value
//    resolution and layout, most of it not exception-safety-audited, and aborting is no better than
//    the crash we are trying to avoid.
//  - There are ~300+ call sites (grep for `to<` under source/), overwhelmingly in CSS value/property
//    resolution (cssstylesheet.cpp, cssrule.cpp, counters.cpp, ...) where the target type was just
//    established by the caller's own control flow (a grammar production, a prior switch on the
//    value's kind, etc.) immediately before the cast -- the same "invariant established one line
//    above" pattern already used throughout this codebase (see CSSTokenStream::consume() in
//    csstokenizer.h). Adding a checked-and-abort (or checked-and-throw) path to all of them is a
//    blanket hot-path cost across CSS parsing and table/box layout with no concrete bug behind it:
//    the audit that flagged this (security-audit/V15-assert-bounds) found no reachable defect, only
//    a latent fuzzing target.
//  - The one surface in this audit that *was* shown to need bounds enforcement beyond assert --
//    CSSTokenizerInputStream, which processes raw untrusted CSS bytes one at a time -- has been
//    hardened directly in csstokenizer.h (advance()/consume()/substring() now clamp instead of
//    relying solely on assert).
//
// If a future fuzzing pass (see security-audit/V15-assert-bounds/poc/note.md) finds a concrete
// mismatched-type path reaching one of these reference overloads (e.g. via a malformed table box
// tree fixup), prefer adding a checked, pointer-returning `to<T>()` call at that specific call site
// (falling back to the pointer overload's existing nullptr-on-mismatch behavior) rather than
// instrumenting every call site here.
template<typename T, typename U>
constexpr T& to(U& value) {
    assert(is<T>(value));
    return static_cast<T&>(value);
}

template<typename T, typename U>
constexpr const T& to(const U& value) {
    assert(is<T>(value));
    return static_cast<const T&>(value);
}

template<typename T, typename U>
constexpr T* to(U* value) {
    if(!is<T>(value))
        return nullptr;
    return static_cast<T*>(value);
}

template<typename T, typename U>
constexpr const T* to(const U* value) {
    if(!is<T>(value))
        return nullptr;
    return static_cast<const T*>(value);
}

template<typename T, typename U>
constexpr RefPtr<T> to(const RefPtr<U>& value) {
    if(!is<T>(value))
        return nullptr;
    return static_cast<T&>(*value);
}

template<typename T, typename U>
constexpr RefPtr<T> to(RefPtr<U>& value) {
    if(!is<T>(value))
        return nullptr;
    return static_cast<T&>(*value);
}

} // namespace plutobook

#endif // PLUTOBOOK_POINTER_H
