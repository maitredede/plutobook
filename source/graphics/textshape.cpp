/*
 * Copyright (c) 2022-2026 Samuel Ugochukwu <sammycageagle@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "textshape.h"
#include "fontresource.h"
#include "graphicscontext.h"
#include "geometry.h"
#include "textbreakiterator.h"

#include <algorithm>

#include <unicode/uchar.h>
#include <unicode/uscript.h>
#include <hb-cplusplus.hh>
#include <cairo-ft.h>

namespace plutobook {

TextShapeRunGlyphDataList::TextShapeRunGlyphDataList(Heap* heap, size_t size)
    : m_data(new (heap) TextShapeRunGlyphData[size])
    , m_size(size)
{
}

std::unique_ptr<TextShapeRun> TextShapeRun::create(Heap* heap, const SimpleFontData* fontData, uint32_t offset, uint32_t length, float width, TextShapeRunGlyphDataList glyphs)
{
    return std::unique_ptr<TextShapeRun>(new (heap) TextShapeRun(fontData, offset, length, width, std::move(glyphs)));
}

TextShapeRun::TextShapeRun(const SimpleFontData* fontData, uint32_t offset, uint32_t length, float width, TextShapeRunGlyphDataList glyphs)
    : m_fontData(fontData)
    , m_offset(offset)
    , m_length(length)
    , m_width(width)
    , m_glyphs(std::move(glyphs))
    , m_advancesNonNegative(true)
{
    // Precompute the running advance total once so positionForOffset()/offsetForPosition() can
    // binary search the (monotonic) glyph array instead of rescanning it from index 0 on every
    // call -- line layout queries these once per line, so a linear rescan makes a long run O(n^2).
    float cumulativeAdvance = 0.f;
    const auto numGlyphs = m_glyphs.size();
    for(size_t index = 0; index < numGlyphs; ++index) {
        auto& glyphData = m_glyphs[index];
        if(glyphData.advance < 0.f)
            m_advancesNonNegative = false;
        cumulativeAdvance += glyphData.advance;
        glyphData.advanceUpTo = cumulativeAdvance;
    }
}

// Returns the smallest index in [0, n) for which pred holds, given that pred(i) is false for a
// prefix of indices and true from then on (monotonic). Returns n if pred never holds.
template<typename Pred>
static uint32_t lowerBoundIndex(uint32_t n, Pred&& pred)
{
    uint32_t lo = 0;
    uint32_t hi = n;
    while(lo < hi) {
        auto mid = lo + (hi - lo) / 2;
        if(pred(mid))
            hi = mid;
        else
            lo = mid + 1;
    }

    return lo;
}

uint32_t TextShapeRun::glyphIndexForOffset(uint32_t offset, Direction direction) const
{
    const auto numGlyphs = m_glyphs.size();
    if(direction == Direction::Rtl) {
        // characterIndex is non-increasing along the glyph array for an RTL run: find the first
        // glyph whose characterIndex has dropped below offset.
        return lowerBoundIndex(numGlyphs, [&](uint32_t i) { return m_glyphs[i].characterIndex < offset; });
    }

    // characterIndex is non-decreasing along the glyph array for an LTR run: find the first
    // glyph whose characterIndex has reached offset.
    return lowerBoundIndex(numGlyphs, [&](uint32_t i) { return m_glyphs[i].characterIndex >= offset; });
}

float TextShapeRun::positionForOffset(uint32_t offset, Direction direction) const
{
    assert(offset <= m_length);
    auto index = glyphIndexForOffset(offset, direction);
    return index == 0 ? 0.f : m_glyphs[index - 1].advanceUpTo;
}

float TextShapeRun::positionForVisualOffset(uint32_t offset, Direction direction) const
{
    assert(offset < m_length);
    if(direction == Direction::Rtl)
        offset = m_length - offset - 1;
    return positionForOffset(offset, direction);
}

uint32_t TextShapeRun::offsetForPosition(float position, Direction direction) const
{
    assert(position >= 0.f && position <= m_width);
    if(position <= 0.f)
        return direction == Direction::Ltr ? 0 : m_length;
    const auto numGlyphs = m_glyphs.size();
    if(m_advancesNonNegative) {
        // advanceUpTo is non-decreasing along the glyph array in this (common) case, so the first
        // glyph whose cumulative advance crosses `position` can be found by binary search. Glyphs
        // sharing a cluster share a characterIndex, so it does not matter whether the search lands
        // on the first or last glyph of the crossing cluster -- the returned characterIndex is the
        // same either way, matching the linear scan below exactly.
        auto index = direction == Direction::Rtl
            ? lowerBoundIndex(numGlyphs, [&](uint32_t i) { return position <= m_glyphs[i].advanceUpTo; })
            : lowerBoundIndex(numGlyphs, [&](uint32_t i) { return position < m_glyphs[i].advanceUpTo; });
        if(index == numGlyphs)
            return direction == Direction::Rtl ? 0 : m_length;
        return m_glyphs[index].characterIndex;
    }

    // Fallback for the rare run containing a negative advance (eg. sufficiently negative
    // letter-spacing/word-spacing applied to a narrow glyph), where the cumulative advance is not
    // guaranteed monotonic and a binary search could disagree with a left-to-right scan. Kept
    // verbatim from the original implementation so behavior is unchanged for these runs.
    uint32_t glyphIndex = 0;
    float currentPosition = 0.f;
    while(glyphIndex < numGlyphs) {
        currentPosition += m_glyphs[glyphIndex].advance;

        auto characterIndex = m_glyphs[glyphIndex].characterIndex;
        while(glyphIndex < numGlyphs - 1 && characterIndex == m_glyphs[glyphIndex + 1].characterIndex) {
            currentPosition += m_glyphs[++glyphIndex].advance;
        }

        if((direction == Direction::Ltr && position < currentPosition)
            || (direction == Direction::Rtl && position <= currentPosition)) {
            return characterIndex;
        }

        ++glyphIndex;
    }

    return direction == Direction::Rtl ? 0 : m_length;
}

static EmojiPolicy resolveEmojiPolicy(FontVariantEmoji variantEmoji, const uint16_t* characters, int length)
{
    int i = 0;
    uint32_t baseCharacter;
    U16_NEXT(characters, i, length, baseCharacter);

    if(i < length) {
        uint32_t nextCharacter;
        U16_NEXT(characters, i, length, nextCharacter);
        if(nextCharacter == kVariationSelector15Character)
            return EmojiPolicy::RequireText;
        if(nextCharacter == kVariationSelector16Character) {
            return EmojiPolicy::RequireEmoji;
        }
    }

    switch(variantEmoji) {
    case FontVariantEmoji::Normal:
        if(baseCharacter > 0xFF && u_hasBinaryProperty(baseCharacter, UCHAR_EMOJI_PRESENTATION))
            return EmojiPolicy::RequireEmoji;
        break;
    case FontVariantEmoji::Text:
        return EmojiPolicy::RequireText;
    case FontVariantEmoji::Emoji:
        if(u_hasBinaryProperty(baseCharacter, UCHAR_EMOJI))
            return EmojiPolicy::RequireEmoji;
        break;
    case FontVariantEmoji::Unicode:
        if(u_hasBinaryProperty(baseCharacter, UCHAR_EMOJI)) {
            if(u_hasBinaryProperty(baseCharacter, UCHAR_EMOJI_PRESENTATION))
                return EmojiPolicy::RequireEmoji;
            return EmojiPolicy::RequireText;
        }
    }

    return EmojiPolicy::NoPreference;
}

static const SimpleFontData* resolveFontData(const Font* font, const uint16_t* characters, int length, FontVariantEmoji variantEmoji)
{
    return font->fontDataForCharacters(characters, length, resolveEmojiPolicy(variantEmoji, characters, length));
}

constexpr int kMaxGlyphs = 1 << 16;
constexpr int kMaxCharacters = kMaxGlyphs;

#define HB_TO_FLT(v) (static_cast<float>(v) / (1 << 16))

RefPtr<TextShape> TextShape::createForText(const UString& text, Direction direction, bool disableSpacing, const BoxStyle* style)
{
    assert(!text.isEmpty());
    const auto* font = style->font();
    const auto& lang = font->lang();
    auto fontFeatures = style->fontFeatures();
    auto fontVariantEmoji = style->fontVariantEmoji();
    auto letterSpacing = disableSpacing ? 0 : style->letterSpacing();
    auto wordSpacing = disableSpacing ? 0 : style->wordSpacing();
    auto heap = style->heap();

    thread_local hb::unique_ptr<hb_buffer_t> hbBuffer(hb_buffer_create());
    auto hbDirection = direction == Direction::Ltr ? HB_DIRECTION_LTR : HB_DIRECTION_RTL;
    auto hbLanguage = hb_language_from_string(lang.data(), lang.size());
    auto textBuffer = reinterpret_cast<const uint16_t*>(text.getBuffer());

    float totalWidth = 0.f;
    int startIndex = 0;
    int totalLength = text.length();
    TextShapeRunList textRuns(heap);

    CharacterBreakIterator iterator(text, font->locale());
    auto character = text.char32At(startIndex);
    auto nextIndex = iterator.nextBreakOpportunity(startIndex, totalLength);
    auto nextFontData = resolveFontData(font, textBuffer + startIndex, nextIndex, fontVariantEmoji);

    UErrorCode errorCode = U_ZERO_ERROR;
    auto nextScriptCode = uscript_getScript(character, &errorCode);
    while(totalLength > 0) {
        auto fontData = nextFontData;
        auto scriptCode = nextScriptCode;
        if(!fontData || U_FAILURE(errorCode))
            break;
        auto numCharacters = nextIndex - startIndex;
        const auto endIndex = startIndex + totalLength;
        while(nextIndex < endIndex) {
            const auto clusterOffset = nextIndex;
            character = text.char32At(clusterOffset);
            nextIndex = iterator.nextBreakOpportunity(clusterOffset, endIndex);

            const auto clusterLength = nextIndex - clusterOffset;
            if(!treatAsZeroWidthSpace(character)) {
                nextFontData = resolveFontData(font, textBuffer + clusterOffset, clusterLength, fontVariantEmoji);
                nextScriptCode = uscript_getScript(character, &errorCode);
                if(fontData != nextFontData || U_FAILURE(errorCode))
                    break;
                if(nextScriptCode != USCRIPT_INHERITED && nextScriptCode != USCRIPT_COMMON) {
                    if(scriptCode == USCRIPT_INHERITED || scriptCode == USCRIPT_COMMON) {
                        scriptCode = nextScriptCode;
                    } else if(scriptCode != nextScriptCode && !uscript_hasScript(character, scriptCode)) {
                        break;
                    }
                }
            }

            numCharacters += clusterLength;
        }

        assert(numCharacters > 0);
        auto scriptName = uscript_getShortName(scriptCode);
        auto hbScript = hb_script_from_string(scriptName, -1);

        std::vector<hb_feature_t> hbFeatures;
        auto addFeatures = [&hbFeatures](const FontFeatureList& features) {
            for(const auto& feature : features) {
                hb_feature_t hbFeature;
                hbFeature.tag = feature.first.value();
                hbFeature.value = feature.second;
                hbFeature.start = 0;
                hbFeature.end = static_cast<unsigned>(-1);
                hbFeatures.push_back(hbFeature);
            }
        };

        addFeatures(fontFeatures);
        addFeatures(fontData->features());

        while(numCharacters > 0) {
            const auto itemLength = std::min(numCharacters, kMaxCharacters);

            hb_buffer_reset(hbBuffer);
            hb_buffer_add_utf16(hbBuffer, textBuffer + startIndex, itemLength, 0, itemLength);
            hb_buffer_set_direction(hbBuffer, hbDirection);
            hb_buffer_set_language(hbBuffer, hbLanguage);
            hb_buffer_set_script(hbBuffer, hbScript);
            hb_shape(fontData->hbFont(), hbBuffer, hbFeatures.data(), hbFeatures.size());

            auto glyphInfos = hb_buffer_get_glyph_infos(hbBuffer, nullptr);
            auto glyphPositions = hb_buffer_get_glyph_positions(hbBuffer, nullptr);
            auto numGlyphs = hb_buffer_get_length(hbBuffer);

            float width = 0.f;
            TextShapeRunGlyphDataList glyphs(heap, numGlyphs);
            for(size_t index = 0; index < numGlyphs; ++index) {
                const auto& glyphInfo = glyphInfos[index];
                const auto& glyphPosition = glyphPositions[index];

                auto& glyphData = glyphs[index];
                glyphData.glyphIndex = glyphInfo.codepoint;
                glyphData.characterIndex = glyphInfo.cluster;
                glyphData.xOffset = HB_TO_FLT(glyphPosition.x_offset);
                glyphData.yOffset = -HB_TO_FLT(glyphPosition.y_offset);
                glyphData.advance = HB_TO_FLT(glyphPosition.x_advance - glyphPosition.y_advance);

                if(letterSpacing || wordSpacing) {
                    auto character = text.charAt(startIndex + glyphData.characterIndex);
                    if(letterSpacing && !treatAsZeroWidthSpace(character))
                        glyphData.advance += letterSpacing;
                    if(wordSpacing && treatAsSpace(character)) {
                        glyphData.advance += wordSpacing;
                    }
                }

                width += glyphData.advance;
            }

            auto textRun = TextShapeRun::create(heap, fontData, startIndex, itemLength, width, std::move(glyphs));
            totalWidth += width;
            startIndex += itemLength;
            totalLength -= itemLength;
            numCharacters -= itemLength;
            textRuns.push_back(std::move(textRun));
        }
    }

    if(direction == Direction::Rtl)
        std::reverse(textRuns.begin(), textRuns.end());
    return adoptPtr(new (heap) TextShape(text, direction, totalWidth, std::move(textRuns)));
}

RefPtr<TextShape> TextShape::createForTabs(const UString& text, Direction direction, const BoxStyle* style)
{
    auto font = style->font();
    auto heap = style->heap();

    float totalWidth = 0.f;
    int startIndex = 0;
    int totalLength = text.length();

    TextShapeRunList runs(heap);
    if(auto fontData = font->primaryFont()) {
        auto tabWidth = style->tabWidth(fontData->spaceWidth());
        auto spaceGlyph = fontData->spaceGlyph();
        while(totalLength > 0) {
            auto numGlyphs = std::min(totalLength, kMaxGlyphs);
            TextShapeRunGlyphDataList glyphs(heap, numGlyphs);
            for(int index = 0; index < numGlyphs; ++index) {
                assert(text[index + startIndex] == kTabulationCharacter);
                auto& glyphData = glyphs[index];
                glyphData.glyphIndex = spaceGlyph;
                glyphData.characterIndex = direction == Direction::Ltr ? index : numGlyphs - index - 1;
                glyphData.xOffset = 0.f;
                glyphData.yOffset = 0.f;
                glyphData.advance = tabWidth;
            }

            auto run = TextShapeRun::create(heap, fontData, startIndex, numGlyphs, numGlyphs * tabWidth, std::move(glyphs));
            totalWidth += run->width();
            startIndex += numGlyphs;
            totalLength -= numGlyphs;
            runs.push_back(std::move(run));
        }
    }

    return adoptPtr(new (heap) TextShape(text, direction, totalWidth, std::move(runs)));
}

uint32_t TextShape::offsetForPosition(float position) const
{
    auto currentOffset = m_direction == Direction::Ltr ? 0 : m_text.length();
    if(position <= 0.f)
        return currentOffset;
    float currentPosition = 0;
    for(const auto& run : m_runs) {
        if(m_direction == Direction::Rtl)
            currentOffset -= run->length();
        auto runPosition = position - currentPosition;
        if(runPosition >= 0.f && runPosition <= run->width())
            return currentOffset + run->offsetForPosition(runPosition, m_direction);
        if(m_direction == Direction::Ltr)
            currentOffset += run->length();
        currentPosition += run->width();
    }

    return currentOffset;
}

float TextShape::positionForOffset(uint32_t offset) const
{
    auto currentOffset = offset;
    if(m_direction == Direction::Rtl && offset < m_text.length()) {
        currentOffset = m_text.length() - offset - 1;
    }

    float position = 0;
    float currentPosition = 0;
    for(const auto& run : m_runs) {
        if(currentOffset < run->length()) {
            position = currentPosition + run->positionForVisualOffset(currentOffset, m_direction);
            break;
        }

        currentOffset -= run->length();
        currentPosition += run->width();
    }

    if(!position && offset == m_text.length())
        return m_direction == Direction::Rtl ? 0.f : m_width;
    return position;
}

TextShape::~TextShape() = default;

TextShape::TextShape(const UString& text, Direction direction, float width, TextShapeRunList runs)
    : m_text(text)
    , m_direction(direction)
    , m_width(width)
    , m_runs(std::move(runs))
{
}

UString TextShapeView::text() const
{
    if(m_startOffset == m_endOffset)
        return UString();
    return m_shape->text().tempSubStringBetween(m_startOffset, m_endOffset);
}

// TextShapeView methods below all used to walk every run of the shape from its first glyph, even
// for runs entirely outside [startOffset, endOffset) -- harmless for a short view into a short
// shape, but a view onto one line of a long single-run paragraph rescanned the whole run so far on
// every call (once per line), making the run O(n^2). Runs appear offset-ascending for LTR shapes
// and offset-descending for RTL shapes (see TextShape::createForText), so a run entirely on the
// far side of the view can be skipped for O(1), the outer loop can stop once further runs are all
// out of range, and TextShapeRun::glyphIndexForOffset() binary searches straight to the first
// glyph of an overlapping run that can matter, instead of starting from glyph 0.
struct TextShapeViewRunRange {
    bool skip;
    bool stop;
    uint32_t startGlyphIndex;
};

static TextShapeViewRunRange rangeForView(const TextShapeRun& run, Direction direction, uint32_t startOffset, uint32_t endOffset)
{
    auto runStart = run.offset();
    auto runEnd = runStart + run.length();
    if(direction == Direction::Ltr) {
        if(runStart >= endOffset)
            return {true, true, 0};
        if(runEnd <= startOffset)
            return {true, false, 0};
        auto localOffset = startOffset > runStart ? startOffset - runStart : 0;
        return {false, false, run.glyphIndexForOffset(localOffset, direction)};
    }

    if(runEnd <= startOffset)
        return {true, true, 0};
    if(runStart >= endOffset)
        return {true, false, 0};
    auto localOffset = endOffset > runStart ? endOffset - runStart : 0;
    return {false, false, run.glyphIndexForOffset(localOffset, direction)};
}

uint32_t TextShapeView::expansionOpportunityCount() const
{
    if(m_startOffset == m_endOffset)
        return 0;
    uint32_t count = 0;
    auto direction = m_shape->direction();
    const auto& text = m_shape->text();
    for(const auto& run : m_shape->runs()) {
        auto range = rangeForView(*run, direction, m_startOffset, m_endOffset);
        if(range.stop)
            break;
        if(range.skip)
            continue;
        const auto& glyphs = run->glyphs();
        for(uint32_t glyphIndex = range.startGlyphIndex; glyphIndex < glyphs.size(); ++glyphIndex) {
            const auto& glyph = glyphs[glyphIndex];
            auto characterIndex = glyph.characterIndex + run->offset();
            if((direction == Direction::Ltr && characterIndex >= m_endOffset)
                || (direction == Direction::Rtl && characterIndex < m_startOffset)) {
                break;
            }

            if((direction == Direction::Ltr && characterIndex >= m_startOffset)
                || (direction == Direction::Rtl && characterIndex < m_endOffset)) {
                auto character = text.charAt(characterIndex);
                if(treatAsSpace(character)) {
                    ++count;
                }
            }
        }
    }

    return count;
}

void TextShapeView::maxAscentAndDescent(float& maxAscent, float& maxDescent) const
{
    if(m_startOffset == m_endOffset)
        return;
    auto direction = m_shape->direction();
    for(const auto& run : m_shape->runs()) {
        auto range = rangeForView(*run, direction, m_startOffset, m_endOffset);
        if(range.stop)
            break;
        if(range.skip)
            continue;
        const auto& glyphs = run->glyphs();
        for(uint32_t glyphIndex = range.startGlyphIndex; glyphIndex < glyphs.size(); ++glyphIndex) {
            const auto& glyph = glyphs[glyphIndex];
            auto characterIndex = glyph.characterIndex + run->offset();
            if((direction == Direction::Ltr && characterIndex >= m_endOffset)
                || (direction == Direction::Rtl && characterIndex < m_startOffset)) {
                break;
            }

            if((direction == Direction::Ltr && characterIndex >= m_startOffset)
                || (direction == Direction::Rtl && characterIndex < m_endOffset)) {
                maxAscent = std::max(maxAscent, run->fontData()->ascent());
                maxDescent = std::max(maxDescent, run->fontData()->descent());
            }
        }
    }
}

float TextShapeView::width(float expansion) const
{
    if(m_startOffset == m_endOffset)
        return 0.f;
    float width = 0.f;
    auto direction = m_shape->direction();
    const auto& text = m_shape->text();
    for(const auto& run : m_shape->runs()) {
        auto range = rangeForView(*run, direction, m_startOffset, m_endOffset);
        if(range.stop)
            break;
        if(range.skip)
            continue;
        const auto& glyphs = run->glyphs();
        for(uint32_t glyphIndex = range.startGlyphIndex; glyphIndex < glyphs.size(); ++glyphIndex) {
            const auto& glyph = glyphs[glyphIndex];
            auto characterIndex = glyph.characterIndex + run->offset();
            if((direction == Direction::Ltr && characterIndex >= m_endOffset)
                || (direction == Direction::Rtl && characterIndex < m_startOffset)) {
                break;
            }

            if((direction == Direction::Ltr && characterIndex >= m_startOffset)
                || (direction == Direction::Rtl && characterIndex < m_endOffset)) {
                auto character = text.charAt(characterIndex);
                if(expansion && treatAsSpace(character))
                    width += expansion;
                width += glyph.advance;
            }
        }
    }

    return width;
}

float TextShapeView::draw(GraphicsContext& context, const Point& origin, float expansion, bool stroke) const
{
    if(m_startOffset == m_endOffset)
        return 0.f;
    auto canvas = context.canvas();
    auto direction = m_shape->direction();
    auto offset = origin;
    const auto& text = m_shape->text();
    // Unlike the pure accumulators above, this loop has a visible side effect (cairo drawing calls)
    // for every run, including ones entirely outside the view -- so, unlike above, the outer loop
    // still visits every run in order and issues the same calls for it; only the (potentially
    // expensive) glyph scan is skipped/narrowed, which leaves numGlyphs at 0 exactly as the
    // original scan would have for such a run.
    for(const auto& run : m_shape->runs()) {
        auto range = rangeForView(*run, direction, m_startOffset, m_endOffset);
        const auto& glyphs = run->glyphs();
        auto startGlyphIndex = range.skip || range.stop ? glyphs.size() : range.startGlyphIndex;
        auto glyphBuffer = cairo_glyph_allocate(glyphs.size());
        uint32_t numGlyphs = 0;
        for(uint32_t glyphIndex = startGlyphIndex; glyphIndex < glyphs.size(); ++glyphIndex) {
            const auto& glyph = glyphs[glyphIndex];
            auto characterIndex = glyph.characterIndex + run->offset();
            if((direction == Direction::Ltr && characterIndex >= m_endOffset)
                || (direction == Direction::Rtl && characterIndex < m_startOffset)) {
                break;
            }

            if((direction == Direction::Ltr && characterIndex >= m_startOffset)
                || (direction == Direction::Rtl && characterIndex < m_endOffset)) {
                auto character = text.charAt(characterIndex);
                if(!treatAsZeroWidthSpace(character)) {
                    glyphBuffer[numGlyphs].index = glyph.glyphIndex;
                    glyphBuffer[numGlyphs].x = offset.x + glyph.xOffset;
                    glyphBuffer[numGlyphs].y = offset.y + glyph.yOffset;
                    numGlyphs++;
                }

                offset.x += glyph.advance;
                if(expansion && treatAsSpace(character)) {
                    offset.x += expansion;
                }
            }
        }

        cairo_set_scaled_font(canvas, run->fontData()->font());
        if(stroke) {
            cairo_glyph_path(canvas, glyphBuffer, numGlyphs);
            cairo_stroke(canvas);
        } else {
            cairo_show_glyphs(canvas, glyphBuffer, numGlyphs);
        }

        cairo_glyph_free(glyphBuffer);
    }

    return offset.x - origin.x;
}

void TextShapeView::serialize(std::ostream& o) const
{
    if(m_startOffset == m_endOffset)
        return;
    const auto& text = m_shape->text();
    auto offset = m_startOffset;
    while(offset < m_endOffset) {
        uint32_t ch;
        U16_NEXT(text, offset, m_endOffset, ch);
        if(ch == '&') {
            o << "&amp;";
        } else if(ch == '<') {
            o << "&lt;";
        } else if(ch == '>') {
            o << "&gt;";
        } else if(ch == '"') {
            o << "&quot;";
        } else if(ch == '\'') {
            o << "&apos;";
        } else if(ch >= 32 && ch < 127) {
            o << static_cast<char>(ch);
        } else {
            auto f = o.flags();
            o << "&#x" << std::hex << std::uppercase << ch << ';';
            o.flags(f);
        }
    }
}

} // namespace plutobook
