#include "pe/Strings.h"

#include <algorithm>

namespace pemcp {

namespace {

bool printableAscii(std::uint8_t b) {
    return (b >= 0x20 && b < 0x7F) || b == '\t';
}

} // namespace

std::vector<FoundString> findStrings(std::span<const std::uint8_t> data, std::uint64_t base, const StringScan& scan) {
    std::vector<FoundString> out;
    const std::size_t n = data.size();
    const std::size_t minLength = std::max<std::size_t>(scan.minLength, 1);

    if (scan.ascii) {
        std::size_t i = 0;
        while (i < n && out.size() < scan.maxResults) {
            if (!printableAscii(data[i])) {
                ++i;
                continue;
            }
            std::size_t j = i;
            while (j < n && printableAscii(data[j])) {
                ++j;
            }
            if (j - i >= minLength) {
                FoundString s;
                s.offset = base + i;
                s.length = static_cast<std::uint32_t>(j - i);
                s.text.assign(reinterpret_cast<const char*>(data.data() + i), std::min(j - i, scan.maxTextLength));
                out.push_back(std::move(s));
            }
            i = j;
        }
    }

    if (scan.wide) {
        std::vector<FoundString> wide;
        // A run can start at an odd offset in raw data, so both alignments
        // are searched. A run at one alignment is never a run at the other:
        // its zero high bytes are not printable.
        for (std::size_t phase = 0; phase < 2; ++phase) {
            std::size_t i = phase;
            while (i + 1 < n && wide.size() < scan.maxResults) {
                if (!(printableAscii(data[i]) && data[i + 1] == 0)) {
                    i += 2;
                    continue;
                }
                std::size_t j = i;
                std::string text;
                while (j + 1 < n && printableAscii(data[j]) && data[j + 1] == 0) {
                    if (text.size() < scan.maxTextLength) {
                        text += static_cast<char>(data[j]);
                    }
                    j += 2;
                }
                const std::size_t chars = (j - i) / 2;
                if (chars >= minLength) {
                    FoundString s;
                    s.offset = base + i;
                    s.length = static_cast<std::uint32_t>(chars);
                    s.wide = true;
                    s.text = std::move(text);
                    wide.push_back(std::move(s));
                }
                i = j;
            }
        }
        out.insert(out.end(), std::make_move_iterator(wide.begin()), std::make_move_iterator(wide.end()));
        std::stable_sort(out.begin(), out.end(), [](const FoundString& a, const FoundString& b) { return a.offset < b.offset; });
        if (out.size() > scan.maxResults) {
            out.resize(scan.maxResults);
        }
    }
    return out;
}

} // namespace pemcp
