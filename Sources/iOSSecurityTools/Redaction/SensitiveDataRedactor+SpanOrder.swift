/// The order of the findings: by start, the longer of two that start together first.
extension SensitiveDataRedactor {
    static func isBefore(_ span: Span, _ other: Span) -> Bool {
        span.start != other.start ? span.start < other.start : span.end > other.end
    }

    /// Sorts the spans in place, stably and without a buffer. The findings come as a few runs that
    /// are each in order (those of each detector, the scan's, the cut), which are merged pairwise
    /// by rotations, as Go's `sort.Stable` merges (SymMerge, Kim and Kutzner 2004). The standard
    /// sort took a buffer of half the spans: 3 MB for a megabyte of `1:2@a.bc`, whose user info
    /// passwords and addresses are found by two detectors. Spans that are in order already are
    /// read once and left as they are.
    static func sortRuns(_ spans: inout [Span]) {
        var bounds = [0]
        for k in spans.indices.dropFirst() where isBefore(spans[k], spans[k - 1]) { bounds.append(k) }
        guard bounds.count > 1 else { return }
        bounds.append(spans.count)
        spans.withUnsafeMutableBufferPointer { buffer in
            while bounds.count > 2 {
                var next = [0]
                var i = 0
                while i + 2 < bounds.count {
                    symMerge(buffer, bounds[i], bounds[i + 1], bounds[i + 2])
                    next.append(bounds[i + 2])
                    i += 2
                }
                // A run without a partner in this round is merged in the next.
                if i + 1 < bounds.count { next.append(bounds[i + 1]) }
                bounds = next
            }
        }
    }

    /// Merges the runs `a..<m` and `m..<b`, each in order, keeping spans that are neither before the
    /// other in the order they were.
    private static func symMerge(_ data: UnsafeMutableBufferPointer<Span>, _ a: Int, _ m: Int, _ b: Int) {
        if m - a == 1 {
            // Moves data[a] to the place among m..<b where it belongs.
            var i = m
            var j = b
            while i < j {
                let h = (i + j) / 2
                if isBefore(data[h], data[a]) { i = h + 1 } else { j = h }
            }
            for k in a..<(i - 1) { data.swapAt(k, k + 1) }
            return
        }
        if b - m == 1 {
            // Moves data[m] to the place among a..<m where it belongs.
            var i = a
            var j = m
            while i < j {
                let h = (i + j) / 2
                if !isBefore(data[m], data[h]) { i = h + 1 } else { j = h }
            }
            var k = m
            while k > i {
                data.swapAt(k, k - 1)
                k -= 1
            }
            return
        }
        let mid = (a + b) / 2
        let n = mid + m
        var start: Int
        var r: Int
        if m > mid {
            start = n - b
            r = mid
        } else {
            start = a
            r = m
        }
        let p = n - 1
        while start < r {
            let c = (start + r) / 2
            if !isBefore(data[p - c], data[c]) { start = c + 1 } else { r = c }
        }
        let end = n - start
        if start < m, m < end { rotate(data, start, m, end) }
        if a < start, start < mid { symMerge(data, a, start, mid) }
        if mid < end, end < b { symMerge(data, mid, end, b) }
    }

    /// Swaps the blocks `a..<m` and `m..<b`.
    private static func rotate(_ data: UnsafeMutableBufferPointer<Span>, _ a: Int, _ m: Int, _ b: Int) {
        var i = m - a
        var j = b - m
        while i != j {
            if i > j {
                swapRange(data, m - i, m, j)
                i -= j
            } else {
                swapRange(data, m - i, m + j - i, i)
                j -= i
            }
        }
        swapRange(data, m - i, m, i)
    }

    private static func swapRange(_ data: UnsafeMutableBufferPointer<Span>, _ a: Int, _ b: Int, _ count: Int) {
        for k in 0..<count { data.swapAt(a + k, b + k) }
    }
}
