import Foundation
import iOSSecurityTools

extension RedactionTimeLimitTests {
    /// The thirteenth review's shapes: a megabyte of free text in long single words, escapes and
    /// characters outside the safe alphabet, and bodies of a megabyte of many small values, read
    /// with the body limit raised to 1 MiB.
    static let thirteenthReview = ThirteenthReviewShapes.text + ThirteenthReviewShapes.bodies(size: size, redactor: largeBodies)
}

extension RedactionTimeLimitTests {
    /// Every shape of a megabyte that the reviews timed, one test case each.
    static let ordinaryShapes: [TimedInput] = {
        var all: [TimedInput] = shapes
        all += namesAsValues
        all += nestedPayloads
        all += namesInHiddenValues
        all += attributeShapes
        all += thirteenthReview
        all += FourteenthReviewShapes.text
        all += URLInTextShapes.text
        all += QuotedKeyShapes.text
        all += MarkupQuoteShapes.text
        all += DenseFindingShapes.text
        all += DenseFindingShapes.bodies(size: size, redactor: largeBodies)
        all += DistinctScalarShapes.text
        all += DistinctScalarShapes.bodies(size: size, redactor: largeBodies)
        return all
    }()
}
