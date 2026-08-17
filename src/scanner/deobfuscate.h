#pragma once

#include <string>
#include <vector>

#include "core/core.h"

namespace abyss::scanner {

// Bounded, non-executing static normalization and structural detection for
// obfuscated JavaScript loader patterns. Every function here treats its
// input strictly as data: character transforms (decode, reverse, join) are
// applied the same way a calculator applies arithmetic — nothing is ever
// passed to eval(), Function(), a shell, or any interpreter, in this
// process or any other. Every decode operation has explicit input-size,
// output-size, recursion-depth, expansion-ratio, and operation-count
// bounds so a pathological/adversarial input cannot cause unbounded work.
//
// This exists because literal IOC strings (rules/campaigns/*.rules) only
// catch a byte-for-byte-unchanged payload. A campaign that rotates its
// marker property name, its literal values, or wraps the same logic in a
// different encoding defeats literal matching trivially — these detectors
// target the *shape* of the obfuscation technique instead. See
// README.md and README.md.
std::vector<Finding> scanObfuscationIndicators(const std::string& relPath, const std::string& content);

} // namespace abyss::scanner
