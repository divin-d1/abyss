#include "test_harness.h"

#include <algorithm>

#include "scanner/deobfuscate.h"

using namespace abyss;
using namespace abyss::scanner;

namespace {
bool hasRule(const std::vector<Finding>& findings, const std::string& ruleId) {
    return std::any_of(findings.begin(), findings.end(), [&](const Finding& f) { return f.ruleId == ruleId; });
}
} // namespace

ABYSS_TEST("obfuscation: rotated global[_V] marker (Defender-observed shape) is caught structurally") {
    std::string content = "global['_V']='A9-3800-1';var x = 1;";
    auto findings = scanObfuscationIndicators("config.js", content);
    ABYSS_CHECK(hasRule(findings, "core.obfuscation_global_marker_pattern"));
}

ABYSS_TEST("obfuscation: an entirely different global[...] property/value shape is still caught by the pattern") {
    // Proves this is shape-based, not tied to the two exact confirmed
    // values -- a hypothetical future rotation with a new property name
    // and new numeric value must still be caught.
    std::string content = "global['__cfg']='Z7-99-4';doSomething();";
    auto findings = scanObfuscationIndicators("config.js", content);
    ABYSS_CHECK(hasRule(findings, "core.obfuscation_global_marker_pattern"));
}

ABYSS_TEST("obfuscation: ordinary global property assignment is not flagged") {
    std::string content = "global.myAppConfig = { debug: true, verbose: false };";
    auto findings = scanObfuscationIndicators("config.js", content);
    ABYSS_CHECK(!hasRule(findings, "core.obfuscation_global_marker_pattern"));
}

ABYSS_TEST("obfuscation: base64 content decoding to a dangerous keyword is caught") {
    // base64("require('child_process').exec('whoami')")
    std::string b64 = "cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ3dob2FtaScp";
    std::string content = "const payload = \"" + b64 + "\";";
    auto findings = scanObfuscationIndicators("loader.js", content);
    ABYSS_CHECK(hasRule(findings, "core.obfuscation_base64_hidden_keyword"));
}

ABYSS_TEST("obfuscation: base64-shaped but benign data (e.g. an image data URI) is not flagged") {
    // A long base64 blob that decodes to arbitrary binary noise, not a
    // dangerous keyword -- must not fire.
    std::string content =
        "const icon = \"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=\";";
    auto findings = scanObfuscationIndicators("icon.js", content);
    ABYSS_CHECK(!hasRule(findings, "core.obfuscation_base64_hidden_keyword"));
}

ABYSS_TEST("obfuscation: hex-escaped content decoding to a dangerous keyword is caught") {
    // "require(" spelled entirely in \xNN escapes.
    std::string hexRequire;
    for (char c : std::string("require(")) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c);
        hexRequire += buf;
    }
    std::string content = "var s = \"" + hexRequire + "'fs')\";";
    auto findings = scanObfuscationIndicators("loader.js", content);
    ABYSS_CHECK(hasRule(findings, "core.obfuscation_hex_escape_hidden_keyword"));
}

ABYSS_TEST("obfuscation: hex escapes that decode to plain non-dangerous text are not flagged") {
    std::string content = "var greeting = \"\\x68\\x65\\x6c\\x6c\\x6f\";"; // "hello"
    auto findings = scanObfuscationIndicators("greet.js", content);
    ABYSS_CHECK(!hasRule(findings, "core.obfuscation_hex_escape_hidden_keyword"));
}

ABYSS_TEST("obfuscation: percent-encoded content decoding to a dangerous keyword is caught") {
    std::string content = "var s = \"require%28'child_process'%29\";";
    auto findings = scanObfuscationIndicators("loader.js", content);
    ABYSS_CHECK(hasRule(findings, "core.obfuscation_percent_encoded_hidden_keyword"));
}

ABYSS_TEST("obfuscation: reversed-string-literal idiom revealing a dangerous keyword is caught") {
    std::string reversedRequire = "require(child_process)";
    std::reverse(reversedRequire.begin(), reversedRequire.end());
    std::string content = "var x = '" + reversedRequire + "'.split('').reverse().join('');";
    auto findings = scanObfuscationIndicators("loader.js", content);
    ABYSS_CHECK(hasRule(findings, "core.obfuscation_reversed_string_hidden_keyword"));
}

ABYSS_TEST("obfuscation: reversed-string idiom with benign content is not flagged") {
    std::string content = "var x = 'hello world'.split('').reverse().join('');";
    auto findings = scanObfuscationIndicators("greet.js", content);
    ABYSS_CHECK(!hasRule(findings, "core.obfuscation_reversed_string_hidden_keyword"));
}

ABYSS_TEST("obfuscation: String.fromCharCode usage alone is Low severity, not alarming") {
    std::string content = "var c = String.fromCharCode(72, 101, 108, 108, 111);";
    auto findings = scanObfuscationIndicators("greet.js", content);
    auto it = std::find_if(findings.begin(), findings.end(),
                            [](const Finding& f) { return f.ruleId == "core.obfuscation_charcode_construction"; });
    ABYSS_CHECK(it != findings.end());
    if (it != findings.end()) ABYSS_CHECK(it->severity == Severity::Low);
}

ABYSS_TEST("obfuscation: ordinary harmless minified JavaScript produces no findings") {
    std::string content =
        "!function(e,t){\"object\"==typeof exports?module.exports=t():e.widget=t()}(this,function(){return "
        "function(e){return e*2}});";
    auto findings = scanObfuscationIndicators("bundle.min.js", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("obfuscation: ordinary 'node -e' documentation/usage text does not trigger the marker pattern") {
    std::string content = "// Example usage: node -e \"console.log('hello')\"\n"
                           "// This project does not use global[] markers.\n";
    auto findings = scanObfuscationIndicators("README.js.sample", content);
    ABYSS_CHECK(!hasRule(findings, "core.obfuscation_global_marker_pattern"));
}
