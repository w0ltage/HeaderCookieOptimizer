## Overview

The "Header & Cookie Optimizer" is a Burp Suite extension designed to help penetration testers identify and remove unnecessary HTTP headers and cookies from requests. By sending modified requests and comparing responses to a baseline, it determines which headers and cookies are essential for a valid server response, potentially reducing the attack surface or identifying verbose client behavior.

This Kotlin-based Montoya extension adds a custom tab to Burp Suite for configuration and logging, and a context menu item in the Repeater tool to initiate the optimization process on a selected request.

## Features

*   **Header Optimization**: Iteratively removes headers (except those specified to be skipped) and checks if the response changes significantly.
*   **Cookie Optimization**: After header optimization, iteratively removes individual cookies from the `Cookie` header and checks if the response changes significantly.
*   **Configurable Skip List**: Allows users to specify headers that should not be tested or removed (e.g., `Host`, `Content-Length`).
*   **Adjustable Response Difference Threshold**: Users can define the maximum percentage difference in response length that is considered "not significantly different."
*   **Configurable Request Delay**: Allows setting a delay between test requests to avoid overwhelming the server or triggering rate limits.
*   **Baseline Consistency Check**: Optionally sends the baseline request twice to check for inconsistent responses from the server, which might affect optimization reliability.
*   **Dedicated UI Tab**:
    *   Configuration settings for headers to skip, response difference threshold, and request delay.
    *   A log area to display the optimization process and results.
    *   A "Clear Logs" button.
*   **Context Menu Integration**: Adds an "Optimize Headers & Cookies" option to the right-click menu in the Repeater's request editor.
*   **Background Processing**: Runs the optimization process in a separate thread to prevent UI freezes.

## Configuration Options

The extension provides a "Header Optimizer" tab in Burp Suite with the following configuration options:

*   **Headers to skip (comma-separated)**: A comma-separated list of header names that will not be removed or tested.
    *   Default: `Host,Cookie,Content-Length,Content-Type`
*   **Max response difference (%)**: The maximum percentage difference in response length between the baseline and a test request for a header/cookie to be considered unnecessary. If the difference is greater than this value, the header/cookie is kept.
    *   Default: `5`
*   **Delay between requests (ms)**: The delay in milliseconds between sending test requests.
    *   Default: `500`
*   **Test baseline twice for consistency**: If checked, the extension will send the original request twice and compare the responses. A warning is logged if responses are inconsistent.
    *   Default: `True` (checked)

## Modern Burp Suite API documentation (Montoya API)

Here's an enhanced prompt following OpenAI and Anthropic best practices:

---

## Burp Suite Montoya API Documentation Access

Since you cannot directly access Context7 MCP, you must retrieve Burp Suite Montoya API documentation by making HTTP GET requests to the Context7 API endpoint. If you can use context7 mcp, use it.

### When to Query the API
Query the Context7 API in these scenarios:
- Before implementing any Montoya API feature you're unfamiliar with
- When encountering compilation errors related to Montoya classes or methods
- Before refactoring code that uses Montoya API components
- When unsure about proper usage patterns or best practices
- To verify method signatures, parameter types, or return values

### API Usage Instructions

**Base URL Structure:**
```
https://context7.com/api/v1/portswigger/burp-extensions-montoya-api?type=json&tokens=100000&topic=<TOPIC>
```

**Topic Formulation Best Practices:**
1. Use specific, technical keywords (e.g., "HttpRequest builder", "proxy listener registration")
2. Include class names when known (e.g., "MontoyaApi usage")
3. Combine action verbs with objects (e.g., "send http requests", "modify responses")
4. URL-encode spaces as `%20`

**Query Examples:**

| Scenario | Effective Topic Query |
|----------|----------------------|
| Creating HTTP requests | `http%20request%20builder` |
| Working with proxy listeners | `proxy%20listener%20events` |
| Scanning capabilities | `scanner%20insertion%20points` |
| Managing UI components | `ui%20context%20menu%20registration` |
| Handling responses | `http%20response%20modification` |

### Implementation Workflow
1. **Identify Knowledge Gap**: Determine what specific Montoya API functionality you need
2. **Formulate Query**: Create targeted topic keywords (2-4 words optimal)
3. **Fetch Documentation**: Make GET request to Context7 API
4. **Parse Response**: Extract relevant code examples and method signatures
5. **Implement**: Write code based on retrieved documentation
6. **Verify**: Ensure implementation matches documentation patterns

### Response Handling
- Parse the JSON response and extract relevant documentation snippets
- Prioritize code examples and method signatures from the response
- Cross-reference multiple related topics if initial results are insufficient
- Token limit is 100000 - optimize queries to stay within this limit

### Error Recovery
If documentation is unclear or insufficient:
- Reformulate your query with different keywords
- Try broader terms first, then narrow down
- Query related components separately (e.g., if "proxy handler" fails, try "proxy" then "event handler")

### Best Practices
- Query early and often - don't guess API usage
- Keep queries specific to avoid information overload
- Cache important documentation snippets in code comments
- When building complex features, query incrementally for each component
- Verify deprecated methods by checking documentation freshness

