![Plugin POC](assets/plugin-poc.gif)

# Header & Cookie Optimizer Burp Suite Extension

## Overview

The "Header & Cookie Optimizer" is a Burp Suite extension designed to help penetration testers identify and remove unnecessary HTTP headers and cookies from requests. By sending modified requests and comparing responses to a baseline, it determines which headers and cookies are essential for a valid server response, potentially reducing the attack surface or identifying verbose client behavior.

This Kotlin-based Montoya extension adds a custom tab to Burp Suite for configuration and logging, and a context menu item in the Repeater tool to initiate the optimization process on a selected request.

## Note

This plugin was created live during the talk on "vibecoding" at PHDays 2025.

*   **Talk Recording:** [Watch on YouTube](https://youtu.be/uUhGogya_hM)
*   **Presentation Slides:** Available on the [@hackthishit Telegram channel](https://t.me/hackthishit)

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

## How to Use

1.  Build the extension JAR (see Installation section below for details).
2.  Load the compiled JAR as a Java extension in Burp Suite.
3.  Navigate to the **Repeater** tool in Burp Suite.
4.  Select a request you want to optimize.
5.  Right-click in the request editor pane.
6.  Choose "**Header & Cookie Optimizer**" from the context menu.
7.  The optimization process will start, and logs will appear in the "**Header Optimizer**" tab.
8.  Once complete, the request in the Repeater tab will be updated with the optimized headers and cookies.

## Installation

To install this Kotlin/Java extension in Burp Suite:

1.  **Build the extension JAR**:
    *   Ensure you have a compatible JDK (Java 21 or newer) available in your environment.
    *   From the project root, run `./gradlew build` (or `gradlew.bat build` on Windows). This automatically produces the shaded artifact with all runtime dependencies, including the Kotlin standard library.
    *   The distributable JAR will be generated at `build/libs/HeaderCookieOptimizer-1.0.0.jar`.
2.  **Install the compiled extension**:
    *   In Burp Suite, open **Extensions > Installed** and click **Add**.
    *   Choose **Java** as the extension type.
    *   Select the generated JAR file and complete the wizard.
    *   Monitor the **Output** and **Errors** tabs for any load-time information.

After installation, the "Header Optimizer" suite tab will appear, exposing the configuration panel and log output.

For more general information on installing extensions, refer to the [PortSwigger documentation on manually installing extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/installing/manual-install).

## Troubleshooting

*   Ensure Burp Suite can locate a compatible JVM (Java 21+) to run Montoya extensions.
*   Check the extension's **Output** and **Errors** tabs (within Burp's **Extensions** tool, select the extension, then the respective sub-tabs) for any error messages.
*   The extension logs its actions to its dedicated "Header Optimizer" tab UI.
*   If requests are failing, check the Burp Suite **Alerts** tab for general network or HTTP issues.
*   The extension reuses the request's existing `HttpService`. Make sure the request being optimized has a valid service mapping (e.g., imported from Proxy or Repeater) so outbound requests can be issued successfully.
*   If Burp reports missing Kotlin classes (for example `kotlin.jvm.internal.Intrinsics`), ensure you loaded the `HeaderCookieOptimizer-1.0.0.jar` produced by the Gradle build. That artifact already packages the Kotlin runtime; non-shaded jars will not work.
