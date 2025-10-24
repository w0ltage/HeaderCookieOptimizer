package com.headercookie.optimizer

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.GridLayout
import java.util.Locale
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities
import kotlin.concurrent.thread

class HeaderCookieOptimizerExtension : BurpExtension, ContextMenuItemsProvider {
    companion object {
        private const val EXTENSION_NAME = "Header & Cookie Optimizer"
        private const val TAB_CAPTION = "Header Optimizer"
    }

    private lateinit var api: MontoyaApi

    private val headersToSkipField = JTextField("Host,Cookie,Content-Length,Content-Type", 30)
    private val maxDiffField = JTextField("5", 5)
    private val delayField = JTextField("500", 5)
    private val testBaselineTwiceCheckbox = JCheckBox("", true)
    private val logArea = JTextArea().apply { isEditable = false }
    private val mainPanel: JPanel = JPanel(BorderLayout())

    override fun initialize(api: MontoyaApi?) {
        this.api = requireNotNull(api) { "MontoyaApi cannot be null" }

        setupUserInterface()

        this.api.extension().setName(EXTENSION_NAME)
        this.api.userInterface().registerSuiteTab(TAB_CAPTION, mainPanel)
        this.api.userInterface().registerContextMenuItemsProvider(this)

        log("[+] Header & Cookie Optimizer extension loaded successfully!")
        log("[+] Right-click on a request in Repeater and select 'Optimize Headers & Cookies'")
        this.api.logging().logToOutput("$EXTENSION_NAME loaded")
    }

    private fun setupUserInterface() {
        val configPanel = JPanel(GridLayout(0, 2)).apply {
            border = BorderFactory.createTitledBorder("Configuration")
            add(JLabel("Headers to skip (comma-separated):"))
            add(headersToSkipField)
            add(JLabel("Max response difference (%):"))
            add(maxDiffField)
            add(JLabel("Delay between requests (ms):"))
            add(delayField)
            add(JLabel("Test baseline twice for consistency:"))
            add(testBaselineTwiceCheckbox)
        }

        val logPanel = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Logs")
            val scrollPane = JScrollPane(logArea).apply {
                preferredSize = Dimension(800, 300)
            }
            add(scrollPane, BorderLayout.CENTER)
            val clearButton = JButton("Clear Logs").apply {
                addActionListener { clearLogs() }
            }
            add(clearButton, BorderLayout.SOUTH)
        }

        mainPanel.apply {
            removeAll()
            add(configPanel, BorderLayout.NORTH)
            add(logPanel, BorderLayout.CENTER)
        }
    }

    private fun clearLogs() {
        SwingUtilities.invokeLater { logArea.text = "" }
    }

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val messageEditor = event.messageEditorRequestResponse().orElse(null)
        val selectedRequestResponses = event.selectedRequestResponses()
        val requestResponse = messageEditor?.requestResponse()
            ?: selectedRequestResponses.firstOrNull()?.also {
                if (selectedRequestResponses.size > 1) {
                    log("[!] Multiple messages selected, optimizing the first one")
                }
            }
            ?: return emptyList()

        val menuItem = JMenuItem("Optimize Headers & Cookies").apply {
            addActionListener {
                startOptimization(requestResponse, messageEditor)
            }
        }
        return listOf(menuItem)
    }

    private fun startOptimization(
        requestResponse: HttpRequestResponse,
        messageEditor: MessageEditorHttpRequestResponse?
    ) {
        thread(start = true, isDaemon = true) {
            try {
                log("[*] Optimize action triggered")
                val source = if (messageEditor != null) {
                    "message editor"
                } else {
                    "context selection"
                }
                log("[*] Processing request from $source")
                if (!optimizeRequest(requestResponse, messageEditor)) {
                    log("[!] Optimization failed")
                } else {
                    log("[+] Optimization completed successfully")
                }
            } catch (exception: Exception) {
                log("[!] Error during optimization: ${exception.message}")
                api.logging().logToError(exception)
            }
        }
    }

    private fun optimizeRequest(
        requestResponse: HttpRequestResponse,
        messageEditor: MessageEditorHttpRequestResponse?
    ): Boolean {
        val request = requestResponse.request()

        val headersToSkip = headersToSkipField.text.split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { it.lowercase(Locale.ROOT) }
            .toSet()

        val maxDiffPercentage = maxDiffField.text.toDoubleOrNull()
            ?: run {
                log("[!] Invalid max response difference value: '${maxDiffField.text}'")
                return false
            }

        val delayMillis = delayField.text.toLongOrNull()
            ?: run {
                log("[!] Invalid delay value: '${delayField.text}'")
                return false
            }

        val testBaselineTwice = testBaselineTwiceCheckbox.isSelected

        log("\n[+] Starting request optimization")
        log("[*] Original headers count: ${request.headers().size}")

        val baselineResponse = sendRequest(request) ?: return false
        val baselineLength = baselineResponse.toByteArray().length()
        log("[*] Baseline response length: $baselineLength bytes")

        if (testBaselineTwice) {
            log("[*] Testing baseline consistency...")
            sleep(delayMillis)
            val secondBaseline = sendRequest(request) ?: return false
            val secondLength = secondBaseline.toByteArray().length()
            if (responsesDiffer(baselineResponse, secondBaseline, maxDiffPercentage)) {
                val diff = calculateDiffPercentage(baselineLength, secondLength)
                log("[!] Warning: Inconsistent baseline responses detected")
                log("    First response length: $baselineLength bytes")
                log("    Second response length: $secondLength bytes")
                log("    Difference: %.2f%%".format(diff))
                log("[!] Continuing with optimization, but results may be unreliable")
            } else {
                log("[*] Baseline responses are consistent")
            }
        }

        log("[*] Processing headers...")
        val originalHeaders = request.headers()
        val optimizedHeaders = mutableListOf<HttpHeader>()

        for ((index, header) in originalHeaders.withIndex()) {
            val headerName = header.name()
            if (headerName.lowercase(Locale.ROOT) in headersToSkip) {
                log("    [SKIP] $headerName")
                optimizedHeaders.add(header)
                continue
            }

            val candidateHeaders = originalHeaders.filterIndexed { candidateIndex, _ -> candidateIndex != index }
            sleep(delayMillis)
            val testRequest = request.withUpdatedHeaders(candidateHeaders)
            val testResponse = sendRequest(testRequest)
            if (testResponse == null) {
                log("    [KEEP] $headerName - Could not test, keeping for safety")
                optimizedHeaders.add(header)
                continue
            }

            if (responsesDiffer(baselineResponse, testResponse, maxDiffPercentage)) {
                log("    [KEEP] $headerName - Required for correct response")
                optimizedHeaders.add(header)
            } else {
                log("    [REMOVE] $headerName - Not needed")
            }
        }

        val cookieIndex = optimizedHeaders.indexOfFirst { it.name().equals("Cookie", ignoreCase = true) }
        if (cookieIndex >= 0) {
            log("[*] Processing cookies...")
            val cookieHeader = optimizedHeaders[cookieIndex]
            val cookies = cookieHeader.value().split(";")
                .map { it.trim() }
                .filter { it.isNotEmpty() }

            val requiredCookies = mutableListOf<String>()

            for (cookie in cookies) {
                val cookieName = cookie.substringBefore("=").trim()
                val remainingCookies = cookies.filterNot {
                    it.startsWith("$cookieName=", ignoreCase = false)
                }

                val testHeaders = optimizedHeaders.toMutableList()
                if (remainingCookies.isEmpty()) {
                    testHeaders.removeAt(cookieIndex)
                } else {
                    val newCookieHeader = HttpHeader.httpHeader("Cookie", remainingCookies.joinToString("; "))
                    testHeaders[cookieIndex] = newCookieHeader
                }

                sleep(delayMillis)
                val testRequest = request.withUpdatedHeaders(testHeaders)
                val testResponse = sendRequest(testRequest)
                if (testResponse == null) {
                    log("    [KEEP] Cookie: $cookieName - Could not test, keeping for safety")
                    requiredCookies.add(cookie)
                    continue
                }

                if (responsesDiffer(baselineResponse, testResponse, maxDiffPercentage)) {
                    log("    [KEEP] Cookie: $cookieName - Required for correct response")
                    requiredCookies.add(cookie)
                } else {
                    log("    [REMOVE] Cookie: $cookieName - Not needed")
                }
            }

            if (requiredCookies.isNotEmpty()) {
                optimizedHeaders[cookieIndex] = HttpHeader.httpHeader("Cookie", requiredCookies.joinToString("; "))
            } else {
                optimizedHeaders.removeAt(cookieIndex)
            }
        }

        val optimizedRequest = request.withUpdatedHeaders(optimizedHeaders)
        applyOptimizedRequest(optimizedRequest, requestResponse, messageEditor)

        val originalHeaderCount = originalHeaders.size
        val optimizedHeaderCount = optimizedHeaders.size
        log("[+] Optimization complete!")
        log("    Original headers: $originalHeaderCount")
        log("    Optimized headers: $optimizedHeaderCount")
        log("    Headers removed: ${originalHeaderCount - optimizedHeaderCount}")

        return true
    }

    private fun applyOptimizedRequest(
        optimizedRequest: HttpRequest,
        originalRequestResponse: HttpRequestResponse,
        messageEditor: MessageEditorHttpRequestResponse?
    ) {
        SwingUtilities.invokeLater {
            if (messageEditor != null) {
                messageEditor.setRequest(optimizedRequest)
                log("[*] Updated request in the active editor")
            } else {
                val repeaterTitle = "${EXTENSION_NAME} (${originalRequestResponse.request().url()})"
                api.repeater().sendToRepeater(optimizedRequest, repeaterTitle)
                log("[*] Optimized request sent to Repeater")
            }
        }
    }

    private fun responsesDiffer(
        response1: HttpResponse?,
        response2: HttpResponse?,
        maxDiffPercentage: Double
    ): Boolean {
        if (response1 == null || response2 == null) {
            return true
        }
        val len1 = response1.toByteArray().length()
        val len2 = response2.toByteArray().length()
        val diffPercentage = calculateDiffPercentage(len1, len2)
        return diffPercentage > maxDiffPercentage
    }

    private fun calculateDiffPercentage(len1: Int, len2: Int): Double {
        if (len1 == 0 && len2 == 0) {
            return 0.0
        }
        val maxLen = maxOf(len1, len2).toDouble()
        val minLen = minOf(len1, len2).toDouble()
        return if (maxLen == 0.0) {
            0.0
        } else {
            ((maxLen - minLen) * 100.0) / maxLen
        }
    }

    private fun sendRequest(request: HttpRequest): HttpResponse? {
        return try {
            val response = api.http().sendRequest(request)
            if (!response.hasResponse()) {
                log("[!] Warning: Received null response")
                null
            } else {
                val httpResponse = response.response()
                log("[*] Response received, length: ${httpResponse.toByteArray().length()} bytes")
                httpResponse
            }
        } catch (exception: Exception) {
            log("[!] Error sending request: ${exception.message}")
            api.logging().logToError(exception)
            null
        }
    }

    private fun sleep(delayMillis: Long) {
        if (delayMillis <= 0) {
            return
        }
        try {
            Thread.sleep(delayMillis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun log(message: String) {
        SwingUtilities.invokeLater {
            logArea.append("$message\n")
            logArea.caretPosition = logArea.document.length
        }
    }
}
