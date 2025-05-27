from burp import IBurpExtender, ITab, IContextMenuFactory
from java.awt import BorderLayout, GridLayout, FlowLayout, Dimension
from java.awt.event import ActionListener
from javax.swing import (
    JPanel,
    JLabel,
    JTextField,
    JButton,
    JCheckBox,
    JScrollPane,
    JTextArea,
    JMenuItem,
    BorderFactory,
    JTable,
    JComboBox,
)
from javax.swing.table import DefaultTableModel
from java.util import ArrayList
from threading import Thread
import re
import sys
import traceback
import time

# Add error handling for standard output
try:
    from exceptions import Exception
except ImportError:
    pass


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        """Register extension with callbacks"""
        # Save references to callbacks and helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set extension name
        callbacks.setExtensionName("Header & Cookie Optimizer")

        # Initialize UI components
        self._jPanel = JPanel(BorderLayout())

        # Create configuration panel
        configPanel = JPanel(GridLayout(0, 2))
        configPanel.setBorder(BorderFactory.createTitledBorder("Configuration"))

        # Headers to skip
        configPanel.add(JLabel("Headers to skip (comma-separated):"))
        self._headersToSkipField = JTextField(
            "Host,Cookie,Content-Length,Content-Type", 30
        )
        configPanel.add(self._headersToSkipField)

        # Max response difference
        configPanel.add(JLabel("Max response difference (%):"))
        self._maxDiffField = JTextField("5", 5)
        configPanel.add(self._maxDiffField)

        # Delay between requests
        configPanel.add(JLabel("Delay between requests (ms):"))
        self._delayField = JTextField("500", 5)
        configPanel.add(self._delayField)

        # Test baseline twice checkbox
        configPanel.add(JLabel("Test baseline twice for consistency:"))
        self._testBaselineTwiceCheckbox = JCheckBox("", True)
        configPanel.add(self._testBaselineTwiceCheckbox)

        # Add configuration panel to main panel
        self._jPanel.add(configPanel, BorderLayout.NORTH)

        # Create log panel
        logPanel = JPanel(BorderLayout())
        logPanel.setBorder(BorderFactory.createTitledBorder("Logs"))

        self._logArea = JTextArea()
        self._logArea.setEditable(False)
        logScrollPane = JScrollPane(self._logArea)
        logScrollPane.setPreferredSize(Dimension(800, 300))
        logPanel.add(logScrollPane, BorderLayout.CENTER)

        # Clear logs button
        clearButton = JButton("Clear Logs")
        clearButton.setActionCommand("clearLogs")
        clearButton.addActionListener(self)
        logPanel.add(clearButton, BorderLayout.SOUTH)

        # Add log panel to main panel
        self._jPanel.add(logPanel, BorderLayout.CENTER)

        # Register as context menu factory
        callbacks.registerContextMenuFactory(self)

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # Log extension loaded message
        self.log("[+] Header & Cookie Optimizer extension loaded successfully!")
        self.log(
            "[+] Right-click on a request in Repeater and select 'Optimize Headers & Cookies'"
        )

        # Print to standard output as well (for debugging)
        print("Header & Cookie Optimizer extension loaded successfully!")

    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Header Optimizer"

    def getUiComponent(self):
        """Return the component to be displayed in the tab"""
        return self._jPanel

    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = ArrayList()
        menu_item = JMenuItem("Optimize Headers & Cookies")

        # Only show menu on editor
        if (
            invocation.getInvocationContext()
            == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST
        ):
            menu_item.addActionListener(OptimizeActionListener(self, invocation))
            menu_items.add(menu_item)

        return menu_items

    def actionPerformed(self, event):
        """Handle button click events"""
        if event.getActionCommand() == "clearLogs":
            self._logArea.setText("")

    def log(self, message):
        """Append a message to the extension's log"""
        self._logArea.append(message + "\n")
        # Auto-scroll to the bottom
        self._logArea.setCaretPosition(self._logArea.getDocument().getLength())

    def optimize_headers_and_cookies(self, request_text, requestResponse):
        """Optimize headers and cookies in the request"""
        try:
            # Parse configuration
            headers_to_skip = [
                h.strip() for h in self._headersToSkipField.getText().split(",")
            ]
            max_diff_percentage = float(self._maxDiffField.getText())
            delay_ms = int(self._delayField.getText())
            test_baseline_twice = self._testBaselineTwiceCheckbox.isSelected()

            # Convert string request to byte array for Burp API
            self.log("[*] Converting request to bytes")
            try:
                request_bytes = self._helpers.stringToBytes(request_text)
            except Exception as e:
                self.log("[!] Error converting string to bytes: {}".format(str(e)))
                # Fallback method
                request_bytes = requestResponse.getRequest()
                self.log("[*] Using original request bytes from requestResponse")

            request_info = self._helpers.analyzeRequest(request_bytes)

            # Get the request headers
            headers = request_info.getHeaders()

            # Get the request body
            body_offset = request_info.getBodyOffset()
            body = request_bytes[body_offset:]

            # Log start of optimization
            self.log("\n[+] Starting request optimization")
            self.log(
                "[*] Original headers count: %d" % (len(headers) - 1)
            )  # -1 to exclude the request line

            # Establish baseline response by sending the original request
            self.log("[*] Establishing baseline response...")
            baseline_response = self.send_request(request_bytes)
            if baseline_response is None:
                self.log("[!] Error: Failed to get baseline response")
                return False

            baseline_length = len(baseline_response)
            self.log("[*] Baseline response length: {} bytes".format(baseline_length))

            # If selected, test baseline twice for consistency
            if test_baseline_twice:
                self.log("[*] Testing baseline consistency...")
                time.sleep(delay_ms / 1000.0)  # Convert ms to seconds
                second_baseline = self.send_request(request_bytes)
                if second_baseline is None:
                    self.log("[!] Error: Failed to get second baseline response")
                    return False

                second_length = len(second_baseline)

                # Check if responses are consistent
                if self.responses_differ(
                    baseline_response, second_baseline, max_diff_percentage
                ):
                    self.log("[!] Warning: Inconsistent baseline responses detected")
                    self.log("    First response length: %d bytes" % baseline_length)
                    self.log("    Second response length: %d bytes" % second_length)
                    self.log(
                        "    Difference: %.2f%%"
                        % self.calculate_diff_percentage(baseline_length, second_length)
                    )
                    self.log(
                        "[!] Continuing with optimization, but results may be unreliable"
                    )
                else:
                    self.log("[*] Baseline responses are consistent")

            # Process headers (except the first one which is the request line)
            request_line = headers.get(0)
            optimized_headers = ArrayList()
            optimized_headers.add(request_line)

            self.log("[*] Processing headers...")

            # Add headers that should not be processed
            for i in range(1, headers.size()):
                header = headers.get(i)
                header_name = header.split(":", 1)[0].strip()

                if header_name in headers_to_skip:
                    self.log("    [SKIP] %s" % header_name)
                    optimized_headers.add(header)

            # Process other headers
            for i in range(1, headers.size()):
                header = headers.get(i)
                header_name = header.split(":", 1)[0].strip()

                if header_name in headers_to_skip:
                    continue

                # Create a test request without this header
                test_headers = ArrayList()
                test_headers.add(request_line)

                for j in range(1, headers.size()):
                    if j != i:  # Skip the header we're testing
                        test_headers.add(headers.get(j))

                # Build and send the test request
                test_request = self._helpers.buildHttpMessage(test_headers, body)

                # Wait before sending the next request
                time.sleep(delay_ms / 1000.0)

                # Send the test request
                test_response = self.send_request(test_request)
                if test_response is None:
                    self.log(
                        "[!] Error: Failed to get response for header test: {}".format(
                            header_name
                        )
                    )
                    # Keep the header if we can't test it
                    self.log(
                        "    [KEEP] %s - Could not test, keeping for safety"
                        % header_name
                    )
                    optimized_headers.add(header)
                    continue

                # Check if the response is significantly different
                if self.responses_differ(
                    baseline_response, test_response, max_diff_percentage
                ):
                    self.log(
                        "    [KEEP] %s - Required for correct response" % header_name
                    )
                    optimized_headers.add(header)
                else:
                    self.log("    [REMOVE] %s - Not needed" % header_name)

            # Process cookies only after header processing is complete
            cookie_header = None
            for i in range(optimized_headers.size()):
                header = optimized_headers.get(i)
                if header.startswith("Cookie:"):
                    cookie_header = header
                    break

            # If there's a Cookie header, process the cookies
            if cookie_header is not None:
                self.log("[*] Processing cookies...")
                cookie_index = optimized_headers.indexOf(cookie_header)
                cookies_str = cookie_header[7:].strip()  # Remove "Cookie: " prefix
                cookies = cookies_str.split(";")

                # Process each cookie
                required_cookies = []

                for cookie in cookies:
                    cookie = cookie.strip()
                    if not cookie:
                        continue

                    cookie_name = cookie.split("=", 1)[0].strip()

                    # Create a test request with this cookie removed
                    test_cookies = [
                        c.strip()
                        for c in cookies
                        if c.strip() and not c.strip().startswith(cookie_name + "=")
                    ]

                    if not test_cookies:
                        # If this is the only cookie, we need to check without the Cookie header
                        test_headers = ArrayList()
                        for h in optimized_headers:
                            if not h.startswith("Cookie:"):
                                test_headers.add(h)
                    else:
                        # Build new cookie header with this cookie removed
                        test_cookie_header = "Cookie: " + "; ".join(test_cookies)
                        test_headers = ArrayList()
                        for i, h in enumerate(optimized_headers):
                            if h.startswith("Cookie:"):
                                test_headers.add(test_cookie_header)
                            else:
                                test_headers.add(h)

                    # Build and send the test request
                    test_request = self._helpers.buildHttpMessage(test_headers, body)

                    # Wait before sending the next request
                    time.sleep(delay_ms / 1000.0)

                    # Send the test request
                    test_response = self.send_request(test_request)
                    if test_response is None:
                        self.log(
                            "[!] Error: Failed to get response for cookie test: {}".format(
                                cookie_name
                            )
                        )
                        # Keep the cookie if we can't test it
                        self.log(
                            "    [KEEP] Cookie: %s - Could not test, keeping for safety"
                            % cookie_name
                        )
                        required_cookies.append(cookie)
                        continue

                    # Check if the response is significantly different
                    if self.responses_differ(
                        baseline_response, test_response, max_diff_percentage
                    ):
                        self.log(
                            "    [KEEP] Cookie: %s - Required for correct response"
                            % cookie_name
                        )
                        required_cookies.append(cookie)
                    else:
                        self.log("    [REMOVE] Cookie: %s - Not needed" % cookie_name)

                # Update the optimized headers with the new cookie header
                if required_cookies:
                    new_cookie_header = "Cookie: " + "; ".join(required_cookies)
                    optimized_headers.set(cookie_index, new_cookie_header)
                else:
                    # No cookies required, remove the Cookie header
                    optimized_headers.remove(cookie_index)

            # Build the final optimized request
            optimized_request = self._helpers.buildHttpMessage(optimized_headers, body)

            # Set the optimized request back to the editor
            self.log("[*] Updating request in editor...")
            try:
                # Try to update the request using the requestResponse object directly
                requestResponse.setRequest(optimized_request)
                self.log("[*] Request updated successfully using requestResponse")
            except Exception as e:
                self.log("[!] Error updating request: {}".format(str(e)))
                self.log("[*] Trying alternative method...")

                try:
                    # Get the currently active tool
                    tool = self._callbacks.getToolName(self._callbacks.getToolFlag())
                    self.log("[*] Current tool: {}".format(tool))

                    # Try to update using the context
                    context = self._callbacks.createMessageEditor(self, True)
                    context.setMessage(optimized_request, True)
                    self.log("[*] Request set in message editor")
                except Exception as e:
                    self.log("[!] Alternative method failed: {}".format(str(e)))
                    return False

            # Log completion
            original_header_count = headers.size() - 1  # Exclude request line
            optimized_header_count = (
                optimized_headers.size() - 1
            )  # Exclude request line

            self.log("[+] Optimization complete!")
            self.log("    Original headers: %d" % original_header_count)
            self.log("    Optimized headers: %d" % optimized_header_count)
            self.log(
                "    Headers removed: %d"
                % (original_header_count - optimized_header_count)
            )

            return True
        except Exception as e:
            self.log("[!] Error during optimization: %s" % str(e))
            traceback.print_exc(file=sys.stdout)
            return False

    def send_request(self, request):
        """Send a request and get the response"""
        try:
            # Get the HTTP service from the current request
            # Create a service object directly instead of trying to extract it from the request
            # This assumes we're working with the currently selected message in Repeater

            # Parse the request to get host, port, and protocol
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()

            # Extract host and port from the Host header
            host = None
            port = 443  # Default to HTTPS port
            is_https = True

            for header in headers:
                if header.lower().startswith("host:"):
                    host_value = header[5:].strip()
                    if ":" in host_value:
                        host, port_str = host_value.split(":", 1)
                        port = int(port_str)
                    else:
                        host = host_value

                # Check if we have a non-HTTPS request
                if header.startswith("GET ") or header.startswith("POST "):
                    if header.startswith("GET http://") or header.startswith(
                        "POST http://"
                    ):
                        is_https = False
                        port = 80 if port == 443 else port

            if host is None:
                self.log("[!] Error: Could not determine host from request")
                return None

            # Create an HTTP service object
            http_service = self._helpers.buildHttpService(host, port, is_https)
            self.log(
                "[*] Sending request to: {}://{}:{}".format(
                    "https" if is_https else "http", host, port
                )
            )

            # Make the request and get the response
            response = self._callbacks.makeHttpRequest(http_service, request)

            if response is None:
                self.log("[!] Warning: Received null response")
                return None

            response_data = response.getResponse()
            if response_data is None:
                self.log("[!] Warning: Response data is null")
                return None

            self.log(
                "[*] Response received, length: {} bytes".format(len(response_data))
            )
            return response_data
        except Exception as e:
            self.log("[!] Error sending request: %s" % str(e))
            traceback.print_exc(file=sys.stdout)
            return None

    def responses_differ(self, response1, response2, max_diff_percentage):
        """Check if two responses differ significantly"""
        if response1 is None or response2 is None:
            return True

        # Compare response lengths
        len1 = len(response1)
        len2 = len(response2)

        # Calculate difference percentage
        diff_percentage = self.calculate_diff_percentage(len1, len2)

        # Return True if the difference exceeds the maximum allowed
        return diff_percentage > max_diff_percentage

    def calculate_diff_percentage(self, len1, len2):
        """Calculate the percentage difference between two lengths"""
        if len1 == 0 and len2 == 0:
            return 0

        # Use max length as reference to calculate percentage
        max_len = max(len1, len2)
        min_len = min(len1, len2)
        diff = max_len - min_len

        return (diff * 100.0) / max_len


class OptimizeActionListener(ActionListener):
    """Listener for the optimize menu item"""

    def __init__(self, extender, invocation):
        self._extender = extender
        self._invocation = invocation

    def actionPerformed(self, e):
        try:
            # Log action start for debugging
            self._extender.log("[*] Optimize action triggered")

            # Get selected messages
            http_traffic = self._invocation.getSelectedMessages()

            if http_traffic is None or len(http_traffic) != 1:
                self._extender.log("[!] Error: Please select a single request")
                return

            # Get the message info
            message_info = http_traffic[0]

            # Get the IMessageEditorTab
            context = self._invocation.getInvocationContext()
            self._extender.log("[*] Invocation context: {}".format(context))

            # Get the IHttpRequestResponse object
            requestResponse = self._invocation.getSelectedMessages()[0]
            if requestResponse is None:
                self._extender.log("[!] Error: Could not get selected message")
                return

            # Get request details
            request = requestResponse.getRequest()
            if request is None:
                self._extender.log("[!] Error: Request is null")
                return

            # Convert byte array to string for processing
            request_text = self._extender._helpers.bytesToString(request)

            # Debug message
            self._extender.log("[*] Request length: {} bytes".format(len(request)))

            # Run optimization in a separate thread to avoid freezing the UI
            optimize_thread = Thread(
                target=self._run_optimization_with_error_handling,
                args=(request_text, requestResponse),
            )
            optimize_thread.daemon = True
            optimize_thread.start()

            self._extender.log("[*] Optimization thread started")
        except Exception as e:
            self._extender.log("[!] Error in actionPerformed: {}".format(str(e)))
            traceback.print_exc(file=sys.stdout)

    def _run_optimization_with_error_handling(self, request_text, requestResponse):
        """Run optimization with proper error handling"""
        try:
            self._extender.log("[*] Starting optimization process")
            result = self._extender.optimize_headers_and_cookies(
                request_text, requestResponse
            )
            if result:
                self._extender.log("[+] Optimization completed successfully")
            else:
                self._extender.log("[!] Optimization failed")
        except Exception as e:
            self._extender.log("[!] Error during optimization: {}".format(str(e)))
            traceback.print_exc(file=sys.stdout)
