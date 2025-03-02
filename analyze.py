# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener
from javax.swing import JMenuItem, JScrollPane, JTable, JPanel, JTextArea, JTextField, JLabel, JButton, JSplitPane, ListSelectionModel, JPopupMenu, SwingUtilities, BoxLayout, JEditorPane
from javax.swing.table import DefaultTableModel
from java.util import ArrayList
from java.net import URL
from java.awt import Font
from java.awt.event import MouseAdapter
import threading, json, datetime

class BurpExtender(IBurpExtender, IContextMenuFactory, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("ChatGPT Security Analyzer")

        # Register the context menu
        self._callbacks.registerContextMenuFactory(self)

        # Create and register tabs
        self.analyzer_tab = ChatGPTAnalyzerTab(callbacks)
        self.settings_tab = ChatGPTSettingsTab(callbacks)

        self._callbacks.addSuiteTab(self.analyzer_tab)
        self._callbacks.addSuiteTab(self.settings_tab)

        # FIX: Register State Listener CORRECTLY
        self._callbacks.registerExtensionStateListener(self)

    def extensionUnloaded(self):
        """ Called when the extension is unloaded. Saves logs before closing. """
        print("ChatGPT Security Analyzer is being unloaded. Saving logs...")
        self.analyzer_tab.save_logs()  # Ensure logs are saved

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Ask ChatGPT", actionPerformed=lambda x: self.analyzer_tab.analyze_request(invocation))
        menu_list.add(menu_item)
        return menu_list

class ChatGPTAnalyzerTab(ITab):

    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Log Table (Top Panel)
        self.table_model = DefaultTableModel(["Date Checked", "URL", "Request", "Response", "Comment"], 0)
        self.log_table = JTable(self.table_model)
        self.log_table.setFont(Font("Arial", Font.PLAIN, 12))
        self.log_table.setRowHeight(30)
        self.log_table.getColumnModel().getColumn(4).setPreferredWidth(400)
        log_scroll_pane = JScrollPane(self.log_table)

        # Load logs
        self.load_logs()

        # Create Panel for Request
        request_panel = JPanel()
        request_panel.setLayout(BoxLayout(request_panel, BoxLayout.Y_AXIS))
        request_label = JLabel("REQUEST")

        # Enable Word Wrap for Request
        self.request_text_area = JTextArea()
        self.request_text_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.request_text_area.setEditable(False)
        self.request_text_area.setLineWrap(True)  # Wrap text
        self.request_text_area.setWrapStyleWord(True)  # Wrap by words

        request_scroll_pane = JScrollPane(self.request_text_area)

        request_panel.add(request_label)
        request_panel.add(request_scroll_pane)

        # Create Panel for Response
        response_panel = JPanel()
        response_panel.setLayout(BoxLayout(response_panel, BoxLayout.Y_AXIS))
        response_label = JLabel("RESPONSE")

        # Enable Word Wrap for Response
        self.response_text_area = JTextArea()
        self.response_text_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.response_text_area.setEditable(False)
        self.response_text_area.setLineWrap(True)  # Wrap text
        self.response_text_area.setWrapStyleWord(True)  # Wrap by words

        response_scroll_pane = JScrollPane(self.response_text_area)

        response_panel.add(response_label)
        response_panel.add(response_scroll_pane)

        # Initialize request_response_panel before using it
        request_response_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, request_panel, response_panel)
        request_response_panel.setResizeWeight(0.5)  # Makes both panels take equal space
        request_response_panel.setDividerLocation(0.5)  # Centers the divider

        # Create Panel for ChatGPT Comments (HTML Rendering)
        comment_panel = JPanel()
        comment_panel.setLayout(BoxLayout(comment_panel, BoxLayout.Y_AXIS))
        comment_label = JLabel("CHATGPT RESULT")

        # Use JEditorPane for HTML Rendering
        self.comment_pane = JEditorPane("text/html", "")
        self.comment_pane.setEditable(False)
        self.comment_pane.setContentType("text/html")
        self.comment_pane.setText("<html><body><i>No response from ChatGPT.</i></body></html>")

        comment_scroll_pane = JScrollPane(self.comment_pane)

        comment_panel.add(comment_label)
        comment_panel.add(comment_scroll_pane)

        # Bottom: Request/Response Panel + ChatGPT Result
        bottom_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT, request_response_panel, comment_panel)
        bottom_panel.setDividerLocation(250)

        # Overall Layout: Logs (Top) + Bottom Panel (Request/Response + ChatGPT)
        self.analysis_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT, log_scroll_pane, bottom_panel)
        self.analysis_panel.setDividerLocation(250)

        # Selection Listener for Updating Fields
        self.log_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.log_table.getSelectionModel().addListSelectionListener(self.display_selected_comment)

        # Add Right-Click Delete Option
        self.log_table.addMouseListener(self.TableMouseListener(self))

    def save_logs(self):
        """ Saves logs to Burp storage. """
        logs = []
        for row in range(self.table_model.getRowCount()):
            logs.append({
                "date": self.table_model.getValueAt(row, 0),
                "url": self.table_model.getValueAt(row, 1),
                "request": self.table_model.getValueAt(row, 2),
                "response": self.table_model.getValueAt(row, 3),
                "comment": self.table_model.getValueAt(row, 4),
            })

        json_logs = json.dumps(logs)
        self._callbacks.saveExtensionSetting("chatgpt_logs", json_logs)

    def load_logs(self):
        """ Loads logs from Burp storage. """
        saved_logs = self._callbacks.loadExtensionSetting("chatgpt_logs")
        if saved_logs:
            logs = json.loads(saved_logs)
            for log in logs:
                self.table_model.addRow([log["date"], log["url"], log["request"], log["response"], log["comment"]])
    
    def extensionUnloaded(self):
        """ Called when the extension is unloaded. Saves logs before closing. """
        self.save_logs()

    def display_selected_comment(self, event):
        """Updates the request, response, and comment fields when a row is selected."""
        if not event.getValueIsAdjusting():
            selected_row = self.log_table.getSelectedRow()
            if selected_row != -1:
                request_text = self.table_model.getValueAt(selected_row, 2)
                response_text = self.table_model.getValueAt(selected_row, 3)
                comment_text = self.table_model.getValueAt(selected_row, 4)

                self.request_text_area.setText(request_text+"\n")
                self.response_text_area.setText(response_text+"\n")
                self.comment_pane.setText(comment_text)  # Show Raw HTML Content
                self.comment_pane.setCaretPosition(0)  # Reset Scroll to Top


                # Reset Scroll Position
                self.comment_pane.setCaretPosition(0)

    def analyze_request(self, invocation):
        """Processes the selected HTTP request and sends it to ChatGPT."""
        selected_items = invocation.getSelectedMessages()
        if not selected_items:
            return

        request_info = self._helpers.analyzeRequest(selected_items[0])
        url = request_info.getUrl().toString()
        http_request = self._helpers.bytesToString(selected_items[0].getRequest())
        http_response = self._helpers.bytesToString(selected_items[0].getResponse()) if selected_items[0].getResponse() else "No Response"

        threading.Thread(target=self.ask_chatgpt, args=(url, http_request, http_response)).start()

    def ask_chatgpt(self, url, http_request, http_response):
        """Sends request and response data to ChatGPT for analysis."""

        api_key = self._callbacks.loadExtensionSetting("openai_api_key")

        custom_prompt = self._callbacks.loadExtensionSetting("openai_prompt")
        if not custom_prompt:
            custom_prompt = "Analyze HTTP requests and responses for possible security vulnerabilities. Never write the request and response again. separate between potential security risks and the actual security risks."

        if not api_key:
            print("Missing API key.")
            return

        try:
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": custom_prompt+". and I want the response in HTML format."},
                    {"role": "user", "content": "Analyze this HTTP request:\n\nRequest:\n{}\n\nResponse:\n{}".format(http_request, http_response)}
                ],
                "temperature": 0.5
            }

            json_payload = json.dumps(payload)

            headers = [
                "POST /v1/chat/completions HTTP/1.1",
                "Host: api.openai.com",
                "Authorization: Bearer {}".format(api_key),
                "Content-Type: application/json",
                "Content-Length: {}".format(len(json_payload)),
                "Connection: close"
            ]

            request_data = "\r\n".join(headers) + "\r\n\r\n" + json_payload
            service = self._helpers.buildHttpService("api.openai.com", 443, True)
            response = self._callbacks.makeHttpRequest(service, self._helpers.stringToBytes(request_data))
            response_body = self._helpers.bytesToString(response.getResponse())

            print("📥 Raw OpenAI Response:\n", response_body)

            json_start = response_body.find("{")
            if json_start == -1:
                print("❌ OpenAI response is not JSON:", response_body)
                return

            json_response = json.loads(response_body[json_start:])
            chatgpt_reply = json_response.get("choices", [{}])[0].get("message", {}).get("content", "No response from ChatGPT").replace("```html", "")

            def update_ui():
                self.table_model.addRow([str(datetime.datetime.now()), url, http_request, http_response, chatgpt_reply])

            SwingUtilities.invokeLater(update_ui)

        except Exception as e:
            print("❌ Request failed:", str(e))


    def delete_selected_row(self):
        """ Deletes the selected row and updates storage. """
        selected_row = self.log_table.getSelectedRow()
        if selected_row != -1:
            self.table_model.removeRow(selected_row)
            self.save_logs()  # Update storage after deletion

    class TableMouseListener(MouseAdapter):
        """Handles right-click context menu for deleting rows."""

        def __init__(self, parent):
            self.parent = parent

        def mousePressed(self, event):
            self.show_popup(event)

        def mouseReleased(self, event):
            self.show_popup(event)

        def show_popup(self, event):
            if SwingUtilities.isRightMouseButton(event):
                row = self.parent.log_table.rowAtPoint(event.getPoint())
                if row != -1:
                    self.parent.log_table.setRowSelectionInterval(row, row)
                    menu = JPopupMenu()
                    delete_item = JMenuItem("Delete", actionPerformed=lambda x: self.parent.delete_selected_row())
                    menu.add(delete_item)
                    menu.show(self.parent.log_table, event.getX(), event.getY())

    def getTabCaption(self):
        return "ChatGPT Analyzer"

    def getUiComponent(self):
        return self.analysis_panel


class ChatGPTSettingsTab(ITab):

    def __init__(self, callbacks):
        self._callbacks = callbacks

        self.settings_panel = JPanel()
        self.settings_panel.setLayout(None)

        # API Key Input
        api_label = JLabel("OpenAI API Key:")
        api_label.setBounds(10, 10, 150, 25)
        self.settings_panel.add(api_label)

        self.api_key_field = JTextField(40)
        self.api_key_field.setBounds(160, 10, 400, 25)
        self.settings_panel.add(self.api_key_field)

        # Custom Prompt Input
        prompt_label = JLabel("Custom ChatGPT Prompt:")
        prompt_label.setBounds(10, 50, 200, 25)
        self.settings_panel.add(prompt_label)

        self.prompt_text_area = JTextArea(5, 40)
        self.prompt_text_area.setLineWrap(True)
        self.prompt_text_area.setWrapStyleWord(True)
        scroll_pane = JScrollPane(self.prompt_text_area)
        scroll_pane.setBounds(160, 50, 400, 100)
        self.settings_panel.add(scroll_pane)

        # Save Button
        save_button = JButton("Save Settings", actionPerformed=self.save_settings)
        save_button.setBounds(160, 160, 150, 30)
        self.settings_panel.add(save_button)

        self.load_settings()  # Load existing settings

    def save_settings(self, event):
        api_key = self.api_key_field.getText().strip()
        custom_prompt = self.prompt_text_area.getText().strip()

        self._callbacks.saveExtensionSetting("openai_api_key", api_key)
        self._callbacks.saveExtensionSetting("openai_prompt", custom_prompt)

        self._callbacks.issueAlert("OpenAI API Key and Prompt Saved Successfully!")

    def load_settings(self):
        api_key = self._callbacks.loadExtensionSetting("openai_api_key")
        custom_prompt = self._callbacks.loadExtensionSetting("openai_prompt")

        if api_key:
            self.api_key_field.setText(api_key)

        # Set default prompt if none is saved
        if custom_prompt:
            self.prompt_text_area.setText(custom_prompt)
        else:
            self.prompt_text_area.setText("You are a cybersecurity expert. Analyze HTTP requests for vulnerabilities.")

    def getTabCaption(self):
        return "ChatGPT Settings"

    def getUiComponent(self):
        return self.settings_panel
