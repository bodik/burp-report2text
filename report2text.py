"""
Burp extension report2text

## References

* https://laconicwolf.com/2019/03/09/burp-extension-python-tutorial-generate-a-forced-browsing-wordlist/
* https://parsiya.net/blog/2019-11-26-swing-in-python-burp-extensions-part-3-tips-and-tricks/#create-a-context-menu
* https://github.com/laconicwolf/burp-extensions
"""

from burp import IBurpExtender, IContextMenuFactory, ITab
from java.awt import BorderLayout, Color
from java.awt.event import ActionListener, FocusListener
from java.util import ArrayList
from javax.swing import JMenuItem, JPanel, JScrollPane, JTextArea


__version__ = '0.0.2'

REPORT_TEMPLATE = """----
## Report {report_id}: {issue_name}

url: {url}

### Background

{issue_background}

### Detail

{issue_detail}

### Requests

{requests}
"""

REQUEST_TEMPLATE = """#### Request {request_id}
```
{request}
```

```
{response}
```
"""


class GenerateReportListener(ActionListener):
    """ActionListener for the Burp context menu."""

    def __init__(self, extension, invocation):
        self.extension = extension
        self.invocation = invocation

    def actionPerformed(self, event):
        """Invoked when the context menu item is selected."""

        output = []

        for issue in self.invocation.getSelectedIssues():
            requests = []
            for idx, request in enumerate(issue.getHttpMessages()):
                requests.append(REQUEST_TEMPLATE.format(
                    request_id=idx,
                    request=self.extension._helpers.bytesToString(request.getRequest()).encode('utf-8', errors='replace'),
                    response=self.extension._helpers.bytesToString(request.getResponse()).encode('utf-8', errors='replace')
                ))

            output.append(REPORT_TEMPLATE.format(
                report_id=issue.getIssueType(),
                issue_name=issue.getIssueName(),
                url=issue.getUrl(),
                issue_background=issue.getIssueBackground(),
                issue_detail=issue.getIssueDetail(),
                requests='\n'.join(requests)
            ))

        self.extension.setReportText('\n'.join(output))


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, FocusListener):
    """custom reporting extension implementation"""

    def registerExtenderCallbacks(self, callbacks):
        """extension startup"""

        # commons
        self.EXTENSION_NAME = 'Report2text'
        self.COLOR_RED = Color(0xff6633)
        self.COLOR_BLACK = Color(0x0)

        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.setExtensionName(self.EXTENSION_NAME)

        # menu
        self._callbacks.registerContextMenuFactory(self)

        # output tab
        self._mainTextArea = JTextArea('initial text')
        self._mainTextArea.editable = False
        self._mainTextArea.setLineWrap(True)
        self._mainTextArea.setWrapStyleWord(True)
        self._mainTextArea.addFocusListener(self)

        self._tab = JPanel(BorderLayout())
        self._tab.add(JScrollPane(self._mainTextArea))
        self._callbacks.addSuiteTab(self)

        return

    def createMenuItems(self, invocation):
        """iface IContextMenuFactory; context menu handler"""

        menuItems = ArrayList()
        if invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS:
            menuItem = JMenuItem('Report2text')
            menuItem.addActionListener(GenerateReportListener(self, invocation))
            menuItems.add(menuItem)
        return menuItems

    def getTabCaption(self):
        """iface ITab; Return the text to be displayed on the tab"""
        
        return self.EXTENSION_NAME
                                
    def getUiComponent(self):
        """iface ITab; Passes the UI to burp"""

        return self._tab

    def focusGained(self, event):
        """iface FocusListener; reset color on tab focus"""

        self._setTabBackground(self.COLOR_BLACK)

    def focusLost(self, event):
        """iface FocusListener;"""

    def setReportText(self, text):
        """set report text"""

        self._setTabBackground(self.COLOR_RED)
        self._mainTextArea.text = text

    def _setTabBackground(self, color):
        """set tab caption background"""

        tabbedPane = self.getUiComponent().getParent()
        for idx in range(tabbedPane.getTabCount()):
            if tabbedPane.getTitleAt(idx) == self.EXTENSION_NAME:
                tabbedPane.setBackgroundAt(idx, color);
